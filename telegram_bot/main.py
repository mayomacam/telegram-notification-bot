import os
import json
import logging
import secrets
import time
import uuid
import contextvars
from collections import deque
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager
from collections import deque

from fastapi import FastAPI, HTTPException, Depends, Security, Request, Response
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse, ORJSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
import httpx

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("telegram_gateway")

# 2. Secure Configuration via Environment Variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*").split(",")
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
IP_ALLOWLIST = os.getenv("IP_ALLOWLIST", "").split(",") if os.getenv("IP_ALLOWLIST") else []

if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY]):
    logger.error("CRITICAL: Missing required environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY).")
    exit(1)

# --- Logging Context Filter ---
request_id_var = contextvars.ContextVar("request_id", default="n/a")

class RequestIDFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        return True

# Update logging configuration to include request_id
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(request_id)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
for handler in logging.root.handlers:
    handler.addFilter(RequestIDFilter())

# --- Security Middleware & Helpers ---
class DebugMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())
        token = request_id_var.set(request_id)
        start_time = time.monotonic()

        try:
            response = await call_next(request)
            process_time = time.monotonic() - start_time
        except Exception as e:
            process_time = time.monotonic() - start_time
            logger.error(f"Request {request.method} {request.url.path} failed after {process_time:.4f}s: {e}")
            raise
        finally:
            metrics.add_request_time(process_time)
            request_id_var.reset(token)

        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        response.headers["X-Request-ID"] = request_id

        logger.info(f"Request {request.method} {request.url.path} processed in {process_time:.4f}s")
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "0"  # Modern recommendation is to disable it and use CSP
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return response

class RateLimiter:
    __slots__ = ("requests", "window", "clients")
    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, deque] = {}
        self._last_prune = time.monotonic()

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()

        # Prune all old clients periodically to prevent memory leak
        if now - self._last_prune > self.window:
            expired_ips = [ip for ip, times in self.clients.items() if not times or now - times[-1] > self.window]
            for ip in expired_ips:
                del self.clients[ip]
            self._last_prune = now

        if client_ip not in self.clients:
            self.clients[client_ip] = deque([now])
            return True

        client_times = self.clients[client_ip]
        # Efficiently remove expired timestamps from the left
        while client_times and now - client_times[0] >= self.window:
            client_times.popleft()

        if len(client_times) < self.requests:
            client_times.append(now)
            return True
        return False

rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)

# --- Metrics Tracker ---
class Metrics:
    __slots__ = ("start_time", "total_requests", "successful_notifications",
                 "failed_notifications", "errors", "last_notification_at", "request_times")
    def __init__(self):
        self.start_time = time.monotonic()
        self.total_requests = 0
        self.successful_notifications = 0
        self.failed_notifications = 0
        self.errors = 0
        self.last_notification_at: Optional[str] = None
        self.request_times = deque() # (timestamp, duration)

    def get_uptime(self):
        delta = time.monotonic() - self.start_time
        hours, rem = divmod(delta, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def add_request_time(self, duration: float):
        now = time.monotonic()
        self.request_times.append((now, duration))
        # Keep only last hour of data for RPM/latency
        while self.request_times and now - self.request_times[0][0] > 3600:
            self.request_times.popleft()

    def get_rpm(self):
        now = time.monotonic()
        # count requests in the last 60 seconds
        count = 0
        for t, _ in reversed(self.request_times):
            if now - t < 60:
                count += 1
            else:
                break
        return count

    def get_avg_latency(self):
        now = time.monotonic()
        total_latency = 0.0
        count = 0
        for t, lat in reversed(self.request_times):
            if now - t < 300: # Last 5 minutes
                total_latency += lat
                count += 1
            else:
                break
        return total_latency / count if count > 0 else 0.0

metrics = Metrics()

# --- Models ---
class NotificationPayload(BaseModel):
    message: Optional[str] = Field(None, description="The message to send. If missing, the whole payload is sent as JSON.")

    class Config:
        extra = "allow"

# --- Lifespan Management ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the shared HTTPX client for connection pooling (optimization)
    app.state.http_client = httpx.AsyncClient(timeout=10.0)
    logger.info("Gateway started, HTTP client initialized.")
    yield
    # Clean up
    await app.state.http_client.aclose()
    logger.info("Gateway shutting down, HTTP client closed.")

app = FastAPI(
    title="Secure Telegram Notification Gateway",
    version="2.0.0",
    lifespan=lifespan,
    default_response_class=ORJSONResponse
)

# --- Middlewares ---
app.add_middleware(DebugMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
    allow_credentials=True,
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

# --- Security ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

async def verify_api_key(
    request: Request,
    api_key_header: Optional[str] = Security(api_key_header)
):
    # Check header first, then query parameter
    api_key = api_key_header or request.query_params.get("api_key")

    if not api_key:
        logger.warning("Security Alert: API Key missing.")
        metrics.errors += 1
        raise HTTPException(status_code=403, detail="API Key missing")

    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, API_SECRET_KEY):
        logger.warning("Security Alert: Unauthorized access attempt blocked.")
        metrics.errors += 1
        raise HTTPException(status_code=403, detail="Unauthorized")

    return api_key

# --- Routes ---

@app.get("/health")
async def health_check():
    """Liveness and readiness probe with enriched metrics."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime_seconds": int(time.monotonic() - metrics.start_time),
        "metrics": {
            "total_requests": metrics.total_requests,
            "rpm": metrics.get_rpm(),
            "avg_latency_ms": round(metrics.get_avg_latency() * 1000, 2),
            "security_errors": metrics.errors
        }
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(api_key: str = Depends(verify_security)):
    """A modern, lightweight monitoring dashboard."""
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en" data-theme="dark">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <meta http-equiv="refresh" content="30">
        <title>Gateway Dashboard</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
        <style>
            :root {{
                --pico-primary: #0088cc;
                --pico-primary-hover: #0077b3;
                --pico-primary-focus: rgba(0, 136, 204, 0.25);
            }}
            body {{ padding: 2rem 0; }}
            .status-ok {{ color: #2ecc71; }}
            .status-err {{ color: #e74c3c; }}
            .metric-card {{
                padding: 1rem;
                border-radius: 8px;
                background: var(--pico-card-background-color);
                box-shadow: var(--pico-card-box-shadow);
            }}
            .metric-value {{
                font-size: 1.5rem;
                font-weight: bold;
                display: block;
                margin-top: 0.5rem;
            }}
            .grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }}
            header {{ margin-bottom: 2rem; }}
        </style>
    </head>
    <body>
        <main class="container">
            <header>
                <hgroup>
                    <h1>🛡️ Gateway Sentinel</h1>
                    <p>Secure Telegram Notification Gateway v2.1.0</p>
                </hgroup>
            </header>

            <section>
                <h2>System Health</h2>
                <div class="grid">
                    <article class="metric-card">
                        <small>Status</small>
                        <span class="metric-value status-ok">● ONLINE</span>
                    </article>
                    <article class="metric-card">
                        <small>Uptime</small>
                        <span class="metric-value">{metrics.get_uptime()}</span>
                    </article>
                    <article class="metric-card">
                        <small>Throughput (RPM)</small>
                        <span class="metric-value">{metrics.get_rpm()}</span>
                    </article>
                    <article class="metric-card">
                        <small>Avg Latency</small>
                        <span class="metric-value">{metrics.get_avg_latency():.3f}s</span>
                    </article>
                </div>
            </section>

            <section>
                <h2>Traffic & Security</h2>
                <div class="grid">
                    <article class="metric-card">
                        <small>Total Requests</small>
                        <span class="metric-value">{metrics.total_requests}</span>
                    </article>
                    <article class="metric-card">
                        <small>Auth/IP Blocked</small>
                        <span class="metric-value {"status-err" if metrics.errors > 0 else "" }">{metrics.errors}</span>
                    </article>
                    <article class="metric-card">
                        <small>Successful Dispatches</small>
                        <span class="metric-value status-ok">{metrics.successful_notifications}</span>
                    </article>
                    <article class="metric-card">
                        <small>Failed Dispatches</small>
                        <span class="metric-value {"status-err" if metrics.failed_notifications > 0 else "" }">{metrics.failed_notifications}</span>
                    </article>
                </div>
            </section>

            <section>
                <h2>Recent Activity</h2>
                <article>
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span>Last Successful Dispatch:</span>
                        <mark>{metrics.last_notification_at or 'Never'}</mark>
                    </div>
                </article>
            </section>

            <footer style="margin-top: 4rem; text-align: center; border-top: 1px solid var(--pico-muted-border-color); padding-top: 2rem;">
                <small>
                    Refreshes automatically every 30s •
                    IP Allowlist: <code>{"Active" if IP_ALLOWLIST else "Disabled"}</code>
                </small>
            </footer>
        </main>
        <script>
            let timeLeft = 30;
            setInterval(() => {{
                timeLeft--;
                if (timeLeft < 0) timeLeft = 30;
                document.getElementById('timer').innerText = timeLeft;
            }}, 1000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/notify")
async def send_notification(
    request: Request,
    payload: NotificationPayload,
    api_key: str = Depends(verify_security)
):
    """Receives webhooks and forwards them to Telegram securely."""
    client_ip = request.client.host if request.client else "unknown"

    # IP Allowlist check
    if IP_ALLOWLIST and client_ip not in IP_ALLOWLIST:
        logger.warning(f"Access denied for IP: {client_ip}")
        metrics.errors += 1
        raise HTTPException(status_code=403, detail="IP not allowed")

    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    metrics.total_requests += 1

    # Payload processing
    # If 'message' is provided, use it. Otherwise, use the whole payload as JSON.
    msg_data = payload.model_dump(exclude_unset=True)
    message_text = msg_data.get("message")
    
    if not message_text:
        try:
            # Fallback to raw JSON if no specific message field
            raw_json = await request.json()
            message_text = f"<b>System Notification:</b>\n<pre>{json.dumps(raw_json, indent=2)}</pre>"
        except Exception as e:
            logger.warning(f"Failed to parse raw JSON: {e}")
            message_text = f"<b>System Notification:</b>\n[Empty or Invalid Payload]"

    logger.info(f"Dispatching notification (length: {len(message_text)}) from {client_ip}")

    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_text,
        "parse_mode": "HTML"
    }
    
    start_dispatch = time.monotonic()
    try:
        client: httpx.AsyncClient = request.app.state.http_client
        response = await client.post(telegram_url, json=data)
        dispatch_latency = time.monotonic() - start_dispatch
        logger.info(f"Telegram API response latency: {dispatch_latency:.4f}s")
        response.raise_for_status()

        metrics.successful_notifications += 1
        metrics.last_notification_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        logger.info(f"Notification successfully dispatched from {request.client.host if request.client else 'unknown'}")
        return {"status": "success", "message": "Dispatched"}
            
    except httpx.HTTPStatusError as e:
        metrics.failed_notifications += 1
        metrics.errors += 1
        logger.error(f"Telegram API Error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=502, detail=f"Upstream Telegram error: {e.response.status_code}")
    except Exception as e:
        metrics.failed_notifications += 1
        metrics.errors += 1
        logger.exception("Internal Server Error during dispatch.")
        raise HTTPException(status_code=500, detail="Internal processing error")
