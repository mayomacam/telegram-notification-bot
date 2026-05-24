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
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
IP_ALLOWLIST = os.getenv("IP_ALLOWLIST", "").split(",") if os.getenv("IP_ALLOWLIST") else []
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

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
        start_time = time.time()

        response = await call_next(request)

        process_time = time.time() - start_time
        metrics.add_request_time(process_time)
        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        response.headers["X-Request-ID"] = request_id

        logger.info(f"Request {request.method} {request.url.path} processed in {process_time:.4f}s")
        request_id_var.reset(token)
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
        return response

class RateLimiter:
    __slots__ = ("requests", "window", "clients")

    def __init__(self, requests: int, window: int):
        self.requests = requests
        self.window = window
        self.clients: Dict[str, deque] = {}

    def is_allowed(self, client_ip: str) -> bool:
        now = time.monotonic()

        # Prune clients occasionally to prevent memory bloat
        if len(self.clients) > 1000:
            expired_ips = [ip for ip, times in self.clients.items() if not times or now - times[-1] > self.window]
            for ip in expired_ips:
                del self.clients[ip]

        if client_ip not in self.clients:
            self.clients[client_ip] = deque([now], maxlen=self.requests + 1)
            return True

        times = self.clients[client_ip]
        while times and now - times[0] >= self.window:
            times.popleft()

        if len(times) < self.requests:
            times.append(now)
            return True
        return False

rate_limiter = RateLimiter(RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW)

# --- Metrics Tracker ---
class Metrics:
    __slots__ = ("start_time", "total_requests", "successful_notifications", "failed_notifications", "errors", "last_notification_at", "request_times")

    def __init__(self):
        self.start_time = time.time()
        self.total_requests = 0
        self.successful_notifications = 0
        self.failed_notifications = 0
        self.errors = 0
        self.last_notification_at: Optional[str] = None
        self.request_times = deque() # Stores (timestamp, duration)

    def get_uptime(self):
        delta = time.time() - self.start_time
        hours, rem = divmod(delta, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"

    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def add_request_time(self, duration: float):
        now = time.time()
        self.request_times.append((now, duration))
        # Keep only last hour of data for RPM/latency
        while self.request_times and now - self.request_times[0][0] > 3600:
            self.request_times.popleft()

    def get_rpm(self):
        now = time.time()
        count = 0
        for t, _ in reversed(self.request_times):
            if now - t < 60:
                count += 1
            else:
                break
        return count

    def get_avg_latency(self):
        now = time.time()
        total_lat = 0.0
        count = 0
        for t, lat in reversed(self.request_times):
            if now - t < 300: # Last 5 minutes
                total_lat += lat
                count += 1
            else:
                break
        return total_lat / count if count > 0 else 0

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
    allow_origins=ALLOWED_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

# --- Security ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_security(request: Request, api_key: str = Security(api_key_header)):
    # 1. IP Allowlist Check
    if IP_ALLOWLIST:
        client_ip = request.client.host if request.client else "unknown"
        if client_ip not in IP_ALLOWLIST:
            logger.warning(f"Security Alert: IP {client_ip} not in allowlist.")
            metrics["errors"] += 1
            raise HTTPException(status_code=403, detail="IP not allowed")

    # 2. API Key Check
    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, API_SECRET_KEY):
        logger.warning("Security Alert: Unauthorized API key used.")
        metrics["errors"] += 1
        raise HTTPException(status_code=403, detail="Unauthorized")

    return api_key

# --- Routes ---

@app.get("/health")
async def health_check():
    """Liveness and readiness probe with enriched metrics."""
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "uptime": metrics.get_uptime(),
        "uptime_seconds": int(time.time() - metrics.start_time),
        "metrics": {
            "total_requests": metrics.total_requests,
            "rpm": metrics.get_rpm(),
            "avg_latency_5m": round(metrics.get_avg_latency(), 4),
            "security_errors": metrics.errors,
            "success_notifications": metrics.successful_notifications,
            "failed_notifications": metrics.failed_notifications,
        },
        "config": {
            "rate_limit": f"{RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}s",
            "ip_allowlist_enabled": bool(IP_ALLOWLIST),
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
        <title>Sentinel Dashboard</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css">
        <style>
            :root {{
                --pico-primary: #0088cc;
                --pico-primary-hover: #0077b3;
                --pico-card-background-color: #1a1a1a;
            }}
            body {{ padding-top: 2rem; background-color: #0d1117; }}
            .status-ok {{ color: #3fb950; }}
            .status-err {{ color: #f85149; }}
            .grid {{ grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); }}
            article {{ border: 1px solid #30363d; }}
            header {{ border-bottom: 1px solid #30363d; font-weight: bold; }}
            .metric-value {{ font-family: 'Courier New', Courier, monospace; font-weight: bold; }}
        </style>
    </head>
    <body>
        <main class="container">
            <hgroup>
                <h1>🛡️ Sentinel Monitor</h1>
                <p>Real-time Security & Performance Gateway</p>
            </hgroup>

            <div class="grid">
                <article>
                    <header>System Health</header>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Engine Status</span>
                        <span class="status-ok">● ACTIVE</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Uptime</span>
                        <span class="metric-value">{metrics.get_uptime()}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Throughput (RPM)</span>
                        <span class="metric-value">{metrics.get_rpm()}</span>
                    </div>
                </article>

                <article>
                    <header>Security Sentinel</header>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Blocks (Auth/IP)</span>
                        <span class="metric-value {"status-err" if metrics.errors > 0 else "" }">{metrics.errors}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>IP Allowlist</span>
                        <span class="metric-value">{"Enabled" if IP_ALLOWLIST else "Disabled"}</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Rate Limiting</span>
                        <span class="metric-value">Active ({RATE_LIMIT_REQUESTS}/{RATE_LIMIT_WINDOW}s)</span>
                    </div>
                </article>

                <article>
                    <header>Delivery Metrics</header>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Avg Latency</span>
                        <span class="metric-value">{metrics.get_avg_latency():.3f}s</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Success Rate</span>
                        <span class="metric-value status-ok">{ (metrics.successful_notifications / metrics.total_requests * 100) if metrics.total_requests > 0 else 100:.1f}%</span>
                    </div>
                    <div style="display: flex; justify-content: space-between;">
                        <span>Total Proxied</span>
                        <span class="metric-value">{metrics.total_requests}</span>
                    </div>
                </article>
            </div>

            <footer style="margin-top: 2rem; text-align: center;">
                <small>Sentinel Notification Gateway v2.1.0-secure • Last Update: {datetime.now(timezone.utc).strftime("%H:%M:%S")} UTC</small>
            </footer>
        </main>
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
    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    metrics.total_requests += 1

    # Payload processing
    # If 'message' is provided, use it. Otherwise, use the whole payload as JSON.
    msg_data = payload.model_dump(exclude_unset=True)
    message_text = msg_data.get("message")
    
    if not message_text:
        # Fallback to raw JSON if no specific message field
        raw_json = await request.json()
        message_text = f"<b>System Notification:</b>\n<pre>{json.dumps(raw_json, indent=2)}</pre>"

    logger.debug(f"Preparing to send message: {message_text[:50]}...")

    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_text,
        "parse_mode": "HTML"
    }
    
    start_dispatch = time.time()
    try:
        client: httpx.AsyncClient = request.app.state.http_client
        response = await client.post(telegram_url, json=data)
        dispatch_latency = time.time() - start_dispatch
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
