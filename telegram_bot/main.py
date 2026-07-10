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
import platform

from fastapi import FastAPI, HTTPException, Depends, Security, Request, Response
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse, ORJSONResponse
import orjson
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field, ConfigDict
import httpx
import psutil

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
BLOCKLIST_AGENTS = {"sqlmap", "nmap", "nikto", "dirbuster", "censys"}

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

        user_agent = request.headers.get("user-agent", "unknown")
        x_forwarded_for = request.headers.get("x-forwarded-for", "none")

        # Mask API Key in logs
        api_key = request.headers.get("x-api-key") or request.query_params.get("api_key", "")
        masked_key = api_key[:4] + "****" if len(api_key) > 4 else "****"

        try:
            response = await call_next(request)
            process_time = time.monotonic() - start_time
        except Exception as e:
            process_time = time.monotonic() - start_time
            logger.error(f"Request {request.method} {request.url.path} from {request.client.host if request.client else 'unknown'} (UA: {user_agent}, XFF: {x_forwarded_for}, Key: {masked_key}) failed after {process_time:.4f}s: {e}")
            raise
        finally:
            metrics.add_request_time(process_time)
            request_id_var.reset(token)

        response.headers["X-Process-Time"] = f"{process_time:.4f}s"
        response.headers["X-Request-ID"] = request_id

        logger.info(f"Request {request.method} {request.url.path} from {request.client.host if request.client else 'unknown'} (UA: {user_agent}, XFF: {x_forwarded_for}, Key: {masked_key}) processed in {process_time:.4f}s")
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
        response.headers["X-XSS-Protection"] = "0"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "upgrade-insecure-requests;"
        )
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        return response

class SecuritySentinel:
    __slots__ = ("events", "blacklist", "blacklist_duration")

    def __init__(self, blacklist_duration: int = 3600):
        self.events = deque(maxlen=50)  # Store last 50 events
        self.blacklist: Dict[str, float] = {}
        self.blacklist_duration = blacklist_duration

    def log_event(self, ip: str, event_type: str, details: str):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.events.append({
            "timestamp": timestamp,
            "ip": ip,
            "type": event_type,
            "details": details
        })

        # If it's a security violation, consider blacklisting
        if event_type in ("AUTH_FAILURE", "RATE_LIMIT"):
            self._check_blacklist(ip)

    def _check_blacklist(self, ip: str):
        # Very simple logic: if 5 failures in 5 minutes, blacklist for 1 hour
        now = time.monotonic()
        recent_failures = [e for e in self.events if e["ip"] == ip and e["type"] in ("AUTH_FAILURE", "RATE_LIMIT")]
        if len(recent_failures) >= 5:
            self.blacklist[ip] = now + self.blacklist_duration
            logger.warning(f"IP {ip} has been temporarily blacklisted due to multiple security events.")

    def is_blacklisted(self, ip: str) -> bool:
        if ip in self.blacklist:
            if time.monotonic() < self.blacklist[ip]:
                return True
            else:
                del self.blacklist[ip]
        return False

sentinel = SecuritySentinel()

class RateLimiter:
    __slots__ = ("requests", "window", "clients", "_last_prune")
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
                 "failed_notifications", "errors", "security_blocks", "last_notification_at", "request_times")
    def __init__(self):
        self.start_time = time.monotonic()
        self.total_requests = 0
        self.successful_notifications = 0
        self.failed_notifications = 0
        self.errors = 0
        self.security_blocks = 0
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
    model_config = ConfigDict(extra="allow")
    message: Optional[str] = Field(None, description="The message to send. If missing, the whole payload is sent as JSON.")

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

async def verify_security(
    request: Request,
    api_key_header: Optional[str] = Security(api_key_header)
):
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "").lower()

    # Block common scanners
    if any(agent in user_agent for agent in BLOCKLIST_AGENTS):
        logger.warning(f"Security Alert: Blocked request from suspicious User-Agent: {user_agent} (IP: {client_ip})")
        metrics.security_blocks += 1
        sentinel.log_event(client_ip, "AGENT_BLOCKED", f"Suspicious User-Agent: {user_agent}")
        raise HTTPException(status_code=403, detail="Forbidden")

    if sentinel.is_blacklisted(client_ip):
        logger.warning(f"Security Alert: Blocked request from blacklisted IP {client_ip}")
        metrics.security_blocks += 1
        raise HTTPException(status_code=403, detail="IP temporarily blacklisted")

    # Check header first, then query parameter
    api_key = api_key_header or request.query_params.get("api_key")

    if api_key:
        # Log partial key for debugging (first 4 chars)
        masked_key = api_key[:4] + "****" if len(api_key) > 4 else "****"
        logger.debug(f"Verifying API key: {masked_key} from {client_ip}")

    if not api_key:
        logger.warning(f"Security Alert: API Key missing from {client_ip}")
        metrics.security_blocks += 1
        sentinel.log_event(client_ip, "AUTH_FAILURE", "Missing API Key")
        raise HTTPException(status_code=403, detail="API Key missing")

    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, API_SECRET_KEY):
        logger.warning(f"Security Alert: Unauthorized access attempt blocked from {client_ip}")
        metrics.security_blocks += 1
        sentinel.log_event(client_ip, "AUTH_FAILURE", "Invalid API Key")
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
    cpu_usage = psutil.cpu_percent(interval=None)
    memory_usage = psutil.virtual_memory().percent
    sys_info = f"{platform.system()} {platform.release()}"

    events_html = ""
    for event in reversed(sentinel.events):
        events_html += f"""
        <tr>
            <td>{event['timestamp']}</td>
            <td><code>{event['ip']}</code></td>
            <td><mark>{event['type']}</mark></td>
            <td>{event['details']}</td>
        </tr>
        """

    now_time = datetime.now(timezone.utc).strftime("%H:%M:%S UTC")
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
                --pico-primary: #3fb1ff;
                --pico-primary-hover: #2b9dec;
                --pico-background-color: #0b0e14;
                --pico-card-background-color: #11151c;
                --pico-border-color: #1f242d;
            }}
            body {{ padding: 2rem 0; background-color: var(--pico-background-color); font-family: 'Inter', system-ui, -apple-system, sans-serif; }}
            .status-ok {{ color: #3fb1ff; }}
            .status-err {{ color: #ff4d4d; font-weight: bold; }}
            .metric-card {{
                padding: 1.5rem;
                border-radius: 16px;
                border: 1px solid var(--pico-border-color);
                background: var(--pico-card-background-color);
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            }}
            .metric-value {{
                font-size: 2rem;
                font-weight: 800;
                display: block;
                margin-top: 0.5rem;
                font-family: 'JetBrains Mono', 'Fira Code', monospace;
                letter-spacing: -1px;
            }}
            .grid {{ margin-bottom: 2rem; }}
            header {{ margin-bottom: 3rem; border-bottom: 1px solid var(--pico-border-color); padding-bottom: 2rem; }}
            table {{ font-size: 0.85rem; border-radius: 8px; overflow: hidden; }}
            mark {{ background: rgba(255, 77, 77, 0.1); color: #ff4d4d; border: 1px solid rgba(255, 77, 77, 0.3); padding: 2px 6px; border-radius: 4px; }}
            code {{ background: #1a1f29; color: #e1e1e1; }}
            .progress-container {{ height: 6px; background: #1a1f29; border-radius: 10px; margin-top: 12px; overflow: hidden; }}
            .progress-bar {{ height: 100%; background: linear-gradient(90deg, var(--pico-primary), #70c7ff); transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1); }}
            .badge {{ font-size: 0.7rem; text-transform: uppercase; padding: 2px 8px; border-radius: 20px; font-weight: bold; margin-left: 8px; }}
            .badge-live {{ background: #ff4d4d; color: white; animation: blink 2s infinite; }}
            @keyframes blink {{ 0% {{ opacity: 1; }} 50% {{ opacity: 0.4; }} 100% {{ opacity: 1; }} }}
        </style>
    </head>
    <body>
        <main class="container">
            <header>
                <hgroup>
                    <h1 style="display:flex; align-items:center; gap:10px;">
                        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="status-ok"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
                        SENTINEL MONITOR
                        <span class="badge badge-live">LIVE</span>
                    </h1>
                    <p>Advanced Security Gateway • v2.2.0 • System: {sys_info}</p>
                </hgroup>
            </header>

            <section>
                <div class="grid">
                    <article class="metric-card">
                        <small>CPU USAGE</small>
                        <span class="metric-value">{cpu_usage}%</span>
                        <div class="progress-container"><div class="progress-bar" style="width: {cpu_usage}%;"></div></div>
                    </article>
                    <article class="metric-card">
                        <small>RAM USAGE</small>
                        <span class="metric-value">{memory_usage}%</span>
                        <div class="progress-container"><div class="progress-bar" style="width: {memory_usage}%;"></div></div>
                    </article>
                    <article class="metric-card">
                        <small>UPTIME</small>
                        <span class="metric-value">{metrics.get_uptime()}</span>
                    </article>
                </div>
            </section>

            <section>
                <h3>Traffic Metrics</h3>
                <div class="grid">
                    <article class="metric-card">
                        <small>TOTAL REQUESTS</small>
                        <span class="metric-value">{metrics.total_requests}</span>
                    </article>
                    <article class="metric-card">
                        <small>THROUGHPUT (RPM)</small>
                        <span class="metric-value">{metrics.get_rpm()}</span>
                    </article>
                    <article class="metric-card">
                        <small>AVG LATENCY</small>
                        <span class="metric-value status-ok">{metrics.get_avg_latency():.3f}s</span>
                    </article>
                </div>
                <div class="grid">
                    <article class="metric-card">
                        <small>DISPATCH SUCCESS</small>
                        <span class="metric-value status-ok">{metrics.successful_notifications}</span>
                    </article>
                    <article class="metric-card">
                        <small>DISPATCH FAILURES</small>
                        <span class="metric-value {"status-err" if metrics.failed_notifications > 0 else "" }">{metrics.failed_notifications}</span>
                    </article>
                    <article class="metric-card">
                        <small>SECURITY BLOCKS</small>
                        <span class="metric-value {"status-err" if metrics.security_blocks > 0 else "" }">{metrics.security_blocks}</span>
                    </article>
                </div>
            </section>

            <section>
                <h3>Recent Security Events</h3>
                <figure style="overflow-x: auto; max-height: 400px; overflow-y: auto;">
                    <table role="grid">
                        <thead style="position: sticky; top: 0; background: var(--pico-card-background-color); z-index: 1;">
                            <tr>
                                <th>Timestamp</th>
                                <th>Source IP</th>
                                <th>Event Type</th>
                                <th>Details</th>
                            </tr>
                        </thead>
                        <tbody>
                            {events_html if events_html else "<tr><td colspan='4' style='text-align:center;'>No security events recorded.</td></tr>"}
                        </tbody>
                    </table>
                </figure>
            </section>

            <footer style="margin-top: 4rem; text-align: center; color: #505967; padding-top: 2rem; border-top: 1px solid var(--pico-border-color);">
                <small>
                    Last Refreshed: <strong>{now_time}</strong> •
                    Auto-refresh in <span id="timer">30</span>s •
                    IP Allowlist: <code>{"Active" if IP_ALLOWLIST else "Disabled"}</code> •
                    Blacklisted IPs: <code>{len(sentinel.blacklist)}</code>
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
        metrics.security_blocks += 1
        sentinel.log_event(client_ip, "IP_BLOCKED", "IP not in allowlist")
        raise HTTPException(status_code=403, detail="IP not allowed")

    if not rate_limiter.is_allowed(client_ip):
        logger.warning(f"Rate limit exceeded for {client_ip}")
        metrics.security_blocks += 1
        sentinel.log_event(client_ip, "RATE_LIMIT", "Rate limit exceeded")
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
            # Use orjson for high-performance serialization
            formatted_json = orjson.dumps(raw_json, option=orjson.OPT_INDENT_2 | orjson.OPT_NON_STR_KEYS).decode()
            message_text = f"<b>System Notification:</b>\n<pre>{formatted_json}</pre>"
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
        error_body = e.response.text[:500]
        logger.error(f"Telegram API Error: Status {e.response.status_code} | Body: {error_body}...")
        raise HTTPException(status_code=502, detail=f"Upstream Telegram error: {e.response.status_code}")
    except Exception as e:
        metrics.failed_notifications += 1
        metrics.errors += 1
        logger.exception("Internal Server Error during dispatch.")
        raise HTTPException(status_code=500, detail="Internal processing error")
