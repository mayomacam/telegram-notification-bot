import os
import json
import logging
import time
import secrets
from datetime import datetime
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from pydantic import BaseModel, Field
import httpx

# --- Configuration & Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("telegram_gateway")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "*").split(",")

if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY]):
    logger.error("CRITICAL: Missing required environment variables (TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY).")
    exit(1)

# --- Metrics Tracker ---
class Metrics:
    def __init__(self):
        self.start_time = time.time()
        self.total_requests = 0
        self.successful_notifications = 0
        self.failed_notifications = 0
        self.last_notification_at: Optional[str] = None

    def get_uptime(self):
        delta = time.time() - self.start_time
        hours, rem = divmod(delta, 3600)
        minutes, seconds = divmod(rem, 60)
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"

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
    lifespan=lifespan
)

# --- Middlewares ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Adjust as needed for production
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=ALLOWED_HOSTS
)

# --- Security ---
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Security(api_key_header)):
    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, API_SECRET_KEY):
        logger.warning("Security Alert: Unauthorized access attempt blocked.")
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key

# --- Routes ---

@app.get("/health")
async def health_check():
    """Liveness and readiness probe."""
    return {"status": "healthy", "timestamp": datetime.utcnow().isoformat()}

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(api_key: str = Depends(verify_api_key)):
    """A simple, lightweight monitoring dashboard."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Gateway Monitor</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; background-color: #f4f7f6; }}
            .card {{ background: white; border-radius: 8px; padding: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 20px; }}
            h1 {{ color: #2c3e50; }}
            .metric {{ display: flex; justify-content: space-between; border-bottom: 1px solid #eee; padding: 10px 0; }}
            .metric:last-child {{ border-bottom: none; }}
            .label {{ font-weight: bold; color: #7f8c8d; }}
            .status-ok {{ color: #27ae60; font-weight: bold; }}
            .status-err {{ color: #e74c3c; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>🚀 Gateway Monitor</h1>
        <div class="card">
            <div class="metric"><span class="label">Status</span><span class="status-ok">ONLINE</span></div>
            <div class="metric"><span class="label">Uptime</span><span>{metrics.get_uptime()}</span></div>
            <div class="metric"><span class="label">Total Requests</span><span>{metrics.total_requests}</span></div>
        </div>
        <div class="card">
            <h2>Notifications</h2>
            <div class="metric"><span class="label">Successful</span><span class="status-ok">{metrics.successful_notifications}</span></div>
            <div class="metric"><span class="label">Failed</span><span class="status-err">{metrics.failed_notifications}</span></div>
            <div class="metric"><span class="label">Last Notification</span><span>{metrics.last_notification_at or 'Never'}</span></div>
        </div>
        <p style="font-size: 0.8em; color: #95a5a6; text-align: center;">Secure Telegram Notification Gateway v2.0.0</p>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/notify")
async def send_notification(
    request: Request,
    payload: NotificationPayload,
    api_key: str = Depends(verify_api_key)
):
    """Receives webhooks and forwards them to Telegram securely."""
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
    
    try:
        client: httpx.AsyncClient = request.app.state.http_client
        response = await client.post(telegram_url, json=data)
        response.raise_for_status()

        metrics.successful_notifications += 1
        metrics.last_notification_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        logger.info(f"Notification successfully dispatched from {request.client.host if request.client else 'unknown'}")
        return {"status": "success", "message": "Dispatched"}
            
    except httpx.HTTPStatusError as e:
        metrics.failed_notifications += 1
        logger.error(f"Telegram API Error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=502, detail=f"Upstream Telegram error: {e.response.status_code}")
    except Exception as e:
        metrics.failed_notifications += 1
        logger.exception("Internal Server Error during dispatch.")
        raise HTTPException(status_code=500, detail="Internal processing error")
