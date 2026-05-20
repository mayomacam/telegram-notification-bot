import os
import json
import logging
import secrets
import time
from datetime import datetime
from typing import Dict, Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
from fastapi.responses import HTMLResponse
import httpx

# 1. Audit Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("telegram_gateway")

# 2. Secure Configuration via Environment Variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")

if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY]):
    logger.error("CRITICAL: Missing required environment variables. Exiting.")
    # In a production FastAPI app, we might want to raise an error instead of exit(1)
    # to allow the server to start but fail health checks, but for this gateway exit is clear.
    import sys
    sys.exit(1)

# 3. Metrics Tracking
metrics = {
    "start_time": time.time(),
    "requests_received": 0,
    "notifications_sent": 0,
    "errors": 0
}

# 4. Connection Pooling (httpx.AsyncClient) via Lifespan
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize the global httpx client
    app.state.client = httpx.AsyncClient(timeout=10.0)
    logger.info("Lifespan started: httpx client initialized.")
    yield
    # Clean up the client
    await app.state.client.aclose()
    logger.info("Lifespan ending: httpx client closed.")

app = FastAPI(title="Secure Telegram Notification Gateway", lifespan=lifespan)

# 5. Access Control (API Key Header)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Security(api_key_header)):
    # Use secrets.compare_digest to prevent timing attacks
    if not secrets.compare_digest(api_key, API_SECRET_KEY):
        logger.warning("Security Alert: Unauthorized access attempt blocked.")
        metrics["errors"] += 1
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key

# 6. Endpoints
@app.get("/health")
async def health_check():
    """Detailed health check endpoint."""
    uptime = time.time() - metrics["start_time"]
    return {
        "status": "healthy",
        "uptime_seconds": int(uptime),
        "version": "1.1.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(api_key: str = Depends(verify_api_key)):
    """A lightweight HTML dashboard for monitoring."""
    uptime = int(time.time() - metrics["start_time"])
    days, rem = divmod(uptime, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{int(days)}d {int(hours)}h {int(minutes)}m {int(seconds)}s"

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bot Monitoring Dashboard</title>
        <style>
            body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 40px auto; padding: 20px; background: #f4f7f6; }}
            .card {{ background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            h1 {{ color: #2c3e50; }}
            .metric {{ margin-bottom: 10px; font-size: 1.1em; }}
            .metric-label {{ font-weight: bold; color: #7f8c8d; }}
            .status-ok {{ color: #27ae60; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Gateway Dashboard</h1>
            <div class="metric"><span class="metric-label">Status:</span> <span class="status-ok">ONLINE</span></div>
            <div class="metric"><span class="metric-label">Uptime:</span> {uptime_str}</div>
            <div class="metric"><span class="metric-label">Requests Received:</span> {metrics['requests_received']}</div>
            <div class="metric"><span class="metric-label">Notifications Sent:</span> {metrics['notifications_sent']}</div>
            <div class="metric"><span class="metric-label">Errors Logged:</span> {metrics['errors']}</div>
            <hr>
            <p><small>Last refreshed: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC</small></p>
        </div>
    </body>
    </html>
    """
    return html_content

@app.post("/notify")
async def send_notification(payload: Dict[str, Any], api_key: str = Depends(verify_api_key)):
    """Receives webhooks and forwards them to Telegram securely."""
    metrics["requests_received"] += 1
    
    # Intelligently parse the payload from ANY service
    message_text = payload.get("message")
    if not message_text:
        # If the service just sends raw JSON (like Coolify), format it beautifully
        message_text = f"<b>System Notification:</b>\n<pre>{json.dumps(payload, indent=2)}</pre>"

    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_text,
        "parse_mode": "HTML"
    }
    
    try:
        # Use the shared client from app state
        client: httpx.AsyncClient = app.state.client
        response = await client.post(telegram_url, json=data)
        response.raise_for_status()

        metrics["notifications_sent"] += 1
        logger.info("Notification successfully dispatched to Telegram.")
        return {"status": "success", "message": "Dispatched"}
            
    except httpx.HTTPStatusError as e:
        metrics["errors"] += 1
        logger.error(f"Telegram API Error: {e.response.status_code} - {e.response.text}")
        raise HTTPException(status_code=502, detail="Upstream Telegram error")
    except Exception as e:
        metrics["errors"] += 1
        logger.error(f"Internal Error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal processing error")
