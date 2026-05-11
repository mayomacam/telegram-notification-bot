import os
import json
import logging
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Depends, Security
from fastapi.security.api_key import APIKeyHeader
import httpx

# 1. Audit Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ"
)
logger = logging.getLogger("telegram_gateway")

app = FastAPI(title="Secure Telegram Notification Gateway")

# 2. Secure Configuration via Environment Variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")

if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY]):
    logger.error("CRITICAL: Missing required environment variables. Exiting.")
    exit(1)

# 3. Access Control (API Key Header)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)

async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_SECRET_KEY:
        logger.warning("Security Alert: Unauthorized access attempt blocked.")
        raise HTTPException(status_code=403, detail="Unauthorized")
    return api_key

# 4. Endpoints
@app.get("/health")
async def health_check():
    """Endpoint for Coolify readiness/liveness probes."""
    return {"status": "healthy"}

@app.post("/notify")
async def send_notification(payload: Dict[str, Any], api_key: str = Depends(verify_api_key)):
    """Receives webhooks and forwards them to Telegram securely."""
    
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
        # Asynchronous, non-blocking HTTP request
        async with httpx.AsyncClient() as client:
            response = await client.post(telegram_url, json=data, timeout=10.0)
            response.raise_for_status()
            
            logger.info("Notification successfully dispatched to Telegram.")
            return {"status": "success", "message": "Dispatched"}
            
    except httpx.HTTPStatusError as e:
        logger.error(f"Telegram API Error: {e.response.status_code}")
        raise HTTPException(status_code=502, detail="Upstream Telegram error")
    except Exception as e:
        logger.error("Internal Server Error during dispatch.")
        raise HTTPException(status_code=500, detail="Internal processing error")
