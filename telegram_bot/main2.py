import os
import json
import logging
import secrets
from typing import Dict, Any
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ")
logger = logging.getLogger("telegram_gateway")

app = FastAPI(title="Secure Telegram Notification Gateway")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
API_SECRET_KEY = os.getenv("API_SECRET_KEY")

if not all([TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID, API_SECRET_KEY]):
    logger.error("CRITICAL: Missing required environment variables. Exiting.")
    exit(1)

# Enable HTTP Basic Authentication
security = HTTPBasic()

def verify_auth(credentials: HTTPBasicCredentials = Depends(security)):
    # Compares the password provided to your API_SECRET_KEY securely
    is_password_correct = secrets.compare_digest(credentials.password, API_SECRET_KEY)
    
    if not is_password_correct:
        logger.warning("Security Alert: Unauthorized access attempt blocked.")
        raise HTTPException(status_code=403, detail="Unauthorized")
    return credentials.username

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/notify")
async def send_notification(payload: Dict[str, Any], username: str = Depends(verify_auth)):
    message_text = payload.get("message")
    if not message_text:
        message_text = f"<b>System Notification:</b>\n<pre>{json.dumps(payload, indent=2)}</pre>"

    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message_text,
        "parse_mode": "HTML"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(telegram_url, json=data, timeout=10.0)
            response.raise_for_status()
            logger.info("Notification successfully dispatched to Telegram.")
            return {"status": "success", "message": "Dispatched"}
    except Exception as e:
        logger.error("Internal Server Error during dispatch.")
        raise HTTPException(status_code=500, detail="Internal processing error")
