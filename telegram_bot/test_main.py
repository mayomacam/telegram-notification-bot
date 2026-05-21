import os
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

# Mock environment variables BEFORE importing the app
os.environ["TELEGRAM_BOT_TOKEN"] = "fake_token"
os.environ["TELEGRAM_CHAT_ID"] = "fake_chat_id"
os.environ["API_SECRET_KEY"] = "test_secret_key"

from telegram_bot.main import app, metrics

client = TestClient(app)

def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "uptime_seconds" in data

def test_unauthorized_access():
    # Test notify without key
    response = client.post("/notify", json={"message": "hello"})
    assert response.status_code == 403

    # Test notify with wrong key
    response = client.post("/notify", json={"message": "hello"}, headers={"X-API-Key": "wrong_key"})
    assert response.status_code == 403

    # Test dashboard without key
    response = client.get("/dashboard")
    assert response.status_code == 403

def test_dashboard_authorized():
    response = client.get("/dashboard", headers={"X-API-Key": "test_secret_key"})
    assert response.status_code == 200
    assert "Gateway Dashboard" in response.text
    assert "ONLINE" in response.text

@pytest.mark.asyncio
async def test_notify_success():
    # We need to mock the httpx client in app.state.client
    # Since TestClient doesn't trigger lifespan events in the same way as a real server for app.state,
    # we manually set it up or mock the call.

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = AsyncMock()

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        # We manually inject the client into app.state if it's not there (for TestClient)
        if not hasattr(app.state, "client"):
            import httpx
            app.state.client = httpx.AsyncClient()

        response = client.post(
            "/notify",
            json={"message": "test message"},
            headers={"X-API-Key": "test_secret_key"}
        )

        assert response.status_code == 200
        assert response.json() == {"status": "success", "message": "Dispatched"}
        assert metrics["notifications_sent"] > 0

def test_notify_raw_json():
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = AsyncMock()

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        if not hasattr(app.state, "client"):
            import httpx
            app.state.client = httpx.AsyncClient()

        payload = {"foo": "bar", "count": 1}
        response = client.post(
            "/notify",
            json=payload,
            headers={"X-API-Key": "test_secret_key"}
        )

        assert response.status_code == 200
        # Check if it was formatted (manually verify the call logic if needed,
        # but here we just check if it succeeded)
        assert response.json()["status"] == "success"
