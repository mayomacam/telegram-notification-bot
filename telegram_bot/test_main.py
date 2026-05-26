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
    assert "Sentinel Monitor" in response.text
    assert "ACTIVE" in response.text
    assert "pico.min.css" in response.text
    assert "RPM" in response.text
    assert "Latency" in response.text

@pytest.mark.asyncio
async def test_notify_success():
    # We need to mock the httpx client in app.state.client
    # Since TestClient doesn't trigger lifespan events in the same way as a real server for app.state,
    # we manually set it up or mock the call.

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = lambda: None

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        # We manually inject the client into app.state if it's not there (for TestClient)
        if not hasattr(app.state, "http_client"):
            import httpx
            app.state.http_client = httpx.AsyncClient()

        response = client.post(
            "/notify",
            json={"message": "test message"},
            headers={"X-API-Key": "test_secret_key"}
        )

        assert response.status_code == 200
        assert response.json() == {"status": "success", "message": "Dispatched"}
        assert metrics["successful_notifications"] > 0

def test_notify_raw_json():
    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = lambda: None

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        if not hasattr(app.state, "http_client"):
            import httpx
            app.state.http_client = httpx.AsyncClient()

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

def test_security_headers():
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "Strict-Transport-Security" in response.headers
    assert "X-Request-ID" in response.headers
    assert "X-Process-Time" in response.headers

def test_rate_limiting():
    # Set a very low rate limit for testing
    from telegram_bot.main import rate_limiter
    rate_limiter.requests = 2
    rate_limiter.window = 60
    rate_limiter.clients = {} # Reset clients

    mock_response = AsyncMock()
    mock_response.status_code = 200
    mock_response.raise_for_status = lambda: None

    with patch("httpx.AsyncClient.post", return_value=mock_response):
        if not hasattr(app.state, "http_client"):
            import httpx
            app.state.http_client = httpx.AsyncClient()

        # First request
        response = client.post(
            "/notify",
            json={"message": "test 1"},
            headers={"X-API-Key": "test_secret_key"}
        )
        assert response.status_code == 200

        # Second request
        response = client.post(
            "/notify",
            json={"message": "test 2"},
            headers={"X-API-Key": "test_secret_key"}
        )
        assert response.status_code == 200

        # Third request - should be rate limited
        response = client.post(
            "/notify",
            json={"message": "test 3"},
            headers={"X-API-Key": "test_secret_key"}
        )
        assert response.status_code == 429
