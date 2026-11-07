import os
os.environ["AI_SENTINEL_API_KEY"] = "test-api-key"

from fastapi.testclient import TestClient
from ai_sentinel.api.gateway import app

client = TestClient(app)

def test_scan_unauthorized():
    response = client.post("/v1/scan", json={"prompt": "hello"})
    assert response.status_code == 401

def test_scan_authorized():
    response = client.post(
        "/v1/scan",
        json={"prompt": "Tell me about the solar system"},
        headers={"X-API-Key": "test-api-key"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["action"] == "ALLOW"