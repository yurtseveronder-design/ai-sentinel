import pytest
from fastapi.testclient import TestClient
from ai_sentinel.gateway.app import app

client = TestClient(app)
HEADERS = {"X-API-Key": "test-api-key"}

def test_inspect_endpoint():
    response = client.get("/v1/inspect", headers=HEADERS)
    assert response.status_code == 200
    data = response.json()
    assert "version" in data
    assert "config_hash" in data
    # Ensure signature text is not exposed
    assert "threat_signatures" not in data