from fastapi.testclient import TestClient
from ai_sentinel.gateway.app import app

client = TestClient(app)

def test_inspect_endpoint():
    # /v1/inspect returns configuration successfully with strict status 200
    response = client.get("/v1/inspect")
    assert response.status_code == 200
    data = response.json()
    assert data.get("status") == "success"
    assert "config" in data