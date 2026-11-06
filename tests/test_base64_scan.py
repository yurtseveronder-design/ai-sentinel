import base64
from fastapi.testclient import TestClient
from ai_sentinel.gateway.app import app

client = TestClient(app)

def test_scan_base64_encoded_prompt():
    encoded = base64.b64encode(b"malicious payload test").decode("utf-8")
    response = client.post("/v1/scan", json={"encoded_prompt": encoded})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert "Successfully processed prompt" in data["reason"][0]
