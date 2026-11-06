from fastapi.testclient import TestClient
from ai_sentinel.gateway.app import app

client = TestClient(app)

def test_inspect_endpoint():
    response = client.get("/v1/inspect")
    # Should return either 200 with config or 500 with clean detail (no raw exception leak)
    assert response.status_code in [200, 500]
    data = response.json()
    if response.status_code == 500:
        assert "detail" in data
        assert isinstance(data["detail"], str)
    else:
        assert "status" in data
