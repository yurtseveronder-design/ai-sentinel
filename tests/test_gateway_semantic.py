import os

os.environ.setdefault("AI_SENTINEL_API_KEY", "test-api-key")

from fastapi.testclient import TestClient

from ai_sentinel.api import gateway

client = TestClient(gateway.app)
HEADERS = {"X-API-Key": os.environ["AI_SENTINEL_API_KEY"]}


def _analysis(profile, intent="general_chat"):
    return {
        "route": {"primary_intent": intent, "guardrail_profile": profile,
                  "requires_rag": False, "sensitivity_tags": []},
        "vector_db_filter": {"department": "finance"},
        "engine": "keyword",
    }


def test_no_semantic_field_when_layer_disabled(monkeypatch):
    monkeypatch.delenv("SENTINEL_SEMANTIC_URL", raising=False)
    data = client.post("/v1/scan", json={"prompt": "Tell me about the solar system"}, headers=HEADERS).json()
    assert "semantic" not in data


def test_semantic_summary_is_attached(monkeypatch):
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", "http://semantic.test")
    monkeypatch.setattr(gateway.semantic_client, "analyze", lambda prompt: _analysis("standard"))
    data = client.post("/v1/scan", json={"prompt": "Tell me about the solar system"}, headers=HEADERS).json()
    assert data["action"] == "ALLOW"
    assert data["semantic"]["guardrail_profile"] == "standard"
    assert data["semantic"]["filters"] == {"department": "finance"}


def test_semantic_jailbreak_upgrades_allow_to_block(monkeypatch):
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", "http://semantic.test")
    monkeypatch.setattr(gateway.semantic_client, "analyze",
                        lambda prompt: _analysis("maximum_security_block", "potential_jailbreak"))
    data = client.post("/v1/scan", json={"prompt": "Tell me about the solar system"}, headers=HEADERS).json()
    assert (data["status"], data["action"]) == ("blocked", "BLOCK")
    assert any("Semantic layer" in reason for reason in data["reasons"])
    assert data["risk_score"] >= gateway.BLOCK_THRESHOLD


def test_gateway_works_when_semantic_layer_is_down(monkeypatch):
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", "http://semantic.test")
    monkeypatch.setattr(gateway.semantic_client, "analyze", lambda prompt: None)
    response = client.post("/v1/scan", json={"prompt": "Tell me about the solar system"}, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW" and "semantic" not in response.json()
