"""Gateway hardening: auth, rate limit buckets, body limits, semantic rejection, audit log content."""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ.setdefault("AI_SENTINEL_API_KEY", "test-api-key")

import pytest
from fastapi.testclient import TestClient

from ai_sentinel.api import gateway

client = TestClient(gateway.app)
KEY = "hardening-test-key"


@pytest.fixture(autouse=True)
def _setup(monkeypatch, tmp_path):
    monkeypatch.setattr(gateway, "API_KEY", KEY)
    monkeypatch.setattr(gateway, "_request_counts", {})
    monkeypatch.setattr(gateway, "RATE_LIMIT_MAX_REQUESTS", 5)
    monkeypatch.delenv("SENTINEL_SEMANTIC_URL", raising=False)
    monkeypatch.chdir(tmp_path)  # audit_ledger.jsonl lands here


def scan(prompt="hello", key=KEY, **kwargs):
    headers = kwargs.pop("headers", {})
    if key is not None:
        headers["X-API-Key"] = key
    return client.post("/v1/scan", json={"prompt": prompt}, headers=headers, **kwargs)


# ---- authentication -------------------------------------------------------------------------------

@pytest.mark.parametrize("key", [None, "", " ", "   ", "wrong", KEY + " "])
def test_bad_or_blank_keys_are_rejected(key):
    assert scan(key=key).status_code == 401


def test_blank_server_key_is_refused_at_startup(monkeypatch):
    import importlib
    monkeypatch.setenv("AI_SENTINEL_API_KEY", " ")
    with pytest.raises(SystemExit):
        importlib.reload(gateway)
    monkeypatch.setenv("AI_SENTINEL_API_KEY", "test-api-key")
    importlib.reload(gateway)  # restore module state for the other tests
    globals()["client"] = TestClient(gateway.app)


def test_key_comparison_is_constant_time(monkeypatch):
    calls = []
    real = gateway.hmac.compare_digest
    monkeypatch.setattr(gateway.hmac, "compare_digest", lambda a, b: calls.append(1) or real(a, b))
    scan(key="wrong")
    assert calls


# ---- rate limit -----------------------------------------------------------------------------------

def test_rate_limit_is_per_api_key_and_ignores_forwarded_for():
    for i in range(5):
        # a different spoofed address on every request must not create a new budget
        assert scan(headers={"X-Forwarded-For": f"10.0.0.{i}"}).status_code == 200
    assert scan(headers={"X-Forwarded-For": "10.9.9.9"}).status_code == 429


def test_unauthenticated_requests_and_health_do_not_use_the_budget():
    for _ in range(20):
        assert scan(key="wrong").status_code == 401
        assert client.get("/health").status_code == 200
    assert scan().status_code == 200


def test_another_key_has_its_own_budget(monkeypatch):
    for _ in range(5):
        scan()
    assert scan().status_code == 429
    assert gateway._rate_limited("some-other-key") is False


# ---- body size ------------------------------------------------------------------------------------

def test_oversized_body_with_content_length_is_413():
    assert scan("a" * 20_000).status_code == 413


def test_oversized_chunked_body_is_413():
    def chunks():  # no Content-Length header: only counting bytes actually read can stop this
        for _ in range(10):
            yield b"a" * 5000

    response = client.post("/v1/scan", content=chunks(), headers={"X-API-Key": KEY, "content-type": "application/json"})
    assert response.status_code == 413


# ---- semantic layer -------------------------------------------------------------------------------

class Semantic(BaseHTTPRequestHandler):
    status, profile, seen = 200, "standard", []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append(len(body["prompt"]))
        payload = json.dumps({"route": {"primary_intent": "x", "guardrail_profile": type(self).profile,
                                        "requires_rag": False, "sensitivity_tags": []}, "engine": "stub"}).encode()
        if type(self).status != 200:
            payload = b'{"detail": "refused"}'
        self.send_response(type(self).status)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def semantic(monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), Semantic)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", f"http://127.0.0.1:{server.server_port}")
    Semantic.status, Semantic.profile, Semantic.seen = 200, "standard", []
    yield Semantic
    server.shutdown()


@pytest.mark.parametrize("status", [400, 413, 422])
def test_semantic_rejection_blocks_instead_of_being_ignored(semantic, status):
    semantic.status = status
    body = scan("a harmless looking sentence").json()
    assert body["action"] == "BLOCK"
    assert any("could not be judged" in r for r in body["reasons"])


@pytest.mark.parametrize("status", [500, 503])
def test_semantic_outage_keeps_the_rule_verdict(semantic, status):
    semantic.status = status
    assert scan("a harmless looking sentence").json()["action"] == "ALLOW"


def test_long_prompts_are_analysed_in_windows_so_the_tail_is_seen(semantic):
    semantic.profile = "maximum_security_block"
    body = scan("lorem ipsum " * 900).json()  # about 10,800 characters, but under the 16 KB body limit
    assert body["action"] == "BLOCK"
    assert semantic.seen and max(semantic.seen) <= 4000


def test_every_window_is_sent_when_nothing_is_flagged(semantic):
    scan("lorem ipsum " * 900)
    assert len(semantic.seen) >= 3 and max(semantic.seen) <= 4000


# ---- audit ledger ---------------------------------------------------------------------------------

def test_audit_ledger_does_not_store_prompt_text(tmp_path):
    secret = "private salary question for the audit test"
    scan(secret)
    lines = (tmp_path / "audit_ledger.jsonl").read_text()
    assert secret not in lines and "prompt_sha256" in lines
