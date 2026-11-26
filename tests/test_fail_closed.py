"""Fail closed by default: with a semantic layer configured, every way it can fail gives /v1/scan 503 and /ready 'not ready'."""

import os

os.environ.setdefault("AI_SENTINEL_API_KEY", "test-api-key")

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi.testclient import TestClient

from ai_sentinel import semantic_client
from ai_sentinel.api import gateway

KEY = "k-fail-closed"
GOOD = b'{"route": {"primary_intent": "x", "guardrail_profile": "standard", "requires_rag": false, "sensitivity_tags": []}, "engine": "stub"}'


class Semantic(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, *a):
        pass

    def do_GET(self):  # /health always says ok: the point is that /health alone is not enough
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        mode = type(self).mode
        if mode == "slow":
            time.sleep(1.0)
        code = {"http_500": 500, "http_503": 503, "http_401": 401, "http_429": 429}.get(mode, 200)
        body = b"this is not json" if mode == "garbage" else (GOOD if code == 200 else b'{"detail":"x"}')
        try:
            self.send_response(code)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except OSError:
            pass


@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.setattr(gateway, "API_KEY", KEY)
    monkeypatch.setattr(gateway, "EXTRA_API_KEYS", [])
    monkeypatch.setattr(gateway, "MODE", "enforce")
    monkeypatch.setattr(gateway, "_request_counts", {})
    monkeypatch.setattr(gateway, "RATE_LIMIT_MAX_REQUESTS", 10_000)
    monkeypatch.setattr(gateway, "SEMANTIC_REQUIRED", None)  # the setting is not made: the default applies
    monkeypatch.setenv("SENTINEL_SEMANTIC_TIMEOUT", "0.3")
    monkeypatch.chdir(tmp_path)
    semantic_client.reset_state()
    server = ThreadingHTTPServer(("127.0.0.1", 0), Semantic)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    Semantic.mode = "ok"
    yield TestClient(gateway.app), monkeypatch, f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    semantic_client.reset_state()


def scan(client, prompt="a harmless looking sentence"):
    return client.post("/v1/scan", json={"prompt": prompt}, headers={"X-API-Key": KEY})


FAILURES = ["down", "http_500", "http_503", "slow", "garbage", "http_401", "http_429"]  # the seven cases


@pytest.mark.parametrize("case", FAILURES)
def test_every_failure_case_is_503_and_not_ready_by_default(env, case):
    client, mp, url = env
    mp.setenv("SENTINEL_SEMANTIC_URL", "http://127.0.0.1:9" if case == "down" else url)
    Semantic.mode = case
    r = scan(client)
    assert r.status_code == 503, case
    assert "required" in r.json()["detail"]
    ready = client.get("/ready")
    assert ready.status_code == 503 and ready.json()["status"] == "degraded", case


@pytest.mark.parametrize("case", FAILURES)
def test_fail_open_only_when_chosen_on_purpose(env, case):
    client, mp, url = env
    mp.setenv("SENTINEL_SEMANTIC_URL", "http://127.0.0.1:9" if case == "down" else url)
    mp.setattr(gateway, "SEMANTIC_REQUIRED", False)  # SENTINEL_SEMANTIC_REQUIRED=false
    Semantic.mode = case
    r = scan(client)
    assert r.status_code == 200 and r.json()["action"] == "ALLOW"


def test_healthy_layer_is_ready_and_answers(env):
    client, mp, url = env
    mp.setenv("SENTINEL_SEMANTIC_URL", url)
    assert scan(client).status_code == 200
    assert client.get("/ready").status_code == 200


def test_ready_recovers_after_the_layer_recovers(env):
    client, mp, url = env
    mp.setenv("SENTINEL_SEMANTIC_URL", url)
    Semantic.mode = "http_500"
    assert scan(client).status_code == 503 and client.get("/ready").status_code == 503
    Semantic.mode = "ok"
    assert scan(client).status_code == 200 and client.get("/ready").status_code == 200


def test_no_layer_configured_changes_nothing(env):
    client, mp, _ = env
    mp.delenv("SENTINEL_SEMANTIC_URL", raising=False)
    assert scan(client).status_code == 200
    assert client.get("/ready").json()["semantic"] == "not_configured"
    assert gateway.semantic_required() is False


def test_explicit_true_still_works_without_a_url(env):
    client, mp, _ = env
    mp.delenv("SENTINEL_SEMANTIC_URL", raising=False)
    mp.setattr(gateway, "SEMANTIC_REQUIRED", True)
    assert gateway.semantic_required() is True
