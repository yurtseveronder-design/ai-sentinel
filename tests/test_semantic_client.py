import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from ai_sentinel import semantic_client


class _Handler(BaseHTTPRequestHandler):
    seen = {}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        _Handler.seen = {"path": self.path, "key": self.headers.get("X-API-Key"), "prompt": body["prompt"]}
        payload = json.dumps({
            "route": {"primary_intent": "financial_query", "guardrail_profile": "strict_financial",
                      "requires_rag": True, "sensitivity_tags": []},
            "vector_db_filter": {"department": "finance"},
            "engine": "keyword",
        }).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *a):
        pass


@pytest.fixture
def server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()
    srv.server_close()


def test_disabled_without_url(monkeypatch):
    monkeypatch.delenv("SENTINEL_SEMANTIC_URL", raising=False)
    assert semantic_client.semantic_enabled() is False
    assert semantic_client.analyze("hello") is None


def test_analyze_sends_prompt_and_key(monkeypatch, server):
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", server)
    monkeypatch.setenv("SENTINEL_SEMANTIC_API_KEY", "k")
    result = semantic_client.analyze("budget please")
    assert _Handler.seen == {"path": "/api/v1/semantic/analyze", "key": "k", "prompt": "budget please"}
    summary = semantic_client.summarize(result)
    assert summary["intent"] == "financial_query" and summary["filters"] == {"department": "finance"}


def test_fails_open_when_service_is_down(monkeypatch):
    monkeypatch.setenv("SENTINEL_SEMANTIC_URL", "http://127.0.0.1:9")
    monkeypatch.setenv("SENTINEL_SEMANTIC_TIMEOUT", "0.5")
    assert semantic_client.analyze("hello") is None
