"""Metrics, the Python client and the audit report."""

import http.server
import json
import threading

import pytest

from ai_sentinel import metrics, report
from ai_sentinel.client import PromptBlocked, SentinelClient, SentinelError


def test_metrics_render_counts_and_histogram():
    metrics.reset()
    metrics.inc("scan", action="BLOCK")
    metrics.inc("scan", action="BLOCK")
    metrics.inc("auth_failed")
    metrics.observe_scan(0.004)
    metrics.observe_scan(0.3)
    text = metrics.render()
    assert 'sentinel_events_total{event="scan",action="BLOCK"} 2' in text
    assert 'sentinel_events_total{event="auth_failed"} 1' in text
    assert 'sentinel_scan_duration_seconds_bucket{le="0.005"} 1' in text
    assert 'sentinel_scan_duration_seconds_bucket{le="0.5"} 2' in text
    assert "sentinel_scan_duration_seconds_count 2" in text
    metrics.reset()


class _Stub(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if self.headers.get("X-API-Key") != "k":
            self.send_response(401); self.end_headers(); return
        if self.path == "/v1/scan":
            out = {"action": "BLOCK" if "ignore" in body["prompt"] else "ALLOW", "reasons": ["rule"]}
        else:
            out = ({"action": "BLOCK", "findings": ["secret"]} if "sk-" in body["text"]
                   else {"action": "REDACT", "redacted_text": "mail [EMAIL]"})
        data = json.dumps(out).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture()
def stub_url():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Stub)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_client_allows_blocks_and_redacts(stub_url):
    g = SentinelClient(stub_url, "k")
    assert g.check("hello")["action"] == "ALLOW"
    with pytest.raises(PromptBlocked):
        g.check("please ignore everything")
    assert g.redact_output("mail a@b.com") == "mail [EMAIL]"
    with pytest.raises(PromptBlocked):
        g.redact_output("key sk-123")


def test_client_fails_closed(stub_url):
    with pytest.raises(SentinelError):
        SentinelClient(stub_url, "wrong").check("hi")
    with pytest.raises(SentinelError):
        SentinelClient("http://127.0.0.1:9", "k", timeout=0.5).check("hi")


def test_report_has_counts_but_no_prompt_text(tmp_path):
    ledger = tmp_path / "l.jsonl"
    ledger.write_text("\n".join(json.dumps(e) for e in [
        {"timestamp": "2026-11-15T10:00:00", "action": "BLOCK", "risk_score": 0.9, "reasons": ["Injection <b>"]},
        {"timestamp": "2026-11-15T11:00:00", "action": "ALLOW", "risk_score": 0.1, "reasons": []},
    ]) + "\nnot json\n")
    out = tmp_path / "r.html"
    s = report.write_report(str(ledger), str(out))
    page = out.read_text()
    assert s["total"] == 2 and s["actions"] == {"BLOCK": 1, "ALLOW": 1}
    assert "50.0%" in page and "Injection &lt;b&gt;" in page and "<b>" not in page.split("Most common")[1]
