"""
Unit tests for AuditLogger in SecurityShield Lab.
"""

import json
from ai_sentinel.core.audit import AuditLogger


def test_audit_logger_generates_valid_json():
    audit = AuditLogger()
    payload = audit.log_event("BLOCK", 0.95, "test_client_99", ["Prompt injection detected"])
    data = json.loads(payload)
    
    assert data["action"] == "BLOCK"
    assert data["risk_score"] == 0.95
    assert data["client_id"] == "test_client_99"
    assert len(data["reasons"]) == 1