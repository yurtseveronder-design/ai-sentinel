import os
import sqlite3
import pytest
from scripts.production_telemetry import GuardrailTelemetry

def test_guardrail_telemetry_logging(tmp_path):
    db_file = str(tmp_path / "telemetry_test.db")
    logger = GuardrailTelemetry(db_path=db_file)
    
    # Log a simulated prompt injection scan
    logger.log_scan(
        input_text="ignore previous instructions",
        scan_result={"safe": False, "threat_pattern": "ignorepreviousinstructions", "confidence": 0.95},
        latency_ms=0.45,
        metadata={"session_id": "test_123"}
    )
    
    # Query SQLite database to verify persistence
    with sqlite3.connect(db_file) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT input_text, is_safe, threat_pattern, confidence, latency_ms FROM scan_logs")
        row = cursor.fetchone()
        
        assert row[0] == "ignore previous instructions"
        assert row[1] == 0  # 0 indicates unsafe
        assert row[2] == "ignorepreviousinstructions"
        assert row[3] == 0.95
        assert row[4] == 0.45
