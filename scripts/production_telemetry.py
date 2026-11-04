import sqlite3
import json
import time
from typing import Dict, Any

class GuardrailTelemetry:
    def __init__(self, db_path: str = "telemetry.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    input_text TEXT,
                    is_safe INTEGER,
                    threat_pattern TEXT,
                    confidence REAL,
                    latency_ms REAL,
                    metadata TEXT
                )
            """)

    def log_scan(self, input_text: str, scan_result: Dict[str, Any], latency_ms: float, metadata: Dict[str, Any] = None):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO scan_logs (timestamp, input_text, is_safe, threat_pattern, confidence, latency_ms, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    time.time(),
                    input_text,
                    1 if scan_result.get("safe") else 0,
                    scan_result.get("threat_pattern"),
                    scan_result.get("confidence", 0.0),
                    latency_ms,
                    json.dumps(metadata or {})
                )
            )

if __name__ == "__main__":
    logger = GuardrailTelemetry()
    print("Telemetry database initialized successfully.")
