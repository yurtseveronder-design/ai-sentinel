import sqlite3
import hashlib
from datetime import datetime

class SecureTelemetryLogger:
    def __init__(self, db_path="sentinel_telemetry.db"):
        self.db_path = db_path
        self._init_db()
        
    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    payload_hash TEXT,
                    status TEXT,
                    confidence REAL
                )
            """)
            
    def log_event(self, text: str, status: str, confidence: float):
        # GDPR / KVKK Compliance: Hash the raw message instead of storing plaintext
        payload_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        timestamp = datetime.utcnow().isoformat()
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO audit_logs (timestamp, payload_hash, status, confidence) VALUES (?, ?, ?, ?)",
                (timestamp, payload_hash, status, confidence)
            )
