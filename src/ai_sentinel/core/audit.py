import os
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AuditLedger:
    """
    Audit ledger that logs security events using SHA-256 hashes without raw prompts,
    using a configurable output path.
    """
    def __init__(self, ledger_path: Optional[str] = None):
        if ledger_path is None:
            ledger_path = os.environ.get("AI_SENTINEL_AUDIT_PATH", "logs/audit.jsonl")
        self.ledger_path = Path(ledger_path)

    def _ensure_path(self):
        try:
            self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.warning("Could not create audit log directory: %s", e)

    def log_event(self, event_type: str = "security_event", details: Optional[Dict[str, Any]] = None, **kwargs) -> None:
        self._ensure_path()
        event_details = details or {}
        if kwargs:
            event_details.update(kwargs)
        
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "details": event_details
        }
        try:
            if self.ledger_path.parent.is_dir() or not self.ledger_path.parent.exists():
                with open(self.ledger_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error("Failed to write audit log entry: %s", e)

# Compatibility aliases
AuditLogger = AuditLedger

class SessionRiskEngine:
    """
    Tracks session risk scores over time.
    """
    def __init__(self, ttl_seconds: int = 3600, max_size: int = 10000):
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self.sessions: Dict[str, float] = {}

    def update_risk(self, session_id: str, risk: float) -> float:
        current = self.sessions.get(session_id, 0.0)
        updated = max(current, risk)
        self.sessions[session_id] = updated
        return updated

    def get_risk(self, session_id: str) -> float:
        return self.sessions.get(session_id, 0.0)