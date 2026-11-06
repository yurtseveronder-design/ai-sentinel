import hashlib
import json
import logging
import time
import math
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

class SessionRiskEngine:
    """Tracks per-session risk scores with exponential time-based decay."""
    def __init__(self, decay_lambda: float = 0.1):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.decay_lambda = decay_lambda

    def update_and_get_risk(self, session_id: str, incoming_risk: float) -> float:
        current_time = time.time()
        if session_id not in self.sessions:
            self.sessions[session_id] = {"risk": incoming_risk, "last_updated": current_time}
            return incoming_risk

        data = self.sessions[session_id]
        elapsed = current_time - data["last_updated"]
        
        # Apply exponential risk decay based on time elapsed
        decayed_risk = data["risk"] * math.exp(-self.decay_lambda * elapsed)
        
        new_cumulative_risk = min(1.0, decayed_risk + incoming_risk)
        self.sessions[session_id] = {"risk": new_cumulative_risk, "last_updated": current_time}
        return new_cumulative_risk


class AuditLogger:
    """Append-only JSON-lines audit logger recording metadata and SHA-256 hashes only (no raw prompts)."""
    def __init__(self, log_file: str = "logs/audit.jsonl"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, session_id: Optional[str], text: Optional[str], action: str, risk_score: float, reasons: list):
        prompt_hash = "no_input"
        prompt_len = 0
        if text:
            prompt_len = len(text)
            prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

        record = {
            "timestamp": time.time(),
            "session_id": session_id or "anonymous",
            "prompt_hash": prompt_hash,
            "prompt_length": prompt_len,
            "action": action,
            "risk_score": risk_score,
            "reasons": reasons
        }

        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log entry: {e}")