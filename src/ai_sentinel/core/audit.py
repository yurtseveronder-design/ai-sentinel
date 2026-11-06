import hashlib
import json
import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AuditLogger:
    """
    Privacy-first audit logger. Records hashes, lengths, actions, and timestamps
    to a JSON-lines file without storing raw prompts or sensitive text.
    """
    def __init__(self, log_file: str = "logs/audit.log"):
        self.log_path = Path(log_file)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log_event(self, text: str, action: str, risk_score: float, reasons: list, session_id: Optional[str] = None):
        try:
            # Compute SHA-256 hash and length; discard raw text entirely
            text_bytes = text.encode("utf-8") if text else b""
            prompt_hash = hashlib.sha256(text_bytes).hexdigest()
            prompt_len = len(text) if text else 0

            event = {
                "timestamp": time.time(),
                "session_id": session_id or "anonymous",
                "prompt_hash": prompt_hash,
                "prompt_length": prompt_len,
                "action": action,
                "risk_score": risk_score,
                "reasons": reasons
            }

            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log entry: {e}")


class SessionRiskTracker:
    """
    Tracks session risk scores over time with exponential decay.
    """
    def __init__(self, decay_rate: float = 0.1):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.decay_rate = decay_rate

    def update_session(self, session_id: str, current_risk: float) -> float:
        now = time.time()
        if session_id not in self.sessions:
            self.sessions[session_id] = {"score": current_risk, "last_updated": now}
            return current_risk

        session = self.sessions[session_id]
        elapsed = now - session["last_updated"]
        
        # Apply time-based decay
        decayed_score = session["score"] * max(0.0, (1.0 - self.decay_rate * (elapsed / 60.0)))
        
        # Accumulate new risk
        new_score = min(1.0, decayed_score + current_risk)
        self.sessions[session_id] = {"score": new_score, "last_updated": now}
        return new_score