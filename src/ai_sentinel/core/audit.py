import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

class AuditLogger:
    """
    Cryptographic audit logger that records inspection events in JSON-Lines format
    without logging raw prompts (hashing them securely).
    """
    def __init__(self, log_path: Optional[str] = None):
        self.log_path = Path(log_path or os.environ.get("AI_SENTINEL_AUDIT_PATH", "logs/audit.jsonl"))

    def _ensure_log_dir(self):
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def log_event(
        self,
        session_id: Optional[str],
        text: str,
        action: str,
        risk_score: float,
        reasons: List[str]
    ) -> Dict[str, Any]:
        self._ensure_log_dir()
        
        prompt_hash = hashlib.sha256(text.encode("utf-8")).hexdigest() if text else ""
        
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id or "anonymous",
            "prompt_hash": prompt_hash,
            "action": action,
            "risk_score": risk_score,
            "reasons": reasons
        }
        
        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event) + "\n")
        except Exception:
            pass
            
        return event

class SessionRiskEngine:
    """
    Tracks rolling risk scores per session with decay.
    """
    def __init__(self, decay_factor: float = 0.9, max_size: int = 1000):
        self.decay_factor = decay_factor
        self.max_size = max_size
        self.sessions: Dict[str, float] = {}

    def update_and_get_risk(self, session_id: str, current_risk: float) -> float:
        if len(self.sessions) >= self.max_size:
            self.sessions.pop(next(iter(self.sessions)))
            
        previous_risk = self.sessions.get(session_id, 0.0)
        new_risk = max(current_risk, previous_risk * self.decay_factor + current_risk * (1 - self.decay_factor))
        self.sessions[session_id] = new_risk
        return new_risk