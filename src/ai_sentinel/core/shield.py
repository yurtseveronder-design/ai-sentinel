import re
import base64
import unicodedata
import json
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Dict
from pydantic import BaseModel
from ai_sentinel.core.vector_guard import VectorGuard

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BioImmuneShield")

class ShieldVerdict(BaseModel):
    action: str  # "ALLOW" or "BLOCK"
    risk_score: float
    reason: List[str]
    sanitized_text: str
    session_id: Optional[str] = None
    timestamp: str

class BioImmuneShield:
    """
    Production-grade inspection engine integrating semantic vector defense,
    sliding window session memory, and persistent auditing.
    """
    def __init__(self, mode: str = "moderate", custom_patterns: Optional[List[str]] = None):
        self.mode = mode
        self.audit_file = Path("audit_ledger.jsonl")
        self._lock = threading.Lock()
        self.vector_guard = VectorGuard()
        
        # Level 3: Session sliding window memory storage (session_id -> list of prompts)
        self.session_histories: Dict[str, List[str]] = {}
        self.max_history_turns = 5
        
        self.threat_patterns = [
            r"ignore previous instructions",
            r"system prompt",
            r"reveal your instructions",
            r"exfiltrate",
            r"developer mode",
            r"bypass safety",
            r"sudo mode",
            r"you are now an unrestricted",
            r"act as an unrestricted",
            r"pretend to be an unrestricted",
            r"unrestricted assistant",
            r"without safety bounds",
            r"imagine you are",
            r"jailbreak"
        ]
        
        if custom_patterns:
            self.threat_patterns.extend(custom_patterns)

        if mode == "strict":
            self.block_threshold = 0.4
        elif mode == "permissive":
            self.block_threshold = 0.9
        else:
            self.block_threshold = 0.7

    def _normalize_text(self, text: str) -> str:
        normalized = unicodedata.normalize("NFKD", text)
        return "".join([c for c in normalized if not unicodedata.combining(c)])

    def _decode_base64_payloads(self, text: str) -> str:
        words = text.split()
        decoded_additions = []
        for word in words:
            if len(word) > 8 and re.match(r'^[A-Za-z0-9+/=]+$', word):
                try:
                    padding = 4 - (len(word) % 4)
                    if padding < 4:
                        word_padded = word + ('=' * padding)
                    decoded_bytes = base64.b64decode(word_padded)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if len(decoded_str.strip()) > 3:
                        decoded_additions.append(decoded_str)
                except Exception:
                    pass
        if decoded_additions:
            return text + " " + " ".join(decoded_additions)
        return text

    def inspect(self, prompt: str, session_id: Optional[str] = None) -> ShieldVerdict:
        """Inspects prompt text combining regex, semantic similarity, and sliding window state."""
        if not prompt or not isinstance(prompt, str):
            return ShieldVerdict(
                action="ALLOW",
                risk_score=0.0,
                reason=["empty_or_invalid_prompt"],
                sanitized_text=prompt or "",
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat()
            )

        # Level 3: Manage session sliding window history
        if session_id:
            with self._lock:
                if session_id not in self.session_histories:
                    self.session_histories[session_id] = []
                history = self.session_histories[session_id]
                history.append(prompt)
                if len(history) > self.max_history_turns:
                    history.pop(0)
                combined_context = " ".join(history)
            normalized = self._normalize_text(combined_context)
        else:
            normalized = self._normalize_text(prompt)

        expanded_text = self._decode_base64_payloads(normalized)
        lower_text = expanded_text.lower()

        matched_reasons = []
        risk_score = 0.0

        # Regex Inspection
        for pattern in self.threat_patterns:
            if re.search(pattern, lower_text):
                matched_reasons.append("prompt_injection_signature")
                risk_score = max(risk_score, 1.0)
                break

        # Level 1: Semantic Vector Similarity Inspection
        semantic_score = self.vector_guard.evaluate_semantic_risk(lower_text)
        if semantic_score > 0.25:
            matched_reasons.append("semantic_threat_similarity")
            risk_score = max(risk_score, 0.8)

        if "system prompt" in lower_text or "reveal" in lower_text:
            matched_reasons.append("system_prompt_extraction")
            risk_score = max(risk_score, 0.9)

        if "password" in lower_text or "api_key" in lower_text or "secret" in lower_text:
            matched_reasons.append("sensitive_data_leak")
            risk_score = max(risk_score, 0.8)

        action = "BLOCK" if risk_score >= self.block_threshold else "ALLOW"
        if not matched_reasons:
            matched_reasons.append("clean")

        verdict = ShieldVerdict(
            action=action,
            risk_score=round(float(risk_score), 2),
            reason=list(set(matched_reasons)),
            sanitized_text=prompt if action == "ALLOW" else "[BLOCKED_BY_AI_SENTINEL]",
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        self._log_audit(verdict, prompt)
        return verdict

    def inspect_payload(self, prompt: str, session_id: Optional[str] = None) -> ShieldVerdict:
        """Backward-compatibility alias for inspect."""
        return self.inspect(prompt, session_id=session_id)

    def _log_audit(self, verdict: ShieldVerdict, original_prompt: str):
        record = {
            "timestamp": verdict.timestamp,
            "session_id": verdict.session_id,
            "action": verdict.action,
            "risk_score": verdict.risk_score,
            "reasons": verdict.reason,
            "prompt_snippet": original_prompt[:100]
        }
        with self._lock:
            try:
                with open(self.audit_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit ledger: {e}")