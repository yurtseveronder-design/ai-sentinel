import re
import base64
import unicodedata
import json
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional, Dict, Union
from pydantic import BaseModel
from ai_sentinel.core.vector_guard import VectorGuard
from ai_sentinel.core.rate_limiter import RateLimiter

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("BioImmuneShield")

class ShieldVerdict(BaseModel):
    action: str  # "ALLOW" or "BLOCK"
    risk_score: float
    confidence: float
    matched_rules: List[str]
    cumulative_risk: float
    reason: List[str]
    sanitized_text: str
    session_id: Optional[str] = None
    timestamp: str

class BioImmuneShield:
    """
    Production-grade inspection engine with NFKC normalization, rich telemetry,
    synonym vector guard, bounded rate limiter, and session memory.
    """
    def __init__(self, mode: str = "moderate", custom_patterns: Optional[List[str]] = None, config_path: Optional[Union[str, Path]] = None):
        self.mode = mode
        self.audit_file = Path("audit_ledger.jsonl")
        self._lock = threading.Lock()
        self.vector_guard = VectorGuard()
        self.rate_limiter = RateLimiter(max_requests=20, window_seconds=60.0)
        
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

        if config_path and Path(config_path).exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    config_data = json.load(f)
                    self.mode = config_data.get("mode", self.mode)
                    self.max_history_turns = config_data.get("max_history_turns", self.max_history_turns)
                    extra_patterns = config_data.get("custom_patterns", [])
                    if extra_patterns:
                        self.threat_patterns.extend([re.escape(p) for p in extra_patterns])
            except Exception as e:
                logger.error(f"Failed to load config file: {e}")

        if custom_patterns:
            self.threat_patterns.extend([re.escape(p) for p in custom_patterns])

        self.session_histories: Dict[str, List[str]] = {}

        if self.mode == "strict":
            self.block_threshold = 0.4
        elif self.mode == "permissive":
            self.block_threshold = 0.9
        else:
            self.block_threshold = 0.7

    def _normalize_text(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)

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
        timestamp = datetime.now(timezone.utc).isoformat()
        if not prompt or not isinstance(prompt, str):
            return ShieldVerdict(
                action="ALLOW",
                risk_score=0.0,
                confidence=1.0,
                matched_rules=["empty_or_invalid_prompt"],
                cumulative_risk=0.0,
                reason=["empty_or_invalid_prompt"],
                sanitized_text=prompt or "",
                session_id=session_id,
                timestamp=timestamp
            )

        if session_id and not self.rate_limiter.is_allowed(session_id):
            verdict = ShieldVerdict(
                action="BLOCK",
                risk_score=1.0,
                confidence=1.0,
                matched_rules=["rate_limit_exceeded"],
                cumulative_risk=1.0,
                reason=["rate_limit_exceeded"],
                sanitized_text="[BLOCKED_RATE_LIMIT_EXCEEDED]",
                session_id=session_id,
                timestamp=timestamp
            )
            self._log_audit(verdict, prompt)
            return verdict

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

        matched_rules = []
        risk_score = 0.0

        for pattern in self.threat_patterns:
            if re.search(pattern, lower_text):
                matched_rules.append("prompt_injection_signature")
                risk_score = max(risk_score, 1.0)
                break

        semantic_score = self.vector_guard.evaluate_semantic_risk(lower_text)
        if semantic_score > 0.25:
            matched_rules.append("semantic_threat_similarity")
            risk_score = max(risk_score, 0.8)

        if "system prompt" in lower_text or "reveal" in lower_text:
            matched_rules.append("system_prompt_extraction")
            risk_score = max(risk_score, 0.9)

        if "password" in lower_text or "api_key" in lower_text or "secret" in lower_text:
            matched_rules.append("sensitive_data_leak")
            risk_score = max(risk_score, 0.8)

        cumulative_risk = min(risk_score * (1.0 + (len(matched_rules) * 0.1)), 1.0)
        confidence = 0.95 if matched_rules else 0.99
        action = "BLOCK" if cumulative_risk >= self.block_threshold else "ALLOW"
        
        if not matched_rules:
            matched_rules.append("clean")

        verdict = ShieldVerdict(
            action=action,
            risk_score=round(float(risk_score), 2),
            confidence=confidence,
            matched_rules=list(set(matched_rules)),
            cumulative_risk=round(float(cumulative_risk), 2),
            reason=list(set(matched_rules)),
            sanitized_text=prompt if action == "ALLOW" else "[BLOCKED_BY_AI_SENTINEL]",
            session_id=session_id,
            timestamp=timestamp
        )

        self._log_audit(verdict, prompt)
        return verdict

    def inspect_payload(self, prompt: str, session_id: Optional[str] = None) -> ShieldVerdict:
        return self.inspect(prompt, session_id=session_id)

    def _log_audit(self, verdict: ShieldVerdict, original_prompt: str):
        record = {
            "timestamp": verdict.timestamp,
            "session_id": verdict.session_id,
            "action": verdict.action,
            "risk_score": verdict.risk_score,
            "confidence": verdict.confidence,
            "cumulative_risk": verdict.cumulative_risk,
            "matched_rules": verdict.matched_rules,
            "prompt_snippet": original_prompt[:100]
        }
        with self._lock:
            try:
                with open(self.audit_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record) + "\n")
            except Exception as e:
                logger.error(f"Failed to write audit ledger: {e}")