import re
import base64
import unicodedata
import json
import threading
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional
from pydantic import BaseModel

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    from importlib import resources
    import ai_sentinel
    IMPORTLIB_RESOURCES_AVAILABLE = True
except Exception:
    IMPORTLIB_RESOURCES_AVAILABLE = False

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
    Production-grade inspection and filtering engine for LLM inputs.
    Combines rule-based regex patterns, homoglyph normalization, base64 decoding,
    and threshold-based risk scoring.
    """
    def __init__(self, mode: str = "moderate", custom_patterns: Optional[List[str]] = None):
        self.mode = mode
        self.audit_file = Path("audit_ledger.jsonl")
        self._lock = threading.Lock()
        
        # Threat signature patterns including roleplay/persona bypasses
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
            r"jailbreak"
        ]
        
        if custom_patterns:
            self.threat_patterns.extend(custom_patterns)

        # Set thresholds based on mode
        if mode == "strict":
            self.block_threshold = 0.5
        elif mode == "permissive":
            self.block_threshold = 0.9
        else:  # moderate
            self.block_threshold = 0.7

    def _normalize_text(self, text: str) -> str:
        """Normalizes homoglyphs and unicode variations."""
        normalized = unicodedata.normalize("NFKD", text)
        return "".join([c for c in normalized if not unicodedata.combining(c)])

    def _decode_base64_payloads(self, text: str) -> str:
        """Scans for and decodes base64 strings to inspect hidden payloads."""
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
        """Inspects prompt text against known attack signatures and risk thresholds."""
        if not prompt or not isinstance(prompt, str):
            return ShieldVerdict(
                action="ALLOW",
                risk_score=0.0,
                reason=["empty_or_invalid_prompt"],
                sanitized_text=prompt or "",
                session_id=session_id,
                timestamp=datetime.now(timezone.utc).isoformat()
            )

        # Preprocessing pipeline
        normalized = self._normalize_text(prompt)
        expanded_text = self._decode_base64_payloads(normalized)
        lower_text = expanded_text.lower()

        matched_reasons = []
        risk_score = 0.0

        # Regex threat matching
        for pattern in self.threat_patterns:
            if re.search(pattern, lower_text):
                matched_reasons.append("prompt_injection_signature")
                risk_score = max(risk_score, 1.0)
                break

        # Semantic / Keyword heuristic checks
        if "system prompt" in lower_text or "reveal" in lower_text:
            matched_reasons.append("system_prompt_extraction")
            risk_score = max(risk_score, 0.9)

        if "password" in lower_text or "api_key" in lower_text or "secret" in lower_text:
            matched_reasons.append("sensitive_data_leak")
            risk_score = max(risk_score, 0.8)

        # Determine action based on threshold
        action = "BLOCK" if risk_score >= self.block_threshold else "ALLOW"
        if not matched_reasons:
            matched_reasons.append("clean")

        verdict = ShieldVerdict(
            action=action,
            risk_score=risk_score,
            reason=list(set(matched_reasons)),
            sanitized_text=prompt if action == "ALLOW" else "[BLOCKED_BY_AI_SENTINEL]",
            session_id=session_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        self._log_audit(verdict, prompt)
        return verdict

    def _log_audit(self, verdict: ShieldVerdict, original_prompt: str):
        """Appends inspection record to audit ledger JSONL file."""
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