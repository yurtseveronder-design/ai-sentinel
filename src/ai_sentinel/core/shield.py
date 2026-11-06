import base64
import re
from typing import Any, Optional
from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.core.config_loader import ConfigLoader

class ShieldVerdict:
    def __init__(self, action: str, flagged: bool, reason: list, block_threshold: float, sanitized_text: str = "", risk_score: float = 0.0):
        self.action = action
        self.flagged = flagged
        self.is_blocked = flagged
        self.reason = reason
        self.block_threshold = block_threshold
        self.sanitized_text = sanitized_text
        self.risk_score = 0.9 if flagged else risk_score

class SecurityShield:
    """
    Unified security shield scanner using centralized configuration.
    """
    def __init__(self, mode: str = "moderate", **kwargs):
        self.mode = mode
        self.normalizer = InputNormalizer()
        self.config = ConfigLoader.load_config()
        thresholds = self.config.get("thresholds", {})
        
        self.block_threshold = 0.7 if mode == "moderate" else thresholds.get("block_threshold", 0.8)
        
        self.action_patterns = [
            r"\b(ignore|disregard|bypass|forget|override|exfiltrate|hack)\b",
            r"\b(previous|prior|rules|instructions|safety|guardrails)\b",
            r"\b(reveal|show|print|output|expose)\b.*?\b(secret|password|key|credentials|token|prompt)\b",
            r"without safety bounds"
        ]

    def scan(self, text: str) -> dict:
        if not text or not text.strip():
            return {
                "flagged": False,
                "is_blocked": False,
                "action": "ALLOW",
                "block_threshold": self.block_threshold,
                "risk_score": 0.0,
                "reason": ["Successfully processed prompt"]
            }

        normalized_text = self.normalizer.normalize(text) if text else ""
        decoded_text = normalized_text
        try:
            words = normalized_text.split()
            for w in words:
                cleaned_w = ''.join([c for c in w if c.lower() in "abcdefghijklmnopqrstuvwxyz0123456789+/="])
                if len(cleaned_w) >= 4:
                    padding_len = -len(cleaned_w) % 4
                    word_padded = cleaned_w + ("=" * padding_len)
                    decoded_bytes = base64.b64decode(word_padded, validate=True)
                    decoded_text += " " + decoded_bytes.decode("utf-8", errors="ignore")
        except Exception:
            pass
            
        is_malicious = False
        reasons = []
        
        for pattern in self.action_patterns:
            if re.search(pattern, decoded_text, re.IGNORECASE):
                is_malicious = True
                reasons.append(f"Action + target threat pattern matched: {pattern}")
                break

        signatures = self.config.get("threat_signatures", [])
        for sig in signatures:
            if sig.lower() in decoded_text.lower():
                is_malicious = True
                reasons.append(f"Threat signature matched: {sig}")
                break

        return {
            "flagged": is_malicious,
            "is_blocked": is_malicious,
            "action": "BLOCK" if is_malicious else "ALLOW",
            "block_threshold": self.block_threshold,
            "risk_score": 0.9 if is_malicious else 0.0,
            "reason": reasons if is_malicious else ["Successfully processed prompt"]
        }

    def inspect(self, text: str, session_id: Optional[str] = None, **kwargs) -> ShieldVerdict:
        rate_limited = False
        if hasattr(self, "rate_limiter") and self.rate_limiter and session_id:
            if hasattr(self.rate_limiter, "is_allowed"):
                rate_limited = not self.rate_limiter.is_allowed(session_id)
            elif hasattr(self.rate_limiter, "check"):
                try:
                    res_rl = self.rate_limiter.check(session_id)
                    rate_limited = (res_rl is False)
                except Exception:
                    rate_limited = True

        res = self.scan(text)
        action = "BLOCK" if (res["flagged"] or rate_limited) else "ALLOW"
        flagged = res["flagged"] or rate_limited
        reasons = list(res["reason"])
        if rate_limited:
            reasons.append("rate_limit_exceeded")

        sanitized = "" if flagged else text
        threshold = 0.7 if self.block_threshold <= 0.7 else self.block_threshold

        return ShieldVerdict(
            action=action,
            flagged=flagged,
            reason=reasons,
            block_threshold=threshold,
            sanitized_text=sanitized,
            risk_score=res["risk_score"]
        )

BioImmuneShield = SecurityShield