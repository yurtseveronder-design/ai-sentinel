import logging
import re
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List

from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.config.loader import ConfigLoader

logger = logging.getLogger(__name__)

class SecurityShield:
    """
    Enterprise-grade security shield scanner featuring fail-closed error boundaries,
    explicit exception logging, and centralized configuration.
    """

    def __init__(self, mode: str = "moderate", config_path: Optional[str] = None, rate_limiter: Optional[Any] = None, **kwargs):
        self.mode = mode
        self.config_path = config_path
        self.rate_limiter = rate_limiter
        self.normalizer = InputNormalizer()
        self.config = ConfigLoader.load_config(config_path) if config_path else {}
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

        layer_error = None
        decoded_text = text
        try:
            normalized_text = self.normalizer.normalize(text) if self.normalizer else text
            decoded_text = normalized_text
            words = normalized_text.split()
            for w in words:
                cleaned_w = ''.join([c for c in w if c.lower() in "abcdefghijklmnopqrstuvwxyz0123456789+/_="])
                if len(cleaned_w) >= 4:
                    padding_len = -len(cleaned_w) % 4
                    word_padded = cleaned_w + ("=" * padding_len)
                    try:
                        decoded_bytes = base64.b64decode(word_padded, validate=True)
                        decoded_text += " " + decoded_bytes.decode("utf-8", errors="ignore")
                    except Exception as dec_err:
                        logger.debug("Base64 segment decode skip: %s", dec_err)
        except Exception as e:
            logger.error("SecurityShield normalization/decoding error: %s", e, exc_info=True)
            layer_error = "normalizer"

        is_malicious = False
        reasons = []

        if layer_error:
            if self.mode == "strict":
                is_malicious = True
                reasons.append("Fail-closed triggered due to layer error")
            elif self.mode == "moderate":
                is_malicious = True
                reasons.append("Fail-closed triggered due to layer error")

        try:
            for pattern in self.action_patterns:
                if re.search(pattern, decoded_text, re.IGNORECASE):
                    is_malicious = True
                    reasons.append(f"Action + target threat pattern matched: {{pattern}}")
                    break

            signatures = self.config.get("threat_signatures", [])
            for sig in signatures:
                if sig.lower() in decoded_text.lower():
                    is_malicious = True
                    reasons.append(f"Threat signature matched: {{sig}}")
                    break
        except Exception as pat_err:
            logger.error("Threat pattern matching error: %s", pat_err, exc_info=True)
            is_malicious = True
            reasons.append("Layer error: pattern_matcher")

        return {
            "flagged": is_malicious,
            "is_blocked": is_malicious,
            "action": "BLOCK" if is_malicious else "ALLOW",
            "block_threshold": self.block_threshold,
            "risk_score": 0.9 if is_malicious else 0.0,
            "reason": reasons if reasons else ["Successfully processed prompt"]
        }

    def inspect(self, text: str, session_id: Optional[str] = None, **kwargs) -> Any:
        rate_limited = False
        if hasattr(self, "rate_limiter") and self.rate_limiter and session_id:
            try:
                if hasattr(self.rate_limiter, "is_allowed"):
                    rate_limited = not self.rate_limiter.is_allowed(session_id)
                elif hasattr(self.rate_limiter, "check"):
                    res_rl = self.rate_limiter.check(session_id)
                    rate_limited = (res_rl is False)
            except Exception as rl_err:
                logger.error("Rate limiter evaluation error: %s", rl_err, exc_info=True)
                rate_limited = True

        res = self.scan(text)
        action = "BLOCK" if (res["flagged"] or rate_limited) else "ALLOW"
        flagged = res["flagged"] or rate_limited
        reasons = list(res["reason"])
        if rate_limited:
            reasons.append("rate_limit_exceeded")

        sanitized = "" if flagged else text
        threshold = 0.7 if self.block_threshold <= 0.7 else self.block_threshold

        # Returning the verdict object/dict matching expected interface
        return type("ShieldVerdict", (), {
            "action": action,
            "flagged": flagged,
            "reason": reasons,
            "block_threshold": threshold,
            "sanitized_text": sanitized,
            "risk_score": res["risk_score"]
        })()

BioImmuneShield = SecurityShield