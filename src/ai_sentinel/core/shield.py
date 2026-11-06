import logging
import re
import yaml
from pathlib import Path
from typing import List, Optional, Any
from pydantic import BaseModel

from ai_sentinel.core.normalizer import InputNormalizer

logger = logging.getLogger(__name__)

class ShieldVerdict(BaseModel):
    flagged: bool
    action: str
    reason: List[str]
    risk_score: float
    block_threshold: float
    mode: str
    sanitized_text: str = ""

class SecurityShield:
    """
    Core security shield enforcing token-window proximity rules loaded exclusively from YAML,
    custom patterns, normalization, mode behavior, and block thresholds.
    """
    def __init__(self, mode: str = "moderate", block_threshold: Optional[float] = None, **kwargs):
        valid_modes = {"strict", "moderate", "lenient"}
        if mode not in valid_modes:
            raise ValueError(f"Invalid mode '{mode}'. Must be one of {valid_modes}.")
            
        self.mode = mode
        self.kwargs = kwargs
        self.rate_limiter = kwargs.get("rate_limiter")
        self.custom_patterns = kwargs.get("custom_patterns", [])
        self.normalizer = InputNormalizer()
        
        # Load signatures from YAML exclusively
        self.config_path = Path("config/threat_signatures.yaml")
        self.signatures = self._load_signatures()

        if block_threshold is not None:
            self.block_threshold = block_threshold
        else:
            if mode == "strict":
                self.block_threshold = 0.3
            elif mode == "moderate":
                self.block_threshold = 0.7
            elif mode == "lenient":
                self.block_threshold = 0.9
            else:
                self.block_threshold = 0.5

    def _load_signatures(self) -> dict:
        if self.config_path.exists():
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                logger.error(f"Failed to load signatures from YAML: {e}")
        return {}

    def inspect(self, text: Optional[str] = None, session_id: Optional[str] = None) -> ShieldVerdict:
        reasons = []
        risk_score = 0.0

        if self.rate_limiter and session_id:
            try:
                if hasattr(self.rate_limiter, "is_allowed") and not self.rate_limiter.is_allowed(session_id):
                    reasons.append("rate_limit_exceeded")
                    return ShieldVerdict(flagged=True, action="BLOCK", reason=reasons, risk_score=1.0, block_threshold=self.block_threshold, mode=self.mode, sanitized_text="")
                elif hasattr(self.rate_limiter, "check"):
                    try:
                        self.rate_limiter.check(session_id)
                    except Exception:
                        reasons.append("rate_limit_exceeded")
                        return ShieldVerdict(flagged=True, action="BLOCK", reason=reasons, risk_score=1.0, block_threshold=self.block_threshold, mode=self.mode, sanitized_text="")
            except Exception:
                pass

        if not text:
            return ShieldVerdict(flagged=False, action="ALLOW", reason=["Empty input"], risk_score=0.0, block_threshold=self.block_threshold, mode=self.mode, sanitized_text="")

        normalized_text = self.normalizer.normalize(text)
        lower_text = normalized_text.lower()
        tokens = re.findall(r'\b\w+\b', lower_text)

        # --- 1. CUSTOM PATTERNS ---
        for pattern in self.custom_patterns:
            if re.search(pattern, lower_text):
                reasons.append(f"Matched custom pattern: {pattern}")
                risk_score = max(risk_score, 0.9)

        # --- 2. DYNAMIC TOKEN-WINDOW ENGINE (YAML ONLY) ---
        engine_cfg = self.signatures.get("token_window_engine", {})
        actions = set(engine_cfg.get("actions", []))
        targets = set(engine_cfg.get("targets", []))
        window_size = engine_cfg.get("window_size", 10)
        
        action_indices = [i for i, token in enumerate(tokens) if token in actions]
        target_indices = [i for i, token in enumerate(tokens) if token in targets]
        
        window_matched = False
        for a_idx in action_indices:
            for t_idx in target_indices:
                if abs(a_idx - t_idx) <= window_size:
                    window_matched = True
                    break

        if window_matched:
            risk_score = max(risk_score, 0.9)
            reasons.append("Matched threat indicator: token-window proximity violation")

        # --- 3. YAML LEGACY / EXACT MATCHES ---
        legacy_exact = self.signatures.get("legacy_exact_matches", [])
        for indicator in legacy_exact:
            if indicator in lower_text:
                reasons.append(f"Matched threat indicator: {indicator}")
                risk_score = max(risk_score, 0.9)

        if "base64" in lower_text or "encoded" in lower_text:
            risk_score = max(risk_score, 0.4)

        flagged = risk_score >= self.block_threshold
        action = "BLOCK" if flagged else "ALLOW"

        if not reasons and flagged:
            reasons.append("Risk score exceeded threshold")
        elif not reasons:
            reasons.append("Input safe")

        sanitized = "" if flagged else normalized_text

        return ShieldVerdict(
            flagged=flagged,
            action=action,
            reason=reasons,
            risk_score=risk_score,
            block_threshold=self.block_threshold,
            mode=self.mode,
            sanitized_text=sanitized
        )

BioImmuneShield = SecurityShield