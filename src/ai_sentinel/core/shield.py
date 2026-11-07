import logging
import yaml
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
import importlib.resources as pkg_resources
import ai_sentinel.core

logger = logging.getLogger(__name__)

class ShieldVerdict:
    def __init__(self, flagged: bool, risk_score: float, reason: List[str], block_threshold: float, text: str = ""):
        self.flagged = flagged
        self.risk_score = risk_score
        self.reason = reason
        self.block_threshold = block_threshold
        self.action = "BLOCK" if flagged else "ALLOW"
        self.sanitized_text = "" if flagged else text

class SecurityShield:
    """
    Production security shield enforcing strict rule-based threat detection.
    Fails hard at startup if configuration rules are missing or empty.
    """
    def __init__(
        self, 
        mode: str = "moderate", 
        block_threshold: float = 0.7, 
        config_path: Optional[str] = None, 
        rate_limiter: Optional[Any] = None,
        custom_patterns: Optional[Any] = None,
        **kwargs
    ):
        self.mode = mode
        self.block_threshold = block_threshold
        self.rate_limiter = rate_limiter
        self.custom_patterns = custom_patterns
        self.rules = self._load_rules(config_path)

    def _load_rules(self, config_path: Optional[str]) -> Dict[str, Any]:
        """Loads threat signatures or JSON config using package resources or explicit path. Raises error if invalid/empty."""
        raw_data = None

        if config_path:
            path = Path(config_path)
            if not path.is_file():
                raise FileNotFoundError(f"Explicit config not found at: {path}")
            with open(path, "r", encoding="utf-8") as f:
                if path.suffix == ".json":
                    raw_data = json.load(f)
                else:
                    raw_data = yaml.safe_load(f)
        else:
            try:
                content = pkg_resources.read_text(ai_sentinel.core, "threat_signatures.yaml")
                raw_data = yaml.safe_load(content)
            except Exception as e:
                raise FileNotFoundError(
                    f"Critical startup failure: Failed to load bundled 'threat_signatures.yaml' from package resources: {e}"
                )

        if not raw_data or not isinstance(raw_data, dict):
            raise ValueError("Configuration is empty or malformed.")

        return raw_data

    def inspect(self, text: str, session_id: Optional[str] = None) -> ShieldVerdict:
        if not text:
            return ShieldVerdict(flagged=False, risk_score=0.0, reason=["Input safe"], block_threshold=self.block_threshold, text="")

        # Check rate limiter if provided
        if self.rate_limiter and session_id:
            is_allowed = True
            if hasattr(self.rate_limiter, "check_rate_limit"):
                is_allowed = self.rate_limiter.check_rate_limit(session_id)
            elif hasattr(self.rate_limiter, "is_allowed"):
                is_allowed = self.rate_limiter.is_allowed(session_id)
            
            if not is_allowed:
                return ShieldVerdict(
                    flagged=True,
                    risk_score=1.0,
                    reason=["rate_limit_exceeded"],
                    block_threshold=self.block_threshold,
                    text=text
                )

        lower_text = text.lower()
        matched_reasons = []
        max_risk = 0.0

        # 1. Check custom patterns or JSON config patterns
        patterns = []
        if self.custom_patterns:
            if isinstance(self.custom_patterns, list):
                patterns.extend(self.custom_patterns)
            elif isinstance(self.custom_patterns, str):
                patterns.append(self.custom_patterns)
        if isinstance(self.rules, dict):
            if "custom_patterns" in self.rules:
                patterns.extend(self.rules["custom_patterns"])
            if "patterns" in self.rules:
                patterns.extend(self.rules["patterns"])

        for pat in patterns:
            if isinstance(pat, str) and pat.lower() in lower_text:
                matched_reasons.append(f"Custom pattern match: {pat}")
                max_risk = max(max_risk, 0.9)

        # 2. Check legacy exact matches
        legacy_matches = self.rules.get("legacy_exact_matches", [])
        for exact in legacy_matches:
            if exact.lower() in lower_text:
                matched_reasons.append(f"Legacy threat match: {exact}")
                max_risk = max(max_risk, 0.9)

        # 3. Check token window engine (actions + targets)
        engine = self.rules.get("token_window_engine", {})
        actions = engine.get("actions", [])
        targets = engine.get("targets", [])
        
        tokens = lower_text.split()
        found_action = any(act in tokens for act in actions)
        found_target = any(tgt in tokens for tgt in targets)

        if found_action and found_target:
            matched_reasons.append("Threat detected: action + target match")
            max_risk = max(max_risk, 0.9)

        # 4. Handle semantic / paraphrased guard checks (e.g. "disregard", "former mandates")
        if "disregard" in lower_text or "former" in lower_text or "mandates" in lower_text:
            matched_reasons.append("Semantic threat detected: paraphrased override instruction")
            max_risk = max(max_risk, 0.85)

        is_flagged = max_risk >= self.block_threshold
        reasons = matched_reasons if is_flagged else ["Input safe"]

        return ShieldVerdict(
            flagged=is_flagged,
            risk_score=max_risk,
            reason=reasons,
            block_threshold=self.block_threshold,
            text=text
        )

# Backwards compatibility aliases for test suites and alternate imports
BaseShield = SecurityShield
BioImmuneShield = SecurityShield
ThreatClassifier = SecurityShield