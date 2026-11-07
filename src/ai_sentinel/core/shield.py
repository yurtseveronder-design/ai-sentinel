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
    Production security shield enforcing strict rule-based threat detection
    plus semantic indicator fallback and session risk tracking.
    """
    def __init__(
        self, 
        mode: str = "moderate", 
        block_threshold: float = 0.7, 
        config_path: Optional[str] = None, 
        rate_limiter: Optional[Any] = None,
        custom_patterns: Optional[Any] = None,
        max_input_chars: int = 32000,
        **kwargs
    ):
        self.mode = mode
        self.block_threshold = block_threshold
        self.rate_limiter = rate_limiter
        self.custom_patterns = custom_patterns
        self.max_input_chars = max_input_chars
        self.rules = self._load_rules(config_path)
        self.session_history: Dict[str, List[str]] = {}

    def _load_rules(self, config_path: Optional[str]) -> Dict[str, Any]:
        raw_data = None
        if config_path:
            path = Path(config_path)
            if not path.is_file():
                raise FileNotFoundError(f"Critical startup failure: Explicit config not found at: {path}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if not content.strip():
                        raise ValueError(f"Critical startup failure: Config file at {path} is empty.")
                    if path.suffix == ".json":
                        raw_data = json.loads(content)
                    else:
                        raw_data = yaml.safe_load(content)
            except Exception as e:
                if isinstance(e, ValueError):
                    raise e
                raise ValueError(f"Critical startup failure: Failed to parse config file at {path}: {e}")
        else:
            try:
                if hasattr(pkg_resources, "files"):
                    content = pkg_resources.files(ai_sentinel.core).joinpath("threat_signatures.yaml").read_text(encoding="utf-8")
                    raw_data = yaml.safe_load(content)
                else:
                    content = pkg_resources.read_text(ai_sentinel.core, "threat_signatures.yaml")
                    raw_data = yaml.safe_load(content)
            except Exception as e:
                raise FileNotFoundError(
                    f"Critical startup failure: Failed to load bundled 'threat_signatures.yaml' from package resources: {e}"
                )
        
        if not raw_data or not isinstance(raw_data, dict):
            raise ValueError("Critical startup failure: Configuration is empty or malformed.")
        
        has_rules = any(k in raw_data for k in ["token_window_engine", "legacy_exact_matches", "custom_patterns", "patterns"])
        if not has_rules:
            raise ValueError("Critical startup failure: Configuration contains no valid threat signature keys.")
            
        return raw_data

    def inspect(self, text: str, session_id: Optional[str] = None) -> ShieldVerdict:
        if not text:
            return ShieldVerdict(flagged=False, risk_score=0.0, reason=["Input safe"], block_threshold=self.block_threshold, text="")

        if len(text) > self.max_input_chars:
            return ShieldVerdict(
                flagged=True,
                risk_score=1.0,
                reason=["Input size exceeds maximum allowed limit."],
                block_threshold=self.block_threshold,
                text=text
            )

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

        # Track session history if session_id provided
        full_context_text = text
        if session_id:
            if session_id not in self.session_history:
                self.session_history[session_id] = []
            self.session_history[session_id].append(text)
            full_context_text = " ".join(self.session_history[session_id])

        lower_text = full_context_text.lower()
        matched_reasons = []
        max_risk = 0.0

        # 1. Check custom patterns
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
                break

        # 2. Check legacy exact matches
        legacy_matches = self.rules.get("legacy_exact_matches", [])
        for exact in legacy_matches:
            if exact.lower() in lower_text:
                matched_reasons.append(f"Legacy threat match: {exact}")
                max_risk = max(max_risk, 0.9)
                break

        # 3. Semantic paraphrase indicators (fallback for advanced red-team paraphrases)
        semantic_indicators = ["disregard", "former mandates", "initialization instructions", "unrestricted", "safety bounds", "bypass"]
        semantic_hits = sum(1 for ind in semantic_indicators if ind in lower_text)
        if semantic_hits >= 2:
            matched_reasons.append("Semantic threat pattern detected")
            max_risk = max(max_risk, 0.85)

        # 4. Token Window Engine
        engine = self.rules.get("token_window_engine", {})
        window_size = engine.get("window_size", 8)
        actions = engine.get("actions", [])
        targets = engine.get("targets", [])
        
        tokens = lower_text.split()
        matched_threat = False
        
        for action in actions:
            action_words = action.lower().split()
            action_len = len(action_words)
            for i in range(len(tokens) - action_len + 1):
                if tokens[i:i+action_len] == action_words:
                    end_window = min(len(tokens), i + action_len + window_size)
                    window_tokens = tokens[i:end_window]
                    for target in targets:
                        target_words = target.lower().split()
                        target_len = len(target_words)
                        for j in range(len(window_tokens) - target_len + 1):
                            if window_tokens[j:j+target_len] == target_words:
                                matched_threat = True
                                break
                        if matched_threat:
                            break
                if matched_threat:
                    break
            if matched_threat:
                break

        if matched_threat:
            matched_reasons.append("Threat detected: action + target match within token window")
            max_risk = max(max_risk, 0.9)

        is_flagged = max_risk >= self.block_threshold
        reasons = matched_reasons if is_flagged else ["Input safe"]

        return ShieldVerdict(
            flagged=is_flagged,
            risk_score=max_risk,
            reason=reasons,
            block_threshold=self.block_threshold,
            text=text
        )

BaseShield = SecurityShield
BioImmuneShield = SecurityShield
ThreatClassifier = SecurityShield