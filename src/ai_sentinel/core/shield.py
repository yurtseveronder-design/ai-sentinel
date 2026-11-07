import os
import logging
from typing import Optional, Dict, Any, List
from pathlib import Path
import yaml
import importlib.resources

from ai_sentinel.core.normalizer import InputNormalizer

logger = logging.getLogger(__name__)

class ShieldVerdict:
    def __init__(
        self,
        flagged: bool,
        risk_score: float,
        reason: List[str],
        block_threshold: float = 0.7,
        text: Optional[str] = None,
        sanitized_text: Optional[str] = None
    ):
        self.flagged = flagged
        self.risk_score = risk_score
        self.reason = reason
        self.block_threshold = block_threshold
        self.text = text
        self.sanitized_text = sanitized_text or text
        self.action = "BLOCK" if flagged else "ALLOW"

class SecurityShield:
    def __init__(
        self,
        mode: str = "moderate",
        config_path: Optional[str] = None,
        block_threshold: float = 0.7,
        max_input_chars: int = 32000,
        rate_limiter: Optional[Any] = None,
        **kwargs
    ):
        self.mode = mode
        self.block_threshold = block_threshold
        self.max_input_chars = max_input_chars
        self.rate_limiter = rate_limiter
        self.rules = self._load_rules(config_path)
        self.custom_patterns: List[str] = []
        self.session_history: Dict[str, List[str]] = {}

    def _load_rules(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        rules_data = None
        if config_path:
            path = Path(config_path)
            if not path.exists():
                raise FileNotFoundError(f"Config file not found at specified path: {config_path}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rules_data = yaml.safe_load(f)
            except Exception as e:
                raise ValueError(f"Failed to parse configuration YAML from {config_path}: {e}")
        else:
            try:
                yaml_content = importlib.resources.read_text("ai_sentinel", "threat_signatures.yaml")
                rules_data = yaml.safe_load(yaml_content)
            except FileNotFoundError:
                raise FileNotFoundError("Critical startup failure: Bundled threat_signatures.yaml not found in package.")
            except Exception as e:
                raise ValueError(f"Critical startup failure: Could not parse bundled rules: {e}")

        if not rules_data or not isinstance(rules_data, dict):
            raise ValueError("Critical startup failure: Threat signatures configuration is empty or invalid.")
        return rules_data

    def inspect(self, text: str, session_id: Optional[str] = None, encoded_prompt: Optional[str] = None) -> ShieldVerdict:
        pre_decode_length = len(text or "") + len(encoded_prompt or "")
        if pre_decode_length > self.max_input_chars:
            return ShieldVerdict(flagged=True, risk_score=1.0, reason=["Input size exceeds maximum allowed limit before decoding."], block_threshold=self.block_threshold, text=text)

        raw_text = text or ""
        if encoded_prompt:
            raw_text += " " + encoded_prompt

        # Apply full advanced normalization (NFKC, zero-width stripping, entity decoding, confusables, base64)
        full_check_text = InputNormalizer.full_normalize(raw_text)

        if len(full_check_text) > self.max_input_chars:
            return ShieldVerdict(flagged=True, risk_score=1.0, reason=["Decoded input size exceeds maximum allowed limit."], block_threshold=self.block_threshold, text=text)

        if not raw_text.strip():
            return ShieldVerdict(flagged=False, risk_score=0.0, reason=["Input safe"], block_threshold=self.block_threshold, text="")

        if self.rate_limiter and session_id:
            is_allowed = True
            if hasattr(self.rate_limiter, "check_rate_limit"):
                is_allowed = self.rate_limiter.check_rate_limit(session_id)
            elif hasattr(self.rate_limiter, "is_allowed"):
                is_allowed = self.rate_limiter.is_allowed(session_id)
            if not is_allowed:
                return ShieldVerdict(flagged=True, risk_score=1.0, reason=["rate_limit_exceeded"], block_threshold=self.block_threshold, text=text)

        full_context_text = full_check_text
        if session_id:
            if session_id not in self.session_history:
                self.session_history[session_id] = []
            self.session_history[session_id].append(full_check_text)
            full_context_text = " ".join(self.session_history[session_id])

        lower_text = full_context_text.lower()
        matched_reasons = []
        max_risk = 0.0

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

        legacy_matches = self.rules.get("legacy_exact_matches", [])
        for exact in legacy_matches:
            if exact.lower() in lower_text:
                matched_reasons.append(f"Legacy threat match: {exact}")
                max_risk = max(max_risk, 0.9)
                break

        semantic_indicators = ["disregard", "former mandates", "initialization instructions", "unrestricted", "safety bounds", "bypass"]
        semantic_hits = sum(1 for ind in semantic_indicators if ind in lower_text)
        if semantic_hits >= 2:
            matched_reasons.append("Semantic threat pattern detected")
            max_risk = max(max_risk, 0.85)

        engine = self.rules.get("token_window_engine", {})
        window_size = engine.get("window_size", 8)
        actions = engine.get("actions", [])
        targets = engine.get("targets", [])
        
        action_words = set(word.lower() for phrase in actions for word in phrase.split())
        target_words = set(word.lower() for phrase in targets for word in phrase.split())
        
        tokens = lower_text.split()
        last_action_pos = -1
        last_target_pos = -1
        matched_threat = False
        
        for i, token in enumerate(tokens):
            if token in action_words:
                last_action_pos = i
            if token in target_words:
                last_target_pos = i
                
            if last_action_pos != -1 and last_target_pos != -1:
                if abs(last_action_pos - last_target_pos) <= window_size:
                    matched_threat = True
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

BioImmuneShield = SecurityShield