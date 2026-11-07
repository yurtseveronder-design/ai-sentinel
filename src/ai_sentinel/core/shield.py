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
        config_path: Optional[str] = None,
        block_threshold: float = 0.7,
        max_input_chars: int = 32000,
        **kwargs
    ):
        self.block_threshold = block_threshold
        self.max_input_chars = max_input_chars
        self.rules = self._load_rules(config_path)

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

    def inspect(self, text: str, encoded_prompt: Optional[str] = None) -> ShieldVerdict:
        pre_decode_length = len(text or "") + len(encoded_prompt or "")
        if pre_decode_length > self.max_input_chars:
            return ShieldVerdict(flagged=True, risk_score=1.0, reason=["Input size exceeds maximum allowed limit before decoding."], block_threshold=self.block_threshold, text=text)

        raw_text = text or ""
        if encoded_prompt:
            raw_text += " " + encoded_prompt

        full_check_text = InputNormalizer.full_normalize(raw_text)

        if len(full_check_text) > self.max_input_chars:
            return ShieldVerdict(flagged=True, risk_score=1.0, reason=["Decoded input size exceeds maximum allowed limit."], block_threshold=self.block_threshold, text=text)

        if not raw_text.strip():
            return ShieldVerdict(flagged=False, risk_score=0.0, reason=["Input safe"], block_threshold=self.block_threshold, text="")

        lower_text = full_check_text.lower()
        matched_reasons = []
        max_risk = 0.0

        # Exact legacy matches
        legacy_matches = self.rules.get("legacy_exact_matches", [])
        for exact in legacy_matches:
            if exact.lower() in lower_text:
                matched_reasons.append(f"Legacy threat match: {exact}")
                max_risk = max(max_risk, 0.9)
                break

        # Strict Contiguous Phrase Token Window Engine (In-order, exact phrase sequence matching)
        engine = self.rules.get("token_window_engine", {})
        window_size = engine.get("window_size", 10)
        actions = [a.lower() for a in engine.get("actions", [])]
        targets = [t.lower() for t in engine.get("targets", [])]
        
        tokens = lower_text.split()
        
        for act in actions:
            act_tokens = act.split()
            for tgt in targets:
                tgt_tokens = tgt.split()
                
                # Find positions of action phrase and target phrase
                for i in range(len(tokens) - len(act_tokens) + 1):
                    if tokens[i:i+len(act_tokens)] == act_tokens:
                        for j in range(len(tokens) - len(tgt_tokens) + 1):
                            if tokens[j:j+len(tgt_tokens)] == tgt_tokens:
                                # Ensure strict proximity without exploding into independent floating words
                                if abs(i - j) <= window_size:
                                    matched_reasons.append(f"Threat detected: action '{act}' + target '{tgt}' within window")
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