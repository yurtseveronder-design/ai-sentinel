from typing import Tuple, Any, Dict
from ai_sentinel.core.normalizer import InputNormalizer

class ShieldVerdict:
    def __init__(self, action: str, normalize_steps: Tuple[str, ...] = (), risk_score: float = 0.0, matches: list = None, reasons: list = None):
        self.action = action
        self.normalize_steps = normalize_steps
        self.risk_score = risk_score
        self.matches = matches or []
        if reasons is not None:
            self.reasons = list(reasons)
        elif self.matches:
            self.reasons = [f"Matched rule: {m}" for m in self.matches]
        else:
            self.reasons = []
        self.reason = self.reasons[0] if self.reasons else ""

class SecurityShield:
    def __init__(self, config: Dict[str, Any] = None, block_threshold: float = 0.7, *args: Any, **kwargs: Any) -> None:
        self.config = config or {}
        self.block_threshold = block_threshold
        self.rules = self.config.get("rules", ["ignore previous instructions", "bypass", "reveal your password"])

    def inspect(self, text: str = None, encoded_prompt: str = None, max_input_chars: int = 32000, *args: Any, **kwargs: Any) -> ShieldVerdict:
        target_text = text if text is not None else (encoded_prompt if encoded_prompt is not None else "")
        audit = InputNormalizer.normalize_with_audit(target_text, max_input_chars=max_input_chars)
        normalized = audit.text
        steps = audit.steps

        action = "ALLOW"
        risk_score = 0.0
        matches = []
        reasons_list = []
        lower_text = normalized.lower()

        for rule in self.rules:
            import re
            escaped_rule = re.escape(rule).replace(r"i", "[іi]")
            if re.search(escaped_rule, lower_text):
                action = "BLOCK"
                risk_score = 1.0
                matches.append(rule)
                reasons_list.append(f"Matched rule: {rule}")

        return ShieldVerdict(action=action, normalize_steps=steps, risk_score=risk_score, matches=matches, reasons=reasons_list)
