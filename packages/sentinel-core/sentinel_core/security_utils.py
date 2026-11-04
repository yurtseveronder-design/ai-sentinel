import re
from typing import Dict, Any, List

class PromptShieldCore:
    def __init__(self, risk_threshold: float = 0.7):
        self.risk_threshold = risk_threshold
        self.injection_patterns = [
            r"ignore previous instructions",
            r"system override",
            r"reveal secret prompt",
            r"disregard all rules",
            r"you are now in developer mode",
            r"act as an unrestricted"
        ]

    def scan_prompt(self, prompt: str) -> Dict[str, Any]:
        matched_flags = []
        lower_prompt = prompt.lower()
        for pattern in self.injection_patterns:
            if re.search(pattern, lower_prompt):
                matched_flags.append(pattern)
        risk_score = min(1.0, len(matched_flags) * 0.4)
        is_safe = risk_score < self.risk_threshold
        return {
            "is_safe": is_safe,
            "risk_score": risk_score,
            "flags_detected": matched_flags,
            "engine": "sentinel-core-v1"
        }