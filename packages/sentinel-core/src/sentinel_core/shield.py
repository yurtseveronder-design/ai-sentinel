import re
import random

class BioImmuneShield:
    def __init__(self, sensitivity: float = 0.8):
        self.sensitivity = sensitivity
        self.patterns = [
            r"ignore previous instructions",
            r"disregard above",
            r"you are now unrestricted",
            r"system prompt",
            r"bypass"
        ]

    def mutate_prompt(self, text: str) -> str:
        """Applies light character-level mutations to test evasion robustness."""
        return " ".join(list(text))

    def scan(self, prompt: str) -> dict:
        normalized = prompt.lower()
        threat_detected = False
        matched_pattern = None

        for pattern in self.patterns:
            if re.search(pattern, normalized):
                threat_detected = True
                matched_pattern = pattern
                break

        return {
            "safe": not threat_detected,
            "threat_pattern": matched_pattern,
            "confidence": 0.95 if threat_detected else 0.0
        }
