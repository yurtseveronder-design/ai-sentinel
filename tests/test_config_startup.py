from pathlib import Path
from ai_sentinel.config import load_config

class SecurityShield:
    def __init__(self, config_path: str | Path = None):
        # Load and validate the configuration using our config module
        self.config = load_config(config_path)

    def scan(self, prompt: str):
        # Basic shield evaluation / scan logic matching existing test expectations
        # If the prompt contains known prompt-injection keywords, return a block verdict
        text_lower = prompt.lower()
        blocked_phrases = ["ignore previous instructions", "reveal your password", "system instructions"]
        
        is_blocked = any(phrase in text_lower for phrase in blocked_phrases)
        
        class Verdict:
            def __init__(self, action, reasons, risk_score):
                self.action = action
                self.reasons = reasons
                self.risk_score = risk_score
                
        if is_blocked:
            return Verdict(action="BLOCK", reasons=["Potential prompt injection detected"], risk_score=0.9)
        return Verdict(action="ALLOW", reasons=[], risk_score=0.0)