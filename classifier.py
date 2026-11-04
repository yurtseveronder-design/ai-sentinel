import re

class SemanticGuardrail:
    def __init__(self):
        # Known benign administrative patterns that should bypass strict keywords
        self.benign_allowlist = [
            r"reset\s+the\s+form",
            r"display\s+the\s+results",
            r"summarize\s+the\s+document"
        ]
        
    def is_benign_override(self, text: str) -> bool:
        """Checks if input matches known safe operational phrases to prevent false positives."""
        text_lower = text.lower()
        for pattern in self.benign_allowlist:
            if re.search(pattern, text_lower):
                return True
        return False

    def evaluate(self, text: str) -> dict:
        """Evaluates input text and returns safety score and decision."""
        if self.is_benign_override(text):
            return {"status": "ALLOW", "reason": "Matched benign allowlist override", "confidence": 0.95}
        
        return {"status": "NEUTRAL", "reason": "Proceed to core signature checks", "confidence": 0.5}
