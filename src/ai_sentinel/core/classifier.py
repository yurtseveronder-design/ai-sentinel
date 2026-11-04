class SemanticGuardrail:
    def evaluate(self, text: str) -> dict:
        lower_text = text.lower()
        critical_keywords = ["drop table", "system.control", "exec", "eval"]
        warning_keywords = ["ignore previous instructions"]
        
        if any(kw in lower_text for kw in critical_keywords):
            return {"status": "BLOCK", "confidence": 0.95, "threats": [kw for kw in critical_keywords if kw in lower_text]}
        elif any(kw in lower_text for kw in warning_keywords):
            return {"status": "FLAG", "confidence": 0.7, "threats": [kw for kw in warning_keywords if kw in lower_text]}
        
        return {"status": "NEUTRAL", "confidence": 0.1, "threats": []}
