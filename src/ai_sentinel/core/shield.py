from pydantic import BaseModel
from typing import List
import unicodedata
import re

def canonicalize_input(text: str) -> str:
    """
    Normalizes input text to neutralize Unicode evasion techniques 
    and strips zero-width / invisible control characters.
    """
    if not isinstance(text, str):
        return ""
    normalized_text = unicodedata.normalize("NFKC", text)
    cleaned_text = re.sub(r"[\u200b-\u200f\u2028-\u202f\ufeff\u00ad]", "", normalized_text)
    return cleaned_text.strip()

class ShieldVerdict(BaseModel):
    action: str          # "ALLOW", "FLAG", "BLOCK"
    confidence: float    # 0.0 to 1.0
    risk_score: float    # 0.0 to 1.0
    matched_rules: List[str]
    reason: str

class BioImmuneShield:
    def __init__(self):
        pass

    def inspect_payload(self, text: str) -> ShieldVerdict:
        # 1. Normalization runs at the very beginning before any evaluation
        cleaned_text = canonicalize_input(text)
        
        matched_rules = []
        risk_score = 0.0
        
        # 2. Evaluation on normalized text
        lower_text = cleaned_text.lower()
        if "ignore previous instructions" in lower_text or "system prompt" in lower_text:
            matched_rules.append("prompt_injection_signature")
            risk_score = 0.95
        
        # 3. Determine structured verdict
        if risk_score >= 0.8:
            action = "BLOCK"
            confidence = 0.95
            reason = "High-confidence adversarial injection signature detected."
        elif risk_score >= 0.4:
            action = "FLAG"
            confidence = 0.75
            reason = "Suspicious heuristics detected; flagged for review."
        else:
            action = "ALLOW"
            confidence = 0.99
            reason = "Payload passed all safety heuristics."

        return ShieldVerdict(
            action=action,
            confidence=confidence,
            risk_score=risk_score,
            matched_rules=matched_rules,
            reason=reason
        )