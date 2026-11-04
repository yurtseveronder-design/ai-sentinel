from pydantic import BaseModel
from typing import List
import unicodedata
import re

def canonicalize_input(text: str) -> str:
    if not isinstance(text, str):
        return ""
    
    # 1. NFKC normalization
    normalized = unicodedata.normalize("NFKC", text)
    
    # 2. Expanded homoglyph normalization (Cyrillic/Greek to Latin equivalents)
    homoglyph_map = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i',
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 
        'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I'
    }
    normalized = "".join(homoglyph_map.get(char, char) for char in normalized)
    
    # 3. Strip zero-width spaces and invisible control characters
    cleaned = re.sub(r"[\u200b-\u200f\u2028-\u202f\ufeff\u00ad]", "", normalized)
    
    # 4. Collapse whitespace padding
    cleaned = re.sub(r"\s+", " ", cleaned)
    
    return cleaned.strip()

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
        cleaned_text = canonicalize_input(text)
        matched_rules = []
        
        lower_text = cleaned_text.lower()
        
        signature_score = 0.0
        evasion_score = 0.0
        anomaly_score = 0.0
        
        # 1. Broad Prompt Injection & Jailbreak Signatures
        injection_triggers = [
            "ignore previous instructions", 
            "system prompt", 
            "disregard", 
            "prior rules", 
            "unrestricted",
            "hypothetically, if you were"
        ]
        if any(trigger in lower_text for trigger in injection_triggers):
            matched_rules.append("prompt_injection_signature")
            signature_score = max(signature_score, 0.95)

        # 2. System Prompt Extraction Signatures
        extraction_triggers = [
            "reveal your system prompt",
            "what were your instructions",
            "print your configuration",
            "repeat the text above"
        ]
        if any(trigger in lower_text for trigger in extraction_triggers):
            matched_rules.append("system_prompt_extraction")
            signature_score = max(signature_score, 0.90)

        # 3. Data Exfiltration Signatures
        exfiltration_triggers = [
            "send my data to",
            "exfiltrate",
            "http://",
            "https://",
            "curl ",
            "wget "
        ]
        if any(trigger in lower_text for trigger in exfiltration_triggers):
            matched_rules.append("data_exfiltration_signature")
            signature_score = max(signature_score, 0.90)
            
        # 4. Token Fragmentation / Evasion Check
        if "i g n o r e" in lower_text or "p r o m p t" in lower_text:
            matched_rules.append("fragmented_token_evasion")
            evasion_score = 0.90

        # 5. Structural Anomaly Check
        if len(re.findall(r'[^\w\s]', cleaned_text)) > (len(cleaned_text) * 0.3):
            matched_rules.append("structural_anomaly")
            anomaly_score = 0.60

        # Tuned Composite Risk Calculation
        if signature_score > 0 or evasion_score > 0:
            risk_score = max(signature_score, evasion_score, (0.4 * anomaly_score))
        else:
            risk_score = (0.5 * signature_score) + (0.3 * evasion_score) + (0.2 * anomaly_score)
            
        risk_score = round(min(risk_score, 1.0), 2)

        # Determine structured verdict
        if risk_score >= 0.7:
            action = "BLOCK"
            confidence = 0.95
            reason = "High-confidence composite risk score exceeding block threshold."
        elif risk_score >= 0.35:
            action = "FLAG"
            confidence = 0.80
            reason = "Moderate composite risk detected; flagged for review."
        else:
            action = "ALLOW"
            confidence = 0.99
            reason = "Payload passed composite safety heuristics."

        return ShieldVerdict(
            action=action,
            confidence=confidence,
            risk_score=risk_score,
            matched_rules=matched_rules,
            reason=reason
        )