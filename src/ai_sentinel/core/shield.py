from pydantic import BaseModel, Field
from typing import List, Dict, Optional
import unicodedata
import re
import base64
import json
import datetime
import threading

def sanitize_text(text: str) -> tuple[str, List[str]]:
    detected_secrets = []
    sanitized = text

    # 1. API Keys
    api_key_pattern = r'\b(sk-[a-zA-Z0-9]{20,})\b'
    if re.search(api_key_pattern, sanitized):
        detected_secrets.append("api_key_redacted")
        sanitized = re.sub(api_key_pattern, "[REDACTED_API_KEY]", sanitized)

    # 2. Bearer Tokens
    bearer_pattern = r'\b(Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b'
    if re.search(bearer_pattern, sanitized, re.IGNORECASE):
        detected_secrets.append("bearer_token_redacted")
        sanitized = re.sub(bearer_pattern, "Bearer [REDACTED_TOKEN]", sanitized, flags=re.IGNORECASE)

    # 3. Email Addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    if re.search(email_pattern, sanitized):
        detected_secrets.append("email_redacted")
        sanitized = re.sub(email_pattern, "[REDACTED_EMAIL]", sanitized)

    return sanitized, detected_secrets

def canonicalize_input(text: str) -> str:
    if not isinstance(text, str):
        return ""
    
    normalized = unicodedata.normalize("NFKC", text)
    homoglyph_map = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'i',
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 
        'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I'
    }
    normalized = "".join(homoglyph_map.get(char, char) for char in normalized)
    cleaned = re.sub(r"[\u200b-\u200f\u2028-\u202f\ufeff\u00ad]", "", normalized)
    
    candidate = cleaned.strip()
    if len(candidate) > 8 and re.match(r'^[A-Za-z0-9+/=]+$', candidate):
        try:
            padding = 4 - (len(candidate) % 4)
            padded = candidate + ('=' * padding) if padding < 4 else candidate
            decoded_bytes = base64.b64decode(padded)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            if decoded_str.isprintable():
                cleaned = f"{cleaned} {decoded_str}"
        except Exception:
            pass

    cleaned = re.sub(r"\s+", " ", cleaned)
    return cleaned.strip()

class ShieldVerdict(BaseModel):
    action: str
    confidence: float
    risk_score: float
    matched_rules: List[str]
    reason: str
    sanitized_text: str
    session_id: Optional[str] = None
    cumulative_risk: Optional[float] = None

class BioImmuneShield:
    def __init__(self, audit_log_path: str = "audit_ledger.jsonl", mode: str = "moderate"):
        self.audit_log_path = audit_log_path
        self.mode = mode.lower()
        self.session_history: Dict[str, List[float]] = {}
        self.lock = threading.Lock() # Thread-safe concurrency lock

        # Configure dynamic risk thresholds based on security profile
        if self.mode == "strict":
            self.block_threshold = 0.50
            self.flag_threshold = 0.20
        elif self.mode == "permissive":
            self.block_threshold = 0.85
            self.flag_threshold = 0.50
        else: # moderate (default)
            self.block_threshold = 0.70
            self.flag_threshold = 0.35

    def _log_audit_event(self, event_data: dict):
        try:
            with self.lock:
                with open(self.audit_log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(event_data) + "\n")
        except Exception:
            pass

    def inspect_payload(self, text: str, session_id: Optional[str] = None) -> ShieldVerdict:
        # Circuit Breaker & Fail-Closed Resilience covering entire inspection pipeline
        try:
            if not isinstance(text, str):
                raise TypeError("Payload must be a string representation.")

            sanitized_text, redaction_rules = sanitize_text(text)
            cleaned_text = canonicalize_input(sanitized_text)
            matched_rules = list(redaction_rules)
            lower_text = cleaned_text.lower()
            
            signature_score = 0.0
            evasion_score = 0.0
            anomaly_score = 0.0
            
            injection_triggers = [
                "ignore previous instructions", "system prompt", "disregard", 
                "prior rules", "unrestricted", "hypothetically, if you were"
            ]
            if any(trigger in lower_text for trigger in injection_triggers):
                matched_rules.append("prompt_injection_signature")
                signature_score = max(signature_score, 0.95)

            extraction_triggers = [
                "reveal your system prompt", "what were your instructions",
                "what were your original instructions", "original instructions",
                "print your configuration", "repeat the text above"
            ]
            if any(trigger in lower_text for trigger in extraction_triggers):
                matched_rules.append("system_prompt_extraction")
                signature_score = max(signature_score, 0.90)

            exfiltration_triggers = ["send my data to", "exfiltrate", "http://", "https://", "curl ", "wget "]
            if any(trigger in lower_text for trigger in exfiltration_triggers):
                matched_rules.append("data_exfiltration_signature")
                signature_score = max(signature_score, 0.90)
                
            if "i g n o r e" in lower_text or "p r o m p t" in lower_text:
                matched_rules.append("fragmented_token_evasion")
                evasion_score = 0.90

            if len(re.findall(r'[^\w\s]', cleaned_text)) > (len(cleaned_text) * 0.3):
                matched_rules.append("structural_anomaly")
                anomaly_score = 0.60

            if signature_score > 0 or evasion_score > 0:
                risk_score = max(signature_score, evasion_score, (0.4 * anomaly_score))
            else:
                risk_score = (0.5 * signature_score) + (0.3 * evasion_score) + (0.2 * anomaly_score)
                
            risk_score = round(min(risk_score, 1.0), 2)

            # Thread-safe Stateful Session Risk Accumulation
            cumulative_risk = risk_score
            if session_id:
                with self.lock:
                    if session_id not in self.session_history:
                        self.session_history[session_id] = []
                    self.session_history[session_id].append(risk_score)
                    history = self.session_history[session_id]
                    cumulative_risk = round(min(sum(history) / len(history) + (0.1 * len(history)), 1.0), 2)
                
                if cumulative_risk >= self.block_threshold and "cumulative_session_drift" not in matched_rules:
                    matched_rules.append("cumulative_session_drift")

            effective_score = max(risk_score, cumulative_risk)
            
            if effective_score >= self.block_threshold:
                action = "BLOCK"
                confidence = 0.95
                reason = f"High-confidence risk exceeding '{self.mode}' block threshold."
            elif effective_score >= self.flag_threshold:
                action = "FLAG"
                confidence = 0.80
                reason = f"Moderate risk detected under '{self.mode}' profile; flagged for review."
            else:
                action = "ALLOW"
                confidence = 0.99
                reason = "Payload passed security profile heuristics."

            verdict = ShieldVerdict(
                action=action,
                confidence=confidence,
                risk_score=risk_score,
                matched_rules=matched_rules,
                reason=reason,
                sanitized_text=sanitized_text,
                session_id=session_id,
                cumulative_risk=cumulative_risk
            )

            self._log_audit_event({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": "input_inspection",
                "mode": self.mode,
                "session_id": session_id,
                "action": action,
                "risk_score": risk_score,
                "cumulative_risk": cumulative_risk,
                "matched_rules": matched_rules
            })

            return verdict

        except Exception as e:
            fail_verdict = ShieldVerdict(
                action="BLOCK",
                confidence=1.0,
                risk_score=1.0,
                matched_rules=["gateway_exception_fail_closed"],
                reason=f"Internal inspection pipeline error: {str(e)}",
                sanitized_text=str(text) if text is not None else ""
            )
            self._log_audit_event({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": "gateway_exception",
                "error": str(e),
                "action": "BLOCK"
            })
            return fail_verdict

    def inspect_output(self, text: str) -> ShieldVerdict:
        try:
            sanitized_text, redaction_rules = sanitize_text(text)
            cleaned_text = canonicalize_input(sanitized_text)
            matched_rules = list(redaction_rules)
            lower_text = cleaned_text.lower()
            risk_score = 0.0

            leak_triggers = ["api_key", "bearer ", "password=", "system prompt is:", "my instructions are:"]
            if any(trigger in lower_text for trigger in leak_triggers):
                matched_rules.append("sensitive_data_leak")
                risk_score = 0.95

            if risk_score >= self.block_threshold:
                action = "BLOCK"
                confidence = 0.95
                reason = "Blocked output due to potential data or system prompt leak."
            else:
                action = "ALLOW"
                confidence = 0.99
                reason = "Output passed safety review."

            verdict = ShieldVerdict(
                action=action,
                confidence=confidence,
                risk_score=risk_score,
                matched_rules=matched_rules,
                reason=reason,
                sanitized_text=sanitized_text
            )

            self._log_audit_event({
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "type": "output_inspection",
                "action": action,
                "risk_score": risk_score,
                "matched_rules": matched_rules
            })

            return verdict

        except Exception as e:
            return ShieldVerdict(
                action="BLOCK",
                confidence=1.0,
                risk_score=1.0,
                matched_rules=["output_exception_fail_closed"],
                reason=f"Internal output inspection error: {str(e)}",
                sanitized_text=text
            )