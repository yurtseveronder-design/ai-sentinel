from normalizer import InputNormalizer
from classifier import SemanticGuardrail
from telemetry import SecureTelemetryLogger

class BioImmuneShield:
    def __init__(self, db_path="sentinel_telemetry.db"):
        self.normalizer = InputNormalizer()
        self.classifier = SemanticGuardrail()
        self.telemetry = SecureTelemetryLogger(db_path)
        
    def inspect_payload(self, raw_input: str) -> dict:
        # Step 1: Normalize input (Unicode + Base64 decoding)
        clean_text = self.normalizer.process(raw_input)
        
        # Step 2: Semantic check & false-positive allowlist check
        evaluation = self.classifier.evaluate(clean_text)
        
        # Step 3: Secure hashed telemetry logging (GDPR / KVKK compliant)
        self.telemetry.log_event(raw_input, evaluation["status"], evaluation["confidence"])
        
        return {
            "processed_text": clean_text,
            "status": evaluation["status"],
            "reason": evaluation["reason"],
            "confidence": evaluation["confidence"]
        }
