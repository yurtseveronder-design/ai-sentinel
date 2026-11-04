from sentinel_core.normalizer import InputNormalizer
from sentinel_core.classifier import SemanticGuardrail
from sentinel_core.telemetry import SecureTelemetryLogger

class BioImmuneShield:
    def __init__(self):
        self.normalizer = InputNormalizer()
        self.classifier = SemanticGuardrail()
        self.telemetry = SecureTelemetryLogger()

    def inspect_payload(self, text: str) -> dict:
        cleaned = self.normalizer.clean(text)
        classification = self.classifier.evaluate(cleaned)
        
        status = classification.get("status", "ALLOW")
        confidence = classification.get("confidence", 1.0)
        if status == "BLOCK":
            stance = "Input diverges from established parameters; boundary maintained."
        elif status == "NEUTRAL":
            stance = "Payload neutralized; core integrity preserved."
        else:
            stance = "Harmonious input accepted."
            
        result = {
            "status": status,
            "cleaned": cleaned,
            "confidence": confidence,
            "shield_stance": stance
        }
        self.telemetry.log_event(text, status, confidence)
        return result
