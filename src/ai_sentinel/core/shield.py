from ai_sentinel.core.normalizer import InputNormalizer
from ai_sentinel.core.classifier import SemanticGuardrail

class BioImmuneShield:
    def __init__(self):
        self.normalizer = InputNormalizer()
        self.classifier = SemanticGuardrail()

    def inspect_payload(self, text: str) -> dict:
        cleaned = self.normalizer.clean(text)
        return self.classifier.evaluate(cleaned)
