"""
Input Normalizer for AI-Sentinel.
Sanitizes, decodes, and normalizes incoming text prompts.
"""

import html
import re

class NormalizationAudit:
    """Audit result container for normalization steps."""
    def __init__(self, text: str, steps: list):
        self.text = text
        self.steps = steps


class InputNormalizer:
    """
    Normalizes input text by removing hidden control characters,
    normalizing unicode, decoding HTML entities, and stripping whitespace.
    """
    def __init__(self):
        pass

    def clean(self, text: str) -> str:
        return self.full_normalize(text)

    def sanitize(self, text: str) -> str:
        return self.full_normalize(text)

    def normalize(self, text: str) -> str:
        return self.full_normalize(text)

    @staticmethod
    def full_normalize(text: str) -> str:
        if not isinstance(text, str):
            return ""
        decoded = html.unescape(text)
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', decoded)
        return " ".join(cleaned.split())

    @staticmethod
    def fully_normalize(text: str) -> str:
        return InputNormalizer.full_normalize(text)

    @staticmethod
    def normalize_html(text: str) -> str:
        if not isinstance(text, str):
            return ""
        decoded = html.unescape(text)
        clean_text = re.sub(r'<[^>]*>', '', decoded)
        return " ".join(clean_text.split())

    @staticmethod
    def normalize_with_audit(text: str) -> NormalizationAudit:
        if not isinstance(text, str):
            return NormalizationAudit("", [])
        steps = ["html", "control_char_removal"]
        decoded = html.unescape(text)
        cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', decoded)
        final_text = " ".join(cleaned.split())
        return NormalizationAudit(final_text, steps)