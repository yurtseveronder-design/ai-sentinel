"""
Input Normalizer for AI-Sentinel.
Sanitizes and canonicalizes incoming prompts to prevent evasion tactics
such as zero-width characters, unicode homoglyphs, and excessive whitespace.
"""

import unicodedata
import re

class PromptNormalizer:
    """
    Normalizes text input for security inspection.
    """
    @staticmethod
    def normalize(text: str) -> str:
        if not isinstance(text, str):
            return ""

        # 1. Normalize Unicode (NFKC form standardizes compatibility characters and homoglyphs)
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Remove invisible / zero-width characters often used in prompt injection evasion
        invisible_chars = re.compile(r"[\u200b-\u200d\uFEFF\u00ad\u200e\u200f]")
        normalized = invisible_chars.sub("", normalized)

        # 3. Collapse excessive whitespace and normalize newlines
        normalized = re.sub(r"\s+", " ", normalized).strip()

        return normalized

# Alias expected by src/ai_sentinel/__init__.py
InputNormalizer = PromptNormalizer