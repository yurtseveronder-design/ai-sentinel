"""Input normalizers.

Canonicalizes prompts before detection so compatibility characters,
zero-width characters, and irregular whitespace cannot hide intent.
"""

from ai_sentinel.core.normalizer import PromptNormalizer
from ai_sentinel.normalizers.base import CleaningPattern, InputNormalizer

__all__ = ["CleaningPattern", "InputNormalizer", "PromptNormalizer"]
