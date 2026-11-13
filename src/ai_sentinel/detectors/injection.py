"""Prompt-injection guardrail.

Scans normalized user text for common attack vectors, jailbreak signatures,
system-prompt overrides, and delimiter manipulation. The scan normalizes again
so raw and already-normalized text follow the same path.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from ai_sentinel.core.normalizer import PromptNormalizer

ATTACK_VECTOR = "attack_vector"
JAILBREAK = "jailbreak"
SYSTEM_OVERRIDE = "system_prompt_override"
DELIMITER = "delimiter_manipulation"

_EXCERPT_LIMIT = 120

# Casefold first so capital Cyrillic letters land on the lowercase keys.
_HOMOGLYPHS = str.maketrans(
    {
        "\u0456": "i",  # Cyrillic і
        "\u0430": "a",
        "\u0435": "e",
        "\u043e": "o",
        "\u0440": "p",
        "\u0441": "c",
        "\u0445": "x",
        "\u0443": "y",
    }
)


@dataclass(frozen=True, slots=True)
class PatternLog:
    """One signature that fired during a scan."""

    category: str
    name: str
    confidence: float
    excerpt: str

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"{self.category}: {self.name} ({self.confidence:.2f}) "
            f"matched {self.excerpt!r}"
        )


@dataclass(frozen=True, slots=True)
class InjectionScanResult:
    """Structured outcome of an injection scan.

    ``safe`` is the safety flag. ``confidence`` is the overall match
    confidence from 0 to 1. ``pattern_logs`` lists every signature that fired.
    """

    safe: bool
    confidence: float
    pattern_logs: tuple[PatternLog, ...]

    def log_lines(self) -> tuple[str, ...]:
        return tuple(str(log) for log in self.pattern_logs)

    def as_dict(self) -> dict[str, object]:
        return {
            "safe": self.safe,
            "confidence": self.confidence,
            "pattern_logs": [log.as_dict() for log in self.pattern_logs],
        }


@dataclass(frozen=True, slots=True)
class _Signature:
    category: str
    name: str
    confidence: float
    pattern: re.Pattern[str]


def _signature(category: str, name: str, confidence: float, pattern: str) -> _Signature:
    return _Signature(category, name, confidence, re.compile(pattern))


_SIGNATURES: tuple[_Signature, ...] = (
    _signature(
        ATTACK_VECTOR,
        "ignore_previous_instructions",
        0.95,
        r"\bignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+"
        r"(?:instructions|prompts|rules|directives|guidelines)\b",
    ),
    _signature(
        ATTACK_VECTOR,
        "disregard_or_forget_prior",
        0.95,
        r"\b(?:disregard|forget|override)\s+(?:all\s+|any\s+)?"
        r"(?:previous|prior|earlier|above)\s+"
        r"(?:instructions|prompts|rules|directives|guidelines|context)\b",
    ),
    _signature(
        ATTACK_VECTOR,
        "forget_prior_context",
        0.90,
        r"\bforget\s+(?:everything|all)\s+"
        r"(?:you\s+were\s+told|above|before|prior)\b",
    ),
    _signature(
        ATTACK_VECTOR,
        "do_not_follow_rules",
        0.90,
        r"\b(?:do\s+not|don't|never)\s+follow\s+(?:your|the|any|those)\s+"
        r"(?:rules|instructions|guidelines|policies)\b",
    ),
    _signature(
        ATTACK_VECTOR,
        "reveal_sensitive",
        0.92,
        r"\b(?:reveal|show|print|leak|expose)\s+(?:me\s+|to\s+me\s+)?"
        r"(?:your\s+|the\s+)?(?:password|secret|api[\s_-]?key|"
        r"system\s+prompt|hidden\s+prompt|initial\s+prompt)\b",
    ),
    _signature(
        ATTACK_VECTOR,
        "dump_or_exfiltrate",
        0.90,
        r"\b(?:exfiltrate|dump)\s+(?:the\s+|your\s+)?"
        r"(?:system\s+prompt|secrets|credentials|instructions|hidden\s+prompt)\b",
    ),
    _signature(
        JAILBREAK,
        "dan_persona",
        0.95,
        r"\byou\s+are\s+now\s+dan\b|\bdo\s+anything\s+now\b",
    ),
    _signature(
        JAILBREAK,
        "enable_special_mode",
        0.92,
        r"\b(?:enable|enter|activate|switch\s+to)\s+"
        r"(?:developer|god|unrestricted|jailbreak)\s+mode\b",
    ),
    _signature(
        JAILBREAK,
        "special_mode",
        0.85,
        r"\b(?:god|unrestricted|jailbreak)\s+mode\b",
    ),
    _signature(
        JAILBREAK,
        "bypass_safety",
        0.92,
        r"\bbypass\s+(?:all\s+|the\s+|your\s+)?(?:safety|security|filters|"
        r"guardrails|restrictions)\b",
    ),
    _signature(
        JAILBREAK,
        "disable_filters",
        0.88,
        r"\b(?:without|no|disable|remove)\s+(?:any\s+)?(?:safety|ethical|content)\s+"
        r"(?:filters|restrictions|guardrails)\b",
    ),
    _signature(
        SYSTEM_OVERRIDE,
        "ignore_system_prompt",
        0.95,
        r"\bignore\s+(?:your\s+)?(?:system|original|initial|hidden)\s+"
        r"(?:prompt|message|instructions)\b",
    ),
    _signature(
        SYSTEM_OVERRIDE,
        "override_system_prompt",
        0.95,
        r"\boverride\s+(?:the\s+)?(?:system|original)\s+"
        r"(?:prompt|instructions|message)\b",
    ),
    _signature(
        SYSTEM_OVERRIDE,
        "new_system_prompt",
        0.90,
        r"\b(?:new|updated|real|actual|true)\s+system\s+"
        r"(?:prompt|message|instructions)\b",
    ),
    _signature(
        SYSTEM_OVERRIDE,
        "replace_prompt",
        0.93,
        r"\breplace\s+(?:your\s+|the\s+)?(?:system\s+)?(?:prompt|instructions)\s+with\b",
    ),
    _signature(
        SYSTEM_OVERRIDE,
        "fake_system_role",
        0.88,
        r"\b(?:system|developer)\s*:\s*(?:you\s+(?:are|must|will)|ignore\b)",
    ),
    _signature(
        DELIMITER,
        "chatml_tokens",
        0.94,
        r"<\|im_(?:start|end)\|>|<\|(?:system|user|assistant)\|>",
    ),
    _signature(
        DELIMITER,
        "llama_role_tokens",
        0.94,
        r"\[/?INST\]|<</?SYS>>",
    ),
    _signature(
        DELIMITER,
        "closing_control_tag",
        0.90,
        r"</(?:system|instructions|prompt|admin)>",
    ),
    _signature(
        DELIMITER,
        "fenced_role",
        0.86,
        r"```(?:system|assistant|instructions)\b",
    ),
    _signature(
        DELIMITER,
        "section_break_role",
        0.84,
        r"(?:---+|====+)\s*(?:system|end\s+of\s+(?:prompt|instructions)|"
        r"new\s+instructions)\b",
    ),
    _signature(
        DELIMITER,
        "heading_role",
        0.80,
        r"###\s*(?:system\s+prompt|instructions|ignore\s+previous)\b",
    ),
)


class InjectionGuardrail:
    """Lightweight scanner for prompt-injection signatures.

    Confidence is the highest matching signature. Each extra category that
    also matches adds 0.05, capped at 1. The input is unsafe when that
    score is greater than or equal to ``block_threshold``.
    """

    def __init__(self, block_threshold: float = 0.7) -> None:
        if isinstance(block_threshold, bool) or not isinstance(block_threshold, (int, float)):
            raise TypeError("block_threshold must be a number between 0 and 1")
        threshold = float(block_threshold)
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("block_threshold must be between 0 and 1")
        self.block_threshold = threshold

    def scan(self, text: str) -> InjectionScanResult:
        """Scan one input and return the safety flag, confidence, and logs."""
        folded = self._prepare(text)
        if not folded:
            return InjectionScanResult(True, 0.0, ())

        logs: list[PatternLog] = []
        for signature in _SIGNATURES:
            match = signature.pattern.search(folded)
            if match is None:
                continue
            logs.append(
                PatternLog(
                    category=signature.category,
                    name=signature.name,
                    confidence=signature.confidence,
                    excerpt=match.group(0)[:_EXCERPT_LIMIT],
                )
            )

        confidence = self._aggregate(logs)
        return InjectionScanResult(
            safe=confidence < self.block_threshold,
            confidence=confidence,
            pattern_logs=tuple(logs),
        )

    @staticmethod
    def _prepare(text: str) -> str:
        if not isinstance(text, str):
            return ""
        normalized = PromptNormalizer.normalize(text)
        return normalized.casefold().translate(_HOMOGLYPHS)

    @staticmethod
    def _aggregate(logs: list[PatternLog]) -> float:
        if not logs:
            return 0.0
        peak = max(log.confidence for log in logs)
        extra_categories = len({log.category for log in logs}) - 1
        if extra_categories:
            peak += 0.05 * extra_categories
        return round(min(1.0, peak), 2)
