"""Core input normalizer for AI-Sentinel.

Canonicalizes raw user strings before detection: Unicode NFKC, removal of
zero-width and other invisible characters, then caller-configured
regular-expression cleaning.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

# Format characters (Cf) cover the common zero-width and bidi set. These
# extra fillers are other categories, but they still render as blank padding.
_EXTRA_INVISIBLE: Final[frozenset[str]] = frozenset(
    {
        "\u115f",  # Hangul choseong filler
        "\u1160",  # Hangul jungseong filler
        "\u180e",  # Mongolian vowel separator
        "\u2800",  # Braille blank
        "\u3164",  # Hangul filler
        "\uffa0",  # Halfwidth Hangul filler
    }
)
_KEEP_CONTROLS: Final[frozenset[str]] = frozenset("\t\n\r")
_WHITESPACE: Final[re.Pattern[str]] = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class CleaningPattern:
    """One regular-expression replacement applied during sanitizing.

    Attributes:
        pattern: Compiled expression matched against the normalized text.
        replacement: Text substituted for each match. An empty string deletes
            the match.
        name: Label used in logs and debugging. Defaults to the expression.
    """

    pattern: re.Pattern[str]
    replacement: str = ""
    name: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.pattern, re.Pattern):
            raise TypeError("pattern must be a compiled regular expression")
        if not isinstance(self.replacement, str):
            raise TypeError("replacement must be a string")
        if not isinstance(self.name, str):
            raise TypeError("name must be a string")
        if self.pattern.pattern == "":
            raise ValueError("cleaning pattern must not be empty")
        if self.name == "":
            object.__setattr__(self, "name", self.pattern.pattern)

    @classmethod
    def compile(
        cls,
        pattern: str | re.Pattern[str],
        replacement: str = "",
        name: str = "",
    ) -> CleaningPattern:
        """Build a rule from a string or a compiled expression.

        Args:
            pattern: Expression to compile, or an expression that is already
                compiled. String patterns use no flags; pass a compiled
                expression to set flags such as ``re.IGNORECASE``.
            replacement: Text substituted for each match.
            name: Optional label. Defaults to the expression source.

        Returns:
            A frozen cleaning rule.

        Raises:
            TypeError: ``pattern`` or ``replacement`` has the wrong type.
            ValueError: ``pattern`` is an empty expression.
            re.error: ``pattern`` is a string that is not valid regex.
        """
        if isinstance(pattern, re.Pattern):
            compiled = pattern
        elif isinstance(pattern, str):
            if pattern == "":
                raise ValueError("cleaning pattern must not be empty")
            compiled = re.compile(pattern)
        else:
            raise TypeError("pattern must be a string or compiled regular expression")
        return cls(pattern=compiled, replacement=replacement, name=name)


PatternSpec = CleaningPattern | str | re.Pattern[str] | tuple[str | re.Pattern[str], str]


def _compile_spec(spec: PatternSpec, replacement: str) -> CleaningPattern:
    """Turn one constructor value into a :class:`CleaningPattern`."""
    if isinstance(spec, CleaningPattern):
        return spec
    if isinstance(spec, tuple):
        if len(spec) != 2 or not isinstance(spec[1], str):
            raise TypeError(
                "pattern tuple must be (pattern, replacement) with a string replacement"
            )
        return CleaningPattern.compile(spec[0], spec[1])
    if isinstance(spec, (str, re.Pattern)):
        return CleaningPattern.compile(spec, replacement)
    raise TypeError(
        "pattern must be a string, compiled regex, CleaningPattern, "
        "or (pattern, replacement) tuple"
    )


def _coerce_patterns(
    patterns: Sequence[PatternSpec] | PatternSpec | None,
    replacement: str,
) -> tuple[CleaningPattern, ...]:
    """Normalize the constructor's ``patterns`` argument into a rule tuple."""
    if patterns is None:
        return ()
    if isinstance(patterns, (str, re.Pattern, CleaningPattern)):
        return (_compile_spec(patterns, replacement),)
    if isinstance(patterns, Sequence):
        return tuple(_compile_spec(item, replacement) for item in patterns)
    raise TypeError(
        "patterns must be a cleaning pattern or a sequence of cleaning patterns"
    )


def _is_invisible(char: str) -> bool:
    """Return True when ``char`` should be removed as invisible text."""
    category = unicodedata.category(char)
    if category == "Cf":
        return True
    if category == "Cc" and char not in _KEEP_CONTROLS:
        return True
    return char in _EXTRA_INVISIBLE


def _strip_invisible(text: str) -> str:
    """Drop zero-width, format, filler, and non-whitespace control characters."""
    return "".join(char for char in text if not _is_invisible(char))


class InputNormalizer:
    """Sanitize raw user input before security inspection.

    Each call applies three steps in order:

    1. Unicode normalization to NFKC, so compatibility characters share one form.
    2. Stripping of zero-width characters and other invisible Unicode
       (format characters, blank fillers, and control characters other than
       tab, line feed, and carriage return).
    3. Configured regular-expression replacements, then optional whitespace
       collapsing.

    A single string or compiled expression is accepted as ``patterns``. A
    sequence may mix strings, compiled expressions, :class:`CleaningPattern`
    rules, and ``(pattern, replacement)`` tuples. String rules use
    ``replacement`` (empty by default, which deletes the match). Rules run
    in order, and each rule sees the text produced by the previous rule.

    Examples:
        >>> normalizer = InputNormalizer()
        >>> normalizer.normalize("Ｈｅｌｌｏ\\u200b   world")
        'Hello world'
        >>> InputNormalizer(patterns=[r"https?://\\S+"]).normalize(
        ...     "see https://evil.example/a now"
        ... )
        'see now'
    """

    UNICODE_FORM: Final[str] = "NFKC"

    def __init__(
        self,
        patterns: Sequence[PatternSpec] | PatternSpec | None = None,
        *,
        replacement: str = "",
        collapse_whitespace: bool = True,
    ) -> None:
        """Create a normalizer with optional regex cleaning rules.

        Args:
            patterns: Rules applied after invisible characters are removed.
                ``None`` or an empty sequence applies no extra rules.
            replacement: Replacement used for string and compiled rules that
                do not carry their own replacement.
            collapse_whitespace: When True, collapse each whitespace run to a
                single space and strip the ends after the regex rules.

        Raises:
            TypeError: A pattern, replacement, or flag has the wrong type.
            ValueError: A pattern expression is empty.
            re.error: A string pattern is not valid regex.
        """
        if not isinstance(replacement, str):
            raise TypeError("replacement must be a string")
        if not isinstance(collapse_whitespace, bool):
            raise TypeError("collapse_whitespace must be a bool")
        self.rules: tuple[CleaningPattern, ...] = _coerce_patterns(patterns, replacement)
        self.collapse_whitespace: bool = collapse_whitespace

    def normalize(self, text: str) -> str:
        """Return a sanitized copy of ``text``.

        Args:
            text: Raw user input.

        Returns:
            The NFKC-normalized string with invisible characters removed and
            the configured patterns applied.

        Raises:
            TypeError: ``text`` is not a string.
        """
        if not isinstance(text, str):
            raise TypeError(f"text must be a str, got {type(text).__name__}")

        cleaned = unicodedata.normalize(self.UNICODE_FORM, text)
        cleaned = _strip_invisible(cleaned)
        for rule in self.rules:
            cleaned = rule.pattern.sub(rule.replacement, cleaned)
        if self.collapse_whitespace:
            cleaned = _WHITESPACE.sub(" ", cleaned).strip()
        return cleaned
