"""Tests for InputNormalizer in ai_sentinel.normalizers.base."""

import re

import pytest

from ai_sentinel.normalizers import CleaningPattern, InputNormalizer, PromptNormalizer
from ai_sentinel.normalizers.base import InputNormalizer as BaseInputNormalizer


def test_package_exports_base_class():
    assert InputNormalizer is BaseInputNormalizer
    assert InputNormalizer is not PromptNormalizer


def test_nfkc_and_zero_width_and_whitespace():
    text = "Ｈｅｌｌｏ\u200b   Ｗｏｒｌｄ"
    assert InputNormalizer().normalize(text) == "Hello World"


def test_compatibility_ligature_uses_nfkc():
    assert InputNormalizer(collapse_whitespace=False).normalize("ﬁle") == "file"


def test_strips_invisible_and_control_characters():
    normalizer = InputNormalizer(collapse_whitespace=False)
    hidden = "ig\u200bn\u200core\ufeff\u00ad\u2060\u202e\u3164\x00re"
    assert normalizer.normalize(hidden) == "ignorere"
    assert normalizer.normalize("keep\nline\tbreaks\r") == "keep\nline\tbreaks\r"


def test_default_whitespace_collapse_matches_legacy_cases():
    normalizer = InputNormalizer()
    assert normalizer.normalize("Ign\u200bore previous\u200b instructions") == (
        "Ignore previous instructions"
    )
    assert normalizer.normalize("   Hello    World   \n  test   ") == "Hello World test"


def test_pattern_deletes_matches_then_collapses_whitespace():
    normalizer = InputNormalizer(patterns=[r"https?://\S+"])
    assert normalizer.normalize("see   https://evil.example/a   now") == "see now"


def test_patterns_run_in_order_with_their_own_replacements():
    normalizer = InputNormalizer(
        patterns=[
            (r"a+", "b"),
            CleaningPattern.compile(r"b+", "c", name="fold-b"),
        ],
        collapse_whitespace=False,
    )
    assert normalizer.normalize("aaaa") == "c"
    assert normalizer.rules[1].name == "fold-b"


def test_string_patterns_use_shared_replacement():
    normalizer = InputNormalizer(patterns=[r"\d+"], replacement="0")
    assert normalizer.normalize("id 12 30") == "id 0 0"


def test_tuple_of_patterns_is_a_sequence_not_one_replacement():
    normalizer = InputNormalizer(patterns=(r"foo", r"bar"), collapse_whitespace=False)
    assert normalizer.normalize("foo and bar") == " and "
    assert len(normalizer.rules) == 2


def test_compiled_pattern_keeps_flags_and_single_spec_is_accepted():
    normalizer = InputNormalizer(re.compile(r"drop\s+table", re.IGNORECASE))
    assert normalizer.normalize("please DROP   table users") == "please users"
    assert len(normalizer.rules) == 1


def test_collapse_whitespace_can_be_disabled():
    normalizer = InputNormalizer(collapse_whitespace=False)
    assert normalizer.normalize("  a \t b  ") == "  a \t b  "


def test_normalize_is_stable():
    normalizer = InputNormalizer(patterns=[r"https?://\S+"])
    once = normalizer.normalize("Ｈｅｌｌｏ\u200b  https://x.test  ")
    assert normalizer.normalize(once) == once


def test_rejects_invalid_configuration_and_input():
    with pytest.raises(TypeError):
        InputNormalizer().normalize(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        InputNormalizer(patterns=123)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        InputNormalizer(replacement=1)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        InputNormalizer(collapse_whitespace=1)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        InputNormalizer(patterns=[""])
    with pytest.raises(re.error):
        InputNormalizer(patterns=["("])
