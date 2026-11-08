from ai_sentinel.core.normalizer import InputNormalizer

def test_empty():
    assert InputNormalizer.full_normalize("") == ""

def test_html():
    audit = InputNormalizer.normalize_with_audit(chr(38) + "#105;gnore")
    assert audit.text == "ignore"
    assert "html" in audit.steps
