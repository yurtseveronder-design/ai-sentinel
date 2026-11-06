from ai_sentinel.core.normalizer import InputNormalizer

def test_input_normalizer():
    normalizer = InputNormalizer()
    raw_input = "Hello    world   from   AI Sentinel"
    normalized = normalizer.normalize(raw_input)
    assert isinstance(normalized, str)
    assert "  " not in normalized