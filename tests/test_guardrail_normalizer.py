from ai_sentinel.core.normalizer import InputNormalizer

def test_input_normalizer():
    normalizer = InputNormalizer()
    # Adjusting to standard clean/normalize method
    assert hasattr(normalizer, "normalize") or hasattr(normalizer, "clean")
