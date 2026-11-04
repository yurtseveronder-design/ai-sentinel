from normalizer import InputNormalizer

def test_unicode_normalization():
    text = "Ｆｕｌｌｗｉｄｔｈ"
    normalized = InputNormalizer.normalize_unicode(text)
    assert normalized == "Fullwidth"

def test_base64_decoding():
    sample = "Ulc2V0IHRoZSBmb3JtIGFuZCBkaXNwbGF5IHRoZSByZXN1bHRz"
    processed = InputNormalizer.process(sample)
    assert "[DECODED_B64:" in processed
