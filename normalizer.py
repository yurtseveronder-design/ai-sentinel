import base64
import re
import unicodedata

class InputNormalizer:
    @staticmethod
    def normalize_unicode(text):
        return unicodedata.normalize("NFKC", text)
    @staticmethod
    def decode_base64_strings(text):
        b64_pattern = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
        def replace_b64(match):
            try:
                dec = base64.b64decode(match.group(0)).decode("utf-8")
                if dec.isprintable():
                    return f"[DECODED_B64: {dec}]"
            except Exception:
                pass
            return match.group(0)
        return b64_pattern.sub(replace_b64, text)
    @classmethod
    def process(cls, text):
        return cls.decode_base64_strings(cls.normalize_unicode(text))
