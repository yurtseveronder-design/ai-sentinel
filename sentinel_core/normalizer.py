import unicodedata
import base64
import re

class InputNormalizer:
    def __init__(self):
        pass
    def normalize_unicode(self, text: str) -> str:
        return unicodedata.normalize("NFKC", text)
    def decode_obfuscation(self, text: str) -> str:
        cleaned = text.strip()
        base64_pattern = re.compile(r"[A-Za-z0-9+/]+={0,2}$")
        for _ in range(2):
            if len(cleaned) % 4 == 0 and base64_pattern.match(cleaned):
                try:
                    decoded_bytes = base64.b64decode(cleaned, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8")
                    if decoded_str.isprintable():
                        cleaned = decoded_str
                        continue
                except Exception:
                    break
            break
        return cleaned
    def process(self, text: str) -> str:
        return self.decode_obfuscation(self.normalize_unicode(text))
