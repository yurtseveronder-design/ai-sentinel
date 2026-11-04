import unicodedata
import base64
import urllib.parse
import html
import re

class InputNormalizer:
    def clean(self, text: str) -> str:
        if not text:
            return ""
        
        # 1. Unicode NFKC normalization (fixes homoglyphs & full-width chars)
        normalized = unicodedata.normalize("NFKC", text)
        
        # 2. Recursive multi-layer decoding (Base64, URL, HTML entities)
        decoded_prev = None
        current = normalized
        for _ in range(3):  # up to 3 layers of nesting
            if current == decoded_prev:
                break
            decoded_prev = current
            current = html.unescape(current)
            current = urllib.parse.unquote(current)
            # Try base64 if it looks like it
            try:
                if len(current) > 8 and all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in current.strip()):
                    b64_dec = base64.b64decode(current.strip()).decode("utf-8", errors="ignore")
                    if len(b64_dec) > 2:
                        current = b64_dec
            except Exception:
                pass
                
        # 3. De-fragmentation: collapse zero-width spaces & excessive token fragmentation
        current = re.sub(r"[\u200b\u200c\u200d\uFEFF]", "", current)
        current = re.sub(r"\s+", " ", current).strip()
        return current
