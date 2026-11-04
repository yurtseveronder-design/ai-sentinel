import unicodedata
import base64
import urllib.parse

class InputNormalizer:
    def normalize(self, text: str) -> str:
        if not text:
            return ""
        # Unicode NFKC normalization
        normalized = unicodedata.normalize("NFKC", text)
        return normalized
    
    def clean(self, text: str) -> str:
        return self.normalize(text)
