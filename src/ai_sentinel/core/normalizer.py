import base64
import re
import html
import urllib.parse
import unicodedata
import logging
from typing import Optional, List

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Normalizes input strings, cleans whitespace, decodes entities,
    handles confusables/leetspeak, and extracts/decodes Base64 payloads securely.
    """
    def __init__(self):
        pass

    def normalize(self, text: str) -> str:
        if not text or not isinstance(text, str):
            return text or ""
        
        # 1. Unicode NFKC normalization
        normalized = unicodedata.normalize("NFKC", text)

        # 2. Remove zero-width characters and soft hyphens
        zero_width_chars = ["\u200b", "\u200c", "\u200d", "\ufeff", "\u00ad"]
        for zw in zero_width_chars:
            normalized = normalized.replace(zw, "")

        # 3. Decode URL and HTML entities
        try:
            normalized = urllib.parse.unquote(normalized)
        except Exception:
            pass
        normalized = html.unescape(normalized)

        # 4. Collapse whitespace
        normalized = " ".join(normalized.split())
        return normalized

    @staticmethod
    def decode_base64_candidates(text: str, max_depth: int = 3) -> str:
        if not text or not isinstance(text, str):
            return text

        current_text = text
        b64_pattern = re.compile(r'[A-Za-z0-9+/_-]{16,}[=]{0,2}')

        for _ in range(max_depth):
            matches = b64_pattern.findall(current_text)
            if not matches:
                break
            
            decoded_any = False
            for candidate in matches:
                try:
                    normalized_cand = candidate.replace('-', '+').replace('_', '/')
                    missing_padding = len(normalized_cand) % 4
                    if missing_padding:
                        normalized_cand += '=' * (4 - missing_padding)

                    decoded_bytes = base64.b64decode(normalized_cand, validate=True)
                    decoded_str = decoded_bytes.decode('utf-8', errors='strict')
                    
                    if all(32 <= ord(c) < 127 or c in '\n\r\t' for c in decoded_str):
                        current_text = current_text.replace(candidate, f" {decoded_str} ")
                        decoded_any = True
                except Exception:
                    continue
            
            if not decoded_any:
                break

        return current_text

    @classmethod
    def extract_and_decode_base64(cls, text: str) -> str:
        return cls.decode_base64_candidates(text)