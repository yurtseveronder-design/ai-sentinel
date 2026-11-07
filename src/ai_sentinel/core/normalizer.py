import base64
import re
import html
import urllib.parse
import unicodedata
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Handles robust input normalization, character cleaning, confusable mapping,
    HTML/URL entity decoding, and advanced nested Base64 extraction.
    """
    
    # Cyrillic and Greek characters commonly used to spoof Latin letters in prompt injections
    CONFUSABLES_MAP = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O',
        'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'І': 'I',
        'α': 'a', 'ε': 'e', 'ο': 'o', 'ρ': 'p', 'ν': 'v', 'ω': 'w',
    }

    # Leetspeak / substitution mapping
    LEET_MAP = {
        '1': 'i', '3': 'e', '4': 'a', '0': 'o', '5': 's', '7': 't', '@': 'a', '$': 's'
    }

    @staticmethod
    def normalize_whitespace(text: str) -> str:
        if not text:
            return ""
        return " ".join(text.split())

    @classmethod
    def clean_unicode_and_entities(cls, text: str) -> str:
        """
        Applies NFKC normalization, strips zero-width spaces/soft hyphens,
        and decodes HTML and URL entities.
        """
        if not text:
            return ""

        # Decode URL encoding first (e.g., %20 -> space)
        try:
            text = urllib.parse.unquote(text)
        except Exception:
            pass

        # Decode HTML entities (e.g., &#x27; -> ')
        text = html.unescape(text)

        # Apply Unicode NFKC normalization (compatibility decomposition + composition)
        text = unicodedata.normalize("NFKC", text)

        # Strip zero-width characters, soft hyphens, and directional formatting marks
        zero_width_chars = [
            '\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad', 
            '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e'
        ]
        for char in zero_width_chars:
            text = text.replace(char, '')

        return text

    @classmethod
    def replace_confusables(cls, text: str) -> str:
        """
        Maps lookalike Cyrillic/Greek characters to their Latin equivalents.
        """
        if not text:
            return ""
        return "".join(cls.CONFUSABLES_MAP.get(c, c) for c in text)

    @staticmethod
    def decode_single_base64(token: str) -> Optional[str]:
        """
        Attempts to decode a single token as standard or URL-safe Base64.
        """
        if not token or len(token) < 4:
            return None
            
        cleaned = token.strip("\"'()[]{},.:;!?`*")
        if len(cleaned) < 4:
            return None

        for alt_token in [cleaned, cleaned + "=", cleaned + "=="]:
            for b64_fn in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    padding_needed = len(alt_token) % 4
                    padded_token = alt_token + ("=" * ((4 - padding_needed) % 4))
                    decoded_bytes = b64_fn(padded_token.encode("utf-8"), validate=True)
                    decoded_str = decoded_bytes.decode("utf-8")
                    
                    if decoded_str and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded_str):
                        return decoded_str
                except Exception:
                    continue
        return None

    @classmethod
    def extract_and_decode_base64(cls, text: str, max_depth: int = 3) -> str:
        if not text:
            return ""

        current_text = text
        b64_pattern = re.compile(r'[A-Za-z0-9+/_-]{4,}={0,2}')

        for depth in range(max_depth):
            decoded_any = False
            matches = b64_pattern.findall(current_text)
            
            for match in matches:
                decoded = cls.decode_single_base64(match)
                if decoded:
                    current_text = current_text.replace(match, f" {decoded} ")
                    decoded_any = True
            
            if not decoded_any:
                break

        return current_text

    @classmethod
    def full_normalize(cls, text: str) -> str:
        """
        Performs full multi-layer normalization pipeline:
        1. Unicode cleanup & entity decoding
        2. Confusable character replacement
        3. Base64 extraction and recursive decoding
        4. Whitespace regularization
        """
        if not text:
            return ""
        
        cleaned = cls.clean_unicode_and_entities(text)
        cleaned = cls.replace_confusables(cleaned)
        decoded_expanded = cls.extract_and_decode_base64(cleaned)
        
        return cls.normalize_whitespace(decoded_expanded)