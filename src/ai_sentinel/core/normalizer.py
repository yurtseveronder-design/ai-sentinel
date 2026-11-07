import base64
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Handles robust input normalization, character cleaning, and advanced 
    nested Base64 extraction with punctuation handling.
    """
    
    @staticmethod
    def normalize_whitespace(text: str) -> str:
        """
        Collapses excessive whitespace and strips leading/trailing spaces.
        """
        if not text:
            return ""
        return " ".join(text.split())

    @staticmethod
    def decode_single_base64(token: str) -> Optional[str]:
        """
        Attempts to decode a single token as standard or URL-safe Base64.
        Returns decoded string if valid UTF-8 text, else None.
        """
        if not token or len(token) < 4:
            return None
            
        # Clean potential surrounding punctuation if any leaked through
        cleaned = token.strip("\"'()[]{},.:;!?`*")
        if len(cleaned) < 4:
            return None

        # Try standard and URL-safe base64 decodings with padding fixes
        for alt_token in [cleaned, cleaned + "=", cleaned + "=="]:
            for b64_fn in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    padding_needed = len(alt_token) % 4
                    padded_token = alt_token + ("=" * ((4 - padding_needed) % 4))
                    decoded_bytes = b64_fn(padded_token.encode("utf-8"), validate=True)
                    decoded_str = decoded_bytes.decode("utf-8")
                    
                    # Ensure decoded text is printable/meaningful text
                    if decoded_str and all(32 <= ord(c) < 127 or c in "\n\r\t" for c in decoded_str):
                        return decoded_str
                except Exception:
                    continue
        return None

    @classmethod
    def extract_and_decode_base64(cls, text: str, max_depth: int = 3) -> str:
        """
        Searches for Base64 candidates using regex (ignoring surrounding punctuation/quotes),
        decodes them up to max_depth levels, and returns the expanded text.
        """
        if not text:
            return ""

        current_text = text
        
        # Regex to find potential Base64 strings (alphanumeric, +, /, _, -, with padding)
        # Minimum length of 4 characters
        b64_pattern = re.compile(r'[A-Za-z0-9+/_-]{4,}={0,2}')

        for depth in range(max_depth):
            decoded_any = False
            matches = b64_pattern.findall(current_text)
            
            for match in matches:
                decoded = cls.decode_single_base64(match)
                if decoded:
                    # Replace the encoded match with its decoded form
                    current_text = current_text.replace(match, f" {decoded} ")
                    decoded_any = True
            
            if not decoded_any:
                break

        return cls.normalize_whitespace(current_text)