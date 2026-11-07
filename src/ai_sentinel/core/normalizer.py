import base64
import re
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Robust input normalizer and Base64 extraction engine capable of handling
    standard and URL-safe Base64 strings, nested payloads, and surrounding punctuation.
    """
    @staticmethod
    def extract_and_decode_base64(text: str, max_depth: int = 3) -> str:
        if not text:
            return text

        current_text = text
        # Regex to match Base64 candidate strings (standard and URL-safe, min length 16 chars)
        b64_pattern = re.compile(r'\b[A-Za-z0-9\-_+/]{16,}={0,2}\b')

        for depth in range(max_depth):
            matches = b64_pattern.findall(current_text)
            if not matches:
                break
            
            decoded_any = False
            for token in matches:
                try:
                    # Normalize URL-safe characters and add padding if missing
                    normalized_token = token.replace('-', '+').replace('_', '/')
                    padded = normalized_token + '=' * (-len(normalized_token) % 4)
                    
                    decoded_bytes = base64.b64decode(padded, validate=True)
                    decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                    
                    if decoded_str.strip() and decoded_str != token:
                        current_text += " " + decoded_str
                        decoded_any = True
                except Exception as e:
                    logger.debug(f"Base64 decode pass failed securely at depth {depth}: {e}")
            
            if not decoded_any:
                break

        return current_text

    @staticmethod
    def normalize(text: str) -> str:
        if not text:
            return ""
        # Basic whitespace normalization
        normalized = " ".join(text.split())
        # Expand and decode embedded payloads
        normalized = InputNormalizer.extract_and_decode_base64(normalized)
        return normalized