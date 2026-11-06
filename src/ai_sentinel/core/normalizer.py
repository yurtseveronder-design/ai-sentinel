import base64
import re
import logging

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Normalizes input text and safely extracts/decodes token-level Base64 payloads 
    meeting length (>=16) and alphabet criteria.
    """
    def __init__(self):
        # Base64 regex pattern matching valid alphabet strings of length >= 16
        self.b64_token_pattern = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')

    def extract_and_decode_base64(self, text: str) -> str:
        """Scans text for valid Base64 tokens, decodes them individually, and appends results."""
        if not text:
            return text

        decoded_additions = []
        tokens = text.split()
        
        for token in tokens:
            if self.b64_token_pattern.match(token):
                try:
                    # Isolate each decode attempt in its own try block
                    padded_token = token + '=' * (-len(token) % 4)
                    decoded_bytes = base64.b64decode(padded_token, validate=True)
                    decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
                    if decoded_str.strip():
                        decoded_additions.append(decoded_str)
                except Exception as e:
                    logger.debug(f"Failed to decode potential base64 token '{token}': {e}")

        if decoded_additions:
            return text + " " + " ".join(decoded_additions)
        return text

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        # Basic whitespace and normalization normalization
        normalized = " ".join(text.split())
        return self.extract_and_decode_base64(normalized)