import base64
import re
import logging

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Normalizes input text and robustly extracts/decodes Base64 payloads 
    surrounded by punctuation, quotes, or brackets, supporting standard 
    and URL-safe alphabets with nested decoding (up to depth 3).
    """
    def __init__(self):
        # Regex matching standard and URL-safe base64 candidate strings of length >= 16
        self.b64_candidate_pattern = re.compile(r'[A-Za-z0-9+/_=-]{16,}')

    def _decode_recursive(self, token: str, depth: int = 0, max_depth: int = 3) -> list[str]:
        if depth >= max_depth:
            return []
        
        decoded_results = []
        # Normalize URL-safe characters to standard base64 characters
        normalized_token = token.replace('-', '+').replace('_', '/')
        
        try:
            padded_token = normalized_token + '=' * (-len(normalized_token) % 4)
            decoded_bytes = base64.b64decode(padded_token, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            if decoded_str.strip():
                decoded_results.append(decoded_str)
                # Check for nested base64 inside the decoded string
                for sub_candidate in self.b64_candidate_pattern.findall(decoded_str):
                    if len(sub_candidate) >= 16:
                        decoded_results.extend(self._decode_recursive(sub_candidate, depth + 1, max_depth))
        except Exception as e:
            logger.debug(f"Base64 decode attempt failed at depth {depth} for token '{token}': {e}")
            
        return decoded_results

    def extract_and_decode_base64(self, text: str) -> str:
        """Scans text for valid Base64 tokens using regex search, decodes nested payloads, and appends results."""
        if not text:
            return text

        decoded_additions = []
        candidates = self.b64_candidate_pattern.findall(text)
        
        for candidate in candidates:
            results = self._decode_recursive(candidate)
            for res in results:
                if res.strip() and res not in decoded_additions:
                    decoded_additions.append(res)

        if decoded_additions:
            return text + " " + " ".join(decoded_additions)
        return text

    def normalize(self, text: str) -> str:
        if not text:
            return ""
        normalized = " ".join(text.split())
        return self.extract_and_decode_base64(normalized)