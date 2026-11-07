import base64
import re
import unicodedata
import logging
import html
import urllib.parse
from typing import List, Optional

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Advanced input normalizer and Base64 extraction engine handling NFKC normalization,
    zero-width character stripping, confusable mapping, leetspeak resolution, and nested decoding.
    """
    
    CONFUSABLES = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        'і': 'i', 'ј': 'j', 'ѕ': 's', 'ɡ': 'g',
        'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ν': 'v', 'τ': 't',
        '1': 'i', '3': 'e', '4': 'a', '0': 'o', '5': 's', '@': 'a', '$': 's'
    }

    @staticmethod
    def extract_and_decode_base64(text: str, max_depth: int = 3) -> str:
        if not text:
            return text

        current_text = text
        b64_pattern = re.compile(r'\b[A-Za-z0-9\-_+/]{16,}={0,2}\b')

        for depth in range(max_depth):
            matches = b64_pattern.findall(current_text)
            if not matches:
                break
            
            decoded_any = False
            for token in matches:
                try:
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

        # 1. Decode URL and HTML entities
        try:
            text = urllib.parse.unquote(text)
        except Exception:
            pass
        text = html.unescape(text)

        # 2. Apply NFKC Unicode normalization
        normalized = unicodedata.normalize("NFKC", text)

        # 3. Strip zero-width characters and soft hyphens
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
        for char in zero_width_chars:
            normalized = normalized.replace(char, '')

        # 4. Map confusables and leetspeak characters
        char_list = []
        for ch in normalized.lower():
            char_list.append(InputNormalizer.CONFUSABLES.get(ch, ch))
        normalized = "".join(char_list)

        # 5. Collapse spaced-out letters (e.g. "i g n o r e" -> "ignore")
        # Detect sequences of single letters separated by spaces
        spaced_pattern = re.compile(r'\b(?:[a-z]\s){2,}[a-z]\b')
        def collapse_spaced(match):
            return match.group(0).replace(' ', '')
        normalized = spaced_pattern.sub(collapse_spaced, normalized)

        # 6. Basic whitespace normalization
        normalized = " ".join(normalized.split())

        # 7. Extract and decode embedded Base64 payloads
        normalized = InputNormalizer.extract_and_decode_base64(normalized)

        return normalized