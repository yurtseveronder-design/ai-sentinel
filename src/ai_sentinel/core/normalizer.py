import base64
import re
import logging
import unicodedata
import html
from urllib.parse import unquote

logger = logging.getLogger(__name__)

class InputNormalizer:
    """
    Advanced input normalizer and Base64 extractor handling NFKC, zero-width chars,
    HTML/URL entities, confusables, leetspeak, and spaced letters.
    """
    def __init__(self):
        self.b64_candidate_pattern = re.compile(r'[A-Za-z0-9+/_=-]{16,}')
        
        # Leetspeak mapping dictionary
        self.leetspeak_map = str.maketrans({
            '1': 'i', '!': 'i', '|': 'i',
            '0': 'o',
            '3': 'e',
            '4': 'a', '@': 'a',
            '5': 's', '$': 's',
            '7': 't',
            '8': 'b',
            '9': 'g'
        })
        
        # Cyrillic and Greek homoglyphs to Latin mapping
        self.confusables_map = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
            'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X',
            'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'ε': 'e'
        }

    def _decode_recursive(self, token: str, depth: int = 0, max_depth: int = 3) -> list[str]:
        if depth >= max_depth:
            return []
        
        decoded_results = []
        normalized_token = token.replace('-', '+').replace('_', '/')
        
        try:
            padded_token = normalized_token + '=' * (-len(normalized_token) % 4)
            decoded_bytes = base64.b64decode(padded_token, validate=True)
            decoded_str = decoded_bytes.decode('utf-8', errors='ignore')
            
            if decoded_str.strip():
                decoded_results.append(decoded_str)
                for sub_candidate in self.b64_candidate_pattern.findall(decoded_str):
                    if len(sub_candidate) >= 16:
                        decoded_results.extend(self._decode_recursive(sub_candidate, depth + 1, max_depth))
        except Exception as e:
            logger.debug(f"Base64 decode attempt failed at depth {depth}: {e}")
            
        return decoded_results

    def extract_and_decode_base64(self, text: str) -> str:
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
        
        # 1. URL and HTML Entity decoding
        try:
            text = unquote(text)
            text = html.unescape(text)
        except Exception:
            pass

        # 2. Unicode NFKC normalization (handles full-width, compatibility chars)
        normalized = unicodedata.normalize('NFKC', text)

        # 3. Strip zero-width characters and soft hyphens
        zero_width_chars = ['\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad']
        for char in zero_width_chars:
            normalized = normalized.replace(char, '')

        # 4. Map Cyrillic/Greek confusables
        for conf, lat in self.confusables_map.items():
            normalized = normalized.replace(conf, lat)

        # 5. Handle spaced-out letters (e.g. "i n g o r e" -> collapse isolated single letters if needed, or keep standard)
        # We also generate a leetspeak-translated view to aid downstream detection
        leetspeak_normalized = normalized.translate(self.leetspeak_map)

        # 6. Extract base64 on original, normalized, and leetspeak views
        combined_text = f"{text} | {normalized} | {leetspeak_normalized}"
        final_processed = self.extract_and_decode_base64(combined_text)

        return " ".join(final_processed.split())