import unicodedata
import html
import urllib.parse
import re
import base64

class InputNormalizer:
    """
    Strict input normalizer supporting NFKC normalization, zero-width character stripping,
    confusable mapping, leetspeak translation, entity decoding, and targeted Base64 extraction.
    """

    CONFUSABLES = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
        'і': 'i', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', '𝗁': 'h', '𝑚': 'm',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K',
        'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Y': 'Y'
    }

    LEETSPEAK = {
        '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'
    }

    def _decode_base64_tokens(self, text: str) -> str:
        """
        Scans for valid Base64 tokens >= 16 characters. 
        Decodes each in an isolated try block to prevent one bad token from stopping the scan.
        """
        # Matches words containing only valid Base64 characters and at least 16 chars long
        b64_pattern = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')
        
        def replace_token(match):
            token = match.group(0)
            try:
                # Add padding if missing to prevent padding errors
                padded_token = token + "=" * ((4 - len(token) % 4) % 4)
                decoded_bytes = base64.b64decode(padded_token, validate=True)
                decoded_str = decoded_bytes.decode('utf-8')
                
                # If it successfully decodes to a string, append it to the original token
                # so the shield can scan the hidden payload.
                if decoded_str.strip():
                    return f"{token} {decoded_str}"
            except Exception:
                # If decoding fails (e.g., random noise that happens to match the alphabet),
                # just fail safely for this specific token and move on.
                pass
            return token

        return b64_pattern.sub(replace_token, text)

    def normalize(self, text: str) -> str:
        if not text:
            return ""

        # 0. Decode Base64 tokens inline before normalization
        normalized = self._decode_base64_tokens(text)

        # 1. NFKC normalization
        normalized = unicodedata.normalize("NFKC", normalized)

        # 2. Remove zero-width and invisible characters
        zero_width_chars = [
            "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
            "\u200e", "\u200f", "\u202a", "\u202b", "\u202c", "\u202d", "\u202e"
        ]
        for zw in zero_width_chars:
            normalized = normalized.replace(zw, "")

        # 3. Decode HTML and URL entities
        normalized = html.unescape(normalized)
        normalized = urllib.parse.unquote(normalized)

        # 4. Map Cyrillic and Greek confusables
        char_list = []
        for char in normalized:
            mapped = self.CONFUSABLES.get(char, char)
            char_list.append(mapped)
        normalized = "".join(char_list)

        # 5. Map basic leetspeak
        leet_list = []
        for char in normalized:
            mapped = self.LEETSPEAK.get(char, char)
            leet_list.append(mapped)
        normalized = "".join(leet_list)

        # 6. Normalize whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip()

        return normalized