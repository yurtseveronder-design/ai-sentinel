import unicodedata
import html
import urllib.parse
import re

class InputNormalizer:
    """
    Robust input normalizer supporting NFKC normalization, zero-width character stripping,
    confusable mapping, leetspeak translation, and entity decoding.
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

    def normalize(self, text: str) -> str:
        if not text:
            return ""

        # 1. NFKC normalization
        normalized = unicodedata.normalize("NFKC", text)

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