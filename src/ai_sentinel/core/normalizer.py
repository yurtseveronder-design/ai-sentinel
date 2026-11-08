import base64
import html
import re
import unicodedata
from dataclasses import dataclass
from typing import Tuple, Set

@dataclass
class NormalizeAudit:
    text: str
    steps: Tuple[str, ...]

class InputNormalizer:
    @classmethod
    def normalize_with_audit(cls, text: str, max_input_chars: int = 32000) -> NormalizeAudit:
        if not text:
            return NormalizeAudit(text="", steps=())

        steps_set: Set[str] = set()
        current = text

        surrogate_cleaned = re.sub(r"[\ud800-\udfff]", "", current)
        if surrogate_cleaned != current:
            steps_set.add("surrogate")
            current = surrogate_cleaned

        if len(current) > max_input_chars:
            steps_set.add("over_limit")
            return NormalizeAudit(text=current, steps=tuple(sorted(steps_set)))

        for _ in range(3):
            prev = current
            current = unicodedata.normalize("NFKC", current)
            if current != prev:
                steps_set.add("nfkc")

            zw_cleaned = re.sub(r"[\u200b-\u200d\ufeff\u00ad\u2060]", "", current)
            if zw_cleaned != current:
                steps_set.add("zero_width")
                current = zw_cleaned

            html_unescaped = html.unescape(current)
            if html_unescaped != current:
                steps_set.add("html")
                current = html_unescaped

            try:
                from urllib.parse import unquote
                url_decoded = unquote(current)
                if url_decoded != current:
                    steps_set.add("url")
                    current = url_decoded
            except Exception:
                pass

            if current == prev:
                break

        for _ in range(3):
            if cls._is_base64(current):
                try:
                    decoded_bytes = base64.b64decode(current)
                    decoded_str = decoded_bytes.decode("utf-8")
                    if decoded_str.isprintable():
                        current = decoded_str
                        steps_set.add("base64")
                        break
                except Exception:
                    break
            else:
                break

        collapsed = re.sub(r"\s+", " ", current).strip()
        if collapsed != current:
            steps_set.add("whitespace")
            current = collapsed

        return NormalizeAudit(text=current, steps=tuple(sorted(steps_set)))

    @classmethod
    def full_normalize(cls, text: str) -> str:
        return cls.normalize_with_audit(text).text

    @staticmethod
    def _is_base64(s: str) -> bool:
        if len(s) % 4 != 0 or len(s) < 8:
            return False
        return bool(re.match(r"[A-Za-z0-9+/]+={0,2}$", s))
