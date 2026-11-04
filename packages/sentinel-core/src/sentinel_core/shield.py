import re
import unicodedata
from difflib import SequenceMatcher

try:
    from sentinel_core.mutator import MutationEngine
except ImportError:
    try:
        from sentinel_core.mutation import MutationEngine
    except ImportError:
        MutationEngine = None

HOMOGLYPHS = str.maketrans({0x0430: 'a', 0x0441: 'c', 0x0435: 'e', 0x043e: 'o', 0x0440: 'p', 0x0445: 'x', 0x0443: 'y', 0x0456: 'i', 0x0455: 's', 0x0501: 'd', 0x40: 'a', 0x30: 'o', 0x31: 'i', 0x33: 'e', 0x24: 's', 0x21: 'i'})

class BioImmuneShield:
    def __init__(self):
        self.forbidden = 'ignore previous instructions'
        self.forbidden_signature = 'ignorepreviousinstructions'

    def scan(self, text: str) -> dict:
        if not text:
            return {'safe': True, 'threat_pattern': None, 'confidence': 0.0}
        nfkd = unicodedata.normalize('NFKD', str(text))
        translated = nfkd.lower().translate(HOMOGLYPHS)
        cleaned = ''.join(c for c in translated if c.isalnum())
        
        # 1. Exact or substring match
        if self.forbidden_signature in cleaned:
            return {'safe': False, 'threat_pattern': self.forbidden, 'confidence': 0.95}
            
        # 2. Fuzzy sequence similarity match for heavily mutated space injections
        ratio = SequenceMatcher(None, self.forbidden_signature, cleaned).ratio()
        if ratio > 0.65 or ('ignor' in cleaned and 'previous' in cleaned) or ('ignore' in cleaned and 'instruct' in cleaned):
            return {'safe': False, 'threat_pattern': self.forbidden, 'confidence': round(ratio, 2)}
            
        return {'safe': True, 'threat_pattern': None, 'confidence': 0.0}

    def mutate_prompt(self, text: str) -> str:
        if MutationEngine:
            try:
                engine = MutationEngine()
                variants = engine.generate_all_mutations(text)
                if variants:
                    return variants[0]
            except Exception:
                pass
        return ' '.join(text)
