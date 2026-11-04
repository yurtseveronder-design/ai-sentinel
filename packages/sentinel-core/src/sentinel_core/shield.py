import unicodedata
import re

class MutationEngine:
    def generate_all_mutations(self, text: str) -> list:
        mutations = []
        fragmented = ' '.join(text) + ''.join([c + '\u200b' for c in text])
        mutations.append(fragmented)
        return mutations

class BioImmuneShield:
    def __init__(self):
        self.threat_signatures = [
            "ignore previous instructions",
            "system override",
            "disregard safety",
            "bypass restrictions",
            "act as developer",
        ]
        self.homoglyph_map = {
            ord('\u0430'): 'a',
            ord('\u0435'): 'e',
            ord('\u043e'): 'o',
            ord('\u0441'): 'c',
            ord('\u0440'): 'p',
            ord('\u0456'): 'i',
        }

    def mutate_prompt(self, text: str) -> str:
        return ' '.join(text) + ''.join([c + '\u200b' for c in text])

    def normalize(self, text: str) -> str:
        cleaned_text = re.sub(r'[\u200b\u200c\u200d\ufeff]', '', text)
        nfkd = unicodedata.normalize('NFKD', cleaned_text)
        translated = nfkd.translate(self.homoglyph_map)
        collapsed = re.sub(r'\s+', ' ', translated).strip()
        return collapsed.lower()

    def scan(self, prompt: str) -> dict:
        normalized = self.normalize(prompt)
        matched_pattern = None
        confidence = 0.0
        
        for sig in self.threat_signatures:
            if sig in normalized:
                matched_pattern = sig
                confidence = 0.95
                break
            elif any(word in normalized for word in sig.split()):
                matched_pattern = sig
                confidence = 0.70
                
        is_safe = matched_pattern is None
        if is_safe:
            confidence = 0.0
            
        return {
            "safe": is_safe,
            "threat_pattern": matched_pattern,
            "confidence": confidence,
            "normalized_prompt": normalized
        }
