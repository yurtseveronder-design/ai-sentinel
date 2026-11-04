"""
Adversarial Prompt Mutation Engine for AI Security Evaluation.
Generates robust variations of input prompts to test guardrail resilience.
"""

import random

class MutationEngine:
    def __init__(self):
        # Dictionary of common character substitutions/homoglyphs for evasion testing
        self.homoglyphs = {
            'a': ['а', 'ɑ', 'ａ'],  # Cyrillic/modifier lookalikes
            'e': ['е', 'ｅ'],
            'o': ['о', 'ο', 'ｏ'],
            'i': ['і', 'ｉ'],
            's': ['ѕ', 'ｓ']
        }

    def generate_casing_variants(self, text: str) -> list[str]:
        """Generates random casing perturbations."""
        variants = []
        # All lower, all upper, alternate case
        variants.append(text.lower())
        variants.append(text.upper())
        variants.append("".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(text)))
        return list(set(variants))

    def generate_homoglyph_variants(self, text: str, probability: float = 0.3) -> list[str]:
        """Injects unicode homoglyphs to test regex/token bypass."""
        variants = []
        chars = list(text)
        for _ in range(3): # Generate 3 different random permutations
            perturbed = chars.copy()
            for i, c in enumerate(perturbed):
                lower_c = c.lower()
                if lower_c in self.homoglyphs and random.random() < probability:
                    perturbed[i] = random.choice(self.homoglyphs[lower_c])
            variants.append("".join(perturbed))
        return list(set(variants))

    def generate_separator_variants(self, text: str) -> list[str]:
        """Injects zero-width spaces or unconventional delimiters."""
        zero_width_space = "\u200b"
        # Insert zero width space between characters
        zws_variant = zero_width_space.join(list(text))
        return [text, zws_variant]

    def generate_all_mutations(self, text: str) -> list[str]:
        """Runs the complete mutation pipeline to produce a suite of test vectors."""
        mutations = set()
        mutations.update(self.generate_casing_variants(text))
        mutations.update(self.generate_homoglyph_variants(text))
        mutations.update(self.generate_separator_variants(text))
        return list(mutations)