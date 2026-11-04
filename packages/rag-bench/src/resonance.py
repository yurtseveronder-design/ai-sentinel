import re
from typing import Dict, Any

class CognitiveResonanceAnalyzer:
    """
    Analyzes semantic alignment, keyword coverage, vocabulary diversity, 
    and structural pacing between a user query and a generated RAG response.
    """
    def __init__(self, semantic_threshold: float = 0.5):
        self.semantic_threshold = semantic_threshold

    def evaluate_resonance(self, query: str, response: str) -> Dict[str, Any]:
        if not query or not response:
            return {
                "resonance_score": 0.0,
                "is_cognitively_resonant": False,
                "reason": "Empty input detected."
            }

        # Filter out tiny words and tokenize
        q_tokens = [w.lower() for w in re.findall(r'\w+', query) if len(w) > 2]
        r_tokens = [w.lower() for w in re.findall(r'\w+', response) if len(w) > 2]

        if not q_tokens:
            keyword_coverage = 0.0
        else:
            q_set = set(q_tokens)
            r_set = set(r_tokens)
            keyword_coverage = len(q_set.intersection(r_set)) / len(q_set)

        # Vocabulary diversity / repetition penalty check
        unique_ratio = len(set(r_tokens)) / max(len(r_tokens), 1)

        # Structural length balance check (penalize extreme verbosity or abruptness)
        length_ratio = min(len(response), len(query) * 6) / max(len(response), len(query) * 6, 1)

        # Composite cognitive resonance score calculation
        resonance_score = round(float((keyword_coverage * 0.5) + (unique_ratio * 0.3) + (length_ratio * 0.2)), 2)
        is_resonant = resonance_score >= self.semantic_threshold

        return {
            "resonance_score": resonance_score,
            "is_cognitively_resonant": is_resonant,
            "keyword_coverage": round(keyword_coverage, 2),
            "vocabulary_diversity": round(unique_ratio, 2),
            "structural_balance": round(length_ratio, 2)
        }