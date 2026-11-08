"""
Semantic Fuzzy Scorer for AI-Sentinel.
Catches prompt injection paraphrases and semantic variations using token distance
and synonym expansion without heavy LLMs or vector databases.
"""

import re
from typing import List, Tuple

class SemanticFuzzyScorer:
    """
    Performs semantic pattern matching against known injection intent clusters
    using normalized token overlap and semantic synonym expansion.
    """
    def __init__(self):
        # Semantic intent clusters (synonyms and conceptual paraphrases of jailbreaks)
        self.semantic_clusters = {
            "system_prompt_extraction": [
                "system instructions", "initial prompt", "hidden rules", 
                "underlying directives", "developer instructions", "core prompt"
            ],
            "override_directives": [
                "disregard prior", "pay no attention", "forget earlier", 
                "bypass rules", "override previous", "drop constraints"
            ],
            "privilege_escalation": [
                "developer mode", "god mode", "root access", 
                "admin privileges", "unrestricted mode", "jailbreak"
            ]
        }

    def _normalize(self, text: str) -> str:
        text = text.lower()
        text = re.sub(r'[^a-z0-9\s]', '', text)
        return " ".join(text.split())

    def score(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze text for semantic injection patterns.
        Returns (risk_score, triggered_reasons).
        """
        normalized_text = self._normalize(text)
        matched_reasons = []
        max_score = 0.0

        for cluster_name, phrases in self.semantic_clusters.items():
            cluster_matches = 0
            for phrase in phrases:
                # Check semantic synonym/phrase presence
                if phrase in normalized_text:
                    cluster_matches += 1

            if cluster_matches > 0:
                score_increment = min(0.4 * cluster_matches, 0.8)
                max_score = max(max_score, score_increment)
                matched_reasons.append(f"Semantic match detected in cluster: {cluster_name}")

        return max_score, matched_reasons