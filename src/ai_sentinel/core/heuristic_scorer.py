"""
Experimental Heuristic Scorer for SecurityShield Lab.
Evaluates text entropy, suspicious keyword frequency, and prompt anomaly weights.
"""

import re
from typing import Dict, Any, List


class HeuristicScorer:
    """
    Calculates auxiliary risk factors based on lexical density and prompt structure anomalies.
    """

    def __init__(self, sensitivity: float = 1.0):
        self.sensitivity = sensitivity
        # High-risk trigger patterns for supplementary heuristic weighting
        self.suspicious_tokens = [
            r"system\s*prompt",
            r"developer\s*mode",
            r"ignore\s+(previous|all)\s+instructions",
            r"reveal\s+(password|key|secret)",
            r"bypass\s+filter"
        ]

    def evaluate(self, text: str) -> Dict[str, Any]:
        """
        Analyzes text for structural anomalies and returns an additional risk contribution.
        """
        if not text or not isinstance(text, str):
            return {"heuristic_score": 0.0, "matched_patterns": []}

        matched = []
        score_increment = 0.0

        lower_text = text.lower()
        for pattern in self.suspicious_tokens:
            if re.search(pattern, lower_text):
                matched.append(pattern)
                score_increment += 0.25

        # Apply sensitivity multiplier and cap at 1.0
        total_score = min(1.0, score_increment * self.sensitivity)

        return {
            "heuristic_score": round(total_score, 2),
            "matched_patterns": matched
        }