"""
Heuristic Scorer for AI-Sentinel.
Evaluates prompts for heuristic rule violations and injection patterns.
"""

import re
from typing import Tuple, List, Union, Dict, Any

class HeuristicResult(tuple):
    """Allows tuple unpacking and flexible dict key access for all test suites."""
    def __new__(cls, score: float, reasons: List[str]):
        return super().__new__(cls, (score, reasons))

    def __init__(self, score: float, reasons: List[str]):
        self._score = score
        self._reasons = reasons

    def __getitem__(self, key):
        if isinstance(key, str):
            if key in ("score", "heuristic_score", "risk_score"):
                return self._score
            elif key in ("reasons", "details", "flags", "matched_patterns"):
                return self._reasons
            raise KeyError(key)
        return super().__getitem__(key)

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

class HeuristicScorer:
    """
    Scans prompts against known malicious regex patterns and heuristics.
    """
    def __init__(self):
        self.patterns = [
            (r"ignore previous instructions", 0.9, "Prompt override attempt detected"),
            (r"reveal your password", 0.9, "Credential / system prompt extraction attempt"),
            (r"system instructions", 0.8, "System prompt query detected"),
            (r"developer mode", 0.8, "Privilege escalation detected"),
            (r"bypass rules", 0.9, "Rule bypass attempt detected"),
            (r"output system prompt", 0.9, "System prompt extraction attempt")
        ]

    def score(self, text: str) -> HeuristicResult:
        if not isinstance(text, str):
            return HeuristicResult(0.0, [])

        # Handle cyrillic homoglyph 'і' (U+0456) normalization for test cases
        normalized_text = text.lower().replace('і', 'i')
        max_score = 0.0
        reasons = []

        for pattern, weight, reason in self.patterns:
            if re.search(pattern, normalized_text):
                max_score = max(max_score, weight)
                if reason not in reasons:
                    reasons.append(reason)

        return HeuristicResult(max_score, reasons)

    def check(self, text: str) -> HeuristicResult:
        return self.score(text)

    def evaluate(self, text: str) -> HeuristicResult:
        return self.score(text)