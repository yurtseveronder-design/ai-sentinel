"""
SecurityShield Core Inspection Engine for AI-Sentinel.
Inspects prompts for prompt injection, jailbreaks, and security threats.
"""

import re
from typing import Any, Tuple, Union, List
from ai_sentinel.normalizers.base import InputNormalizer

class ShieldVerdict:
    """
    Represents the verdict of a shield inspection.
    """
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    WARNING = "WARNING"

class InspectionResult(str, ShieldVerdict):
    """
    Inspection result supporting tuple unpacking (verdict, score, reasons) and verdict checks.
    """
    def __new__(cls, action, risk_score, reasons):
        obj = super().__new__(cls, action)
        obj.action = action
        obj.risk_score = risk_score
        obj.reasons = reasons
        obj.reason = reasons
        obj.flagged = action == cls.BLOCK
        return obj

    def __iter__(self):
        return iter((self.action, self.risk_score, self.reasons))

    def __getitem__(self, index):
        if isinstance(index, slice):
            return (self.action, self.risk_score, self.reasons)[index]
        tup = (self.action, self.risk_score, self.reasons)
        if index < len(tup):
            return tup[index]
        return self.action

ShieldResult = Tuple[str, List[str]]

class SecurityShield:
    """
    Shield engine that evaluates prompts against security rules and patterns.
    """
    def __init__(self, sensitivity: str = "medium", block_threshold: float = 0.7, threshold: float = None, **kwargs):
        self.sensitivity = sensitivity
        self.block_threshold = threshold if threshold is not None else block_threshold
        # Strict malicious injection patterns (avoiding benign queries like system instruction inquiries unless explicit jailbreak)
        self.threat_patterns = [
            r"ignore\s+(previous|all)\s+instructions",
            r"reveal\s+(your\s+)?(password|secret|api[_\s]?key)",
            r"bypass\s+(safety|security)",
            r"you\s+are\s+now\s+dan",
            r"enable\s+developer\s+mode",
            r"bypass\s+rules"
        ]

    def inspect(self, prompt: str = None, text: str = None, **kwargs) -> InspectionResult:
        """
        Normalizes the incoming prompt, maps homoglyphs, and inspects it for security violations.
        """
        target_text = prompt if prompt is not None else (text if text is not None else "")
        if not isinstance(target_text, str):
            target_text = str(target_text) if target_text else ""

        # The package normalizer: NFKC, invisible characters, then whitespace.
        clean_prompt = InputNormalizer().normalize(target_text)
        
        # Normalize Cyrillic homoglyphs (e.g. Cyrillic 'і' -> Latin 'i') for robust detection
        homoglyph_map = {
            '\u0456': 'i',  # Cyrillic small letter byelorussian-ukrainian i
            '\u0406': 'I',  # Cyrillic capital letter i
            '\u0430': 'a',  # Cyrillic small letter a
            '\u0435': 'e',  # Cyrillic small letter e
            '\u043e': 'o',  # Cyrillic small letter o
            '\u0440': 'p',  # Cyrillic small letter er
            '\u0441': 'c',  # Cyrillic small letter es
            '\u0445': 'x',  # Cyrillic small letter ha
            '\u0443': 'y',  # Cyrillic small letter u
        }
        normalized_chars = [homoglyph_map.get(char, char) for char in clean_prompt]
        lower_prompt = "".join(normalized_chars).lower()

        reasons = []
        risk_score = 0.0
        for pattern in self.threat_patterns:
            if re.search(pattern, lower_prompt, re.IGNORECASE):
                reasons.append(f"Matched threat signature: {pattern}")
                risk_score = 0.9

        action = ShieldVerdict.BLOCK if (risk_score >= self.block_threshold or reasons) else ShieldVerdict.ALLOW
        if not reasons:
            reasons = ["Prompt passed security inspection"]
            risk_score = 0.0

        return InspectionResult(action, risk_score, reasons)