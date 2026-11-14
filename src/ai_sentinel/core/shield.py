"""
SecurityShield Core Inspection Engine for AI-Sentinel.
Inspects prompts for prompt injection, jailbreaks, and security threats.
"""

import re
from typing import Any, Tuple, Union, List
from ai_sentinel.core import signatures
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
        # Threat signatures live in core/signatures.py; kept here as a list for compatibility.
        self.threat_patterns = signatures.all_english()

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
        variants = signatures.fold(lower_prompt)
        for pattern in self.threat_patterns:
            if any(re.search(pattern, v, re.IGNORECASE) for v in variants):
                reasons.append(f"Matched threat signature: {pattern}")
                risk_score = 0.9

        # Multilingual signatures run on the un-folded text (folding would corrupt non-Latin scripts).
        original_lower = clean_prompt.lower()
        for language, patterns in signatures.MULTILINGUAL.items():
            for pattern in patterns:
                if re.search(pattern, original_lower):
                    reasons.append(f"Matched {language} threat signature: {pattern}")
                    risk_score = 0.9

        # Obfuscated spellings ("i.g.n.o.r.e", "ignore-previous-instructions") collapse to one string.
        squeezed = signatures.squeeze(lower_prompt)
        for phrase in signatures.SQUEEZED:
            if phrase in squeezed and not reasons:
                reasons.append(f"Matched obfuscated threat signature: {phrase}")
                risk_score = 0.9

        action = ShieldVerdict.BLOCK if (risk_score >= self.block_threshold or reasons) else ShieldVerdict.ALLOW
        if not reasons:
            reasons = ["Prompt passed security inspection"]
            risk_score = 0.0

        return InspectionResult(action, risk_score, reasons)