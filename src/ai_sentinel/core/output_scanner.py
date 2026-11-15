"""Scans model OUTPUT for leaked secrets and personal data before it reaches the user.

Secrets lead to BLOCK. Personal data leads to REDACT (the text comes back with the values masked).
Findings report types and counts only, never the matched values.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List

SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "api_key": re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "password_assignment": re.compile(r"(?i)\b(?:password|passwd|secret|token)\s*[:=]\s*[^\s,;]{6,}"),
}
PII_PATTERNS = {
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    "us_ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "iban": re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){3,7}(?: ?[A-Z0-9]{1,4})?\b"),
}
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d = d * 2 - 9 if d * 2 > 9 else d * 2
        total += d
    return total % 10 == 0


@dataclass
class OutputVerdict:
    action: str  # ALLOW | REDACT | BLOCK
    findings: List[Dict[str, object]] = field(default_factory=list)
    redacted_text: str = ""


def scan_output(text: str) -> OutputVerdict:
    redacted = text
    counts: Dict[str, int] = {}
    secret_found = False

    for name, pattern in SECRET_PATTERNS.items():
        redacted, n = pattern.subn(f"[REDACTED:{name}]", redacted)
        if n:
            counts[name] = counts.get(name, 0) + n
            secret_found = True

    def mask_card(match):
        if _luhn(match.group()):
            counts["credit_card"] = counts.get("credit_card", 0) + 1
            return "[REDACTED:credit_card]"
        return match.group()

    redacted = CARD.sub(mask_card, redacted)
    for name, pattern in PII_PATTERNS.items():
        redacted, n = pattern.subn(f"[REDACTED:{name}]", redacted)
        if n:
            counts[name] = counts.get(name, 0) + n

    findings = [{"type": k, "count": v} for k, v in sorted(counts.items())]
    if secret_found:
        action = "BLOCK"
    elif findings:
        action = "REDACT"
    else:
        action = "ALLOW"
    return OutputVerdict(action, findings, redacted if findings else text)
