from typing import Optional, Tuple, Dict, Any
from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict

class SentinelClient:
    """
    Drop-in client wrapper for AI-Sentinel security proxy.
    Intercepts prompts, runs inspection/sanitization via BioImmuneShield,
    and raises errors or flags payloads before they reach upstream LLMs.
    """
    def __init__(self, shield: Optional[BioImmuneShield] = None, mode: str = "moderate"):
        self.shield = shield or BioImmuneShield(mode=mode)

    def secure_prompt(self, prompt: str, session_id: Optional[str] = None) -> Tuple[str, ShieldVerdict]:
        """
        Inspects and sanitizes a prompt. Raises PermissionError if blocked.
        Returns the sanitized text and the full ShieldVerdict.
        """
        verdict = self.shield.inspect(prompt, session_id=session_id)
        
        if verdict.action == "BLOCK":
            raise PermissionError(
                f"[AI-Sentinel BLOCKED] Action: BLOCK | Risk Score: {verdict.risk_score:.2f} | Reason: {verdict.reason}"
            )
        
        return verdict.sanitized_text, verdict