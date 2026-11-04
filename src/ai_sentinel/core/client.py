from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict

class SecurityViolationError(Exception):
    """Raised when an incoming prompt is blocked by BioImmuneShield."""
    def __init__(self, message: str, verdict: ShieldVerdict):
        super().__init__(message)
        self.verdict = verdict

class ProtectedLLMClient:
    def __init__(self, shield: BioImmuneShield = None):
        self.shield = shield or BioImmuneShield()

    def generate_response(self, user_prompt: str) -> str:
        """
        Inspects the user prompt through BioImmuneShield before sending to an LLM.
        Raises SecurityViolationError if malicious, otherwise simulates model completion.
        """
        verdict = self.shield.inspect_payload(user_prompt)

        if verdict.action == "BLOCK":
            raise SecurityViolationError(
                f"Request blocked due to security policy. Reason: {verdict.reason}",
                verdict=verdict
            )
        
        if verdict.action == "FLAG":
            # You could add extra logging or monitoring here for flagged queries
            print(f"[WARNING] Processing flagged query: {user_prompt} | Rules: {verdict.matched_rules}")

        # Simulate upstream LLM generation for allowed/flagged requests
        return f"MockLLMResponse: Successfully processed safe prompt -> '{user_prompt}'"