from typing import Optional
from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict

class SentinelOpenAIException(PermissionError):
    def __init__(self, verdict: ShieldVerdict):
        self.verdict = verdict
        super().__init__(f"OpenAI call blocked by AI-Sentinel: {verdict.reason}")

class SentinelOpenAIProxy:
    """
    Transparent proxy wrapper for OpenAI-compatible clients.
    Intercepts messages in chat completions and applies threat inspection.
    """
    def __init__(self, client, shield: Optional[BioImmuneShield] = None, session_id: Optional[str] = None):
        self._client = client
        self._shield = shield or BioImmuneShield()
        self._session_id = session_id
        
        # Expose chat attribute
        self.chat = self._ChatProxy(self)

    class _ChatProxy:
        def __init__(self, outer):
            self._outer = outer
            self.completions = self._CompletionsProxy(outer)

        class _CompletionsProxy:
            def __init__(self, outer):
                self._outer = outer

            def create(self, *args, **kwargs):
                messages = kwargs.get("messages", [])
                for msg in messages:
                    if isinstance(msg, dict) and "content" in msg:
                        content = msg["content"]
                        if isinstance(content, str):
                            verdict = self._outer._shield.inspect(content, session_id=self._outer._session_id)
                            if verdict.action == "BLOCK":
                                raise SentinelOpenAIException(verdict)
                            msg["content"] = verdict.sanitized_text
                            
                return self._outer._client.chat.completions.create(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)