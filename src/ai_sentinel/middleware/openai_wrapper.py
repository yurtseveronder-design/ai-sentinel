"""
OpenAI Client Wrapper for AI-Sentinel.
Intercepts chat completion calls to inspect prompts before sending to OpenAI.
"""

import logging
from typing import Any, Optional
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.core.audit import AuditLogger

logger = logging.getLogger("security_shield.openai")

class AISentinelOpenAI:
    """
    Wrapper for the OpenAI client that automatically applies AI-Sentinel security inspection
    on chat completion requests before they are transmitted.
    """
    def __init__(self, client: Any, shield: Optional[SecurityShield] = None, audit_logger: Optional[AuditLogger] = None):
        self.client = client
        self.shield = shield or SecurityShield()
        self.audit_logger = audit_logger or AuditLogger(service_name="ai-sentinel-openai")

    class ChatCompletionsProxy:
        def __init__(self, completions, shield, audit_logger):
            self._completions = completions
            self._shield = shield
            self._audit_logger = audit_logger

        def create(self, *args, **kwargs):
            messages = kwargs.get("messages", [])
            prompt_text = ""
            for msg in messages:
                if msg.get("role") == "user":
                    prompt_text = msg.get("content", "")

            if prompt_text:
                verdict, score, reasons = self._shield.inspect(prompt_text)
                self._audit_logger.log_event(
                    action=verdict,
                    risk_score=score,
                    client_id="openai-client-wrapper",
                    reasons=reasons
                )
                if verdict == "BLOCK":
                    raise ValueError(f"AI-Sentinel Security Violation: Prompt blocked. Reasons: {reasons}")

            return self._completions.create(*args, **kwargs)

    @property
    def chat(self):
        parent = self
        class ChatProxy:
            def __init__(self, parent_client):
                self.completions = parent.ChatCompletionsProxy(parent_client.chat.completions, parent.shield, parent.audit_logger)
        return ChatProxy(self.client)