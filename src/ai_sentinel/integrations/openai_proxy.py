import logging
from typing import Any, Dict, List, Optional
from ai_sentinel.core.shield import SecurityShield

logger = logging.getLogger(__name__)

class SentinelOpenAIException(ValueError):
    """Custom exception raised when OpenAI proxy detects a security violation."""
    pass

class OpenAIProxyWrapper:
    """
    Enterprise OpenAI proxy wrapper that inspects messages, user/tool content,
    and multi-part payloads before forwarding to OpenAI clients.
    """
    def __init__(self, client: Optional[Any] = None, shield: Optional[SecurityShield] = None, api_key: Optional[str] = None, **kwargs):
        self.client = client
        self.shield = shield or SecurityShield(mode="moderate")
        self.api_key = api_key
        self.kwargs = kwargs

    def __getattr__(self, name: str) -> Any:
        # Delegate attribute lookups (like .chat) to the underlying client
        if self.client and hasattr(self.client, name):
            attr = getattr(self.client, name)
            # If it's chat, return a wrapped chat attribute/object if needed
            return attr
        raise AttributeError(f"'{self.__class__.__name__}' object has no attribute '{name}'")

    def _extract_text(self, content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            texts = []
            for part in content:
                if isinstance(part, dict):
                    if "text" in part:
                        texts.append(str(part["text"]))
                    elif "content" in part:
                        texts.append(str(part["content"]))
                elif isinstance(part, str):
                    texts.append(part)
            return " ".join(texts)
        return str(content or "")

    def inspect_messages(self, messages: List[Dict[str, Any]]) -> None:
        for msg in messages:
            role = msg.get("role", "")
            content = msg.get("content", "")
            
            if role in ["user", "tool", "system"]:
                text_to_scan = self._extract_text(content)
                if text_to_scan:
                    verdict = self.shield.inspect(text=text_to_scan)
                    if verdict.flagged:
                        raise SentinelOpenAIException(f"OpenAIProxy blocked prompt due to security policy: {verdict.reason}")

    def create_chat_completion(self, client: Any = None, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        if not messages and args:
            messages = args[0] if isinstance(args[0], list) else []

        if messages:
            self.inspect_messages(messages)

        target_client = client or self.client
        if target_client and hasattr(target_client, "chat") and hasattr(target_client.chat, "completions"):
            return target_client.chat.completions.create(*args, **kwargs)
        raise RuntimeError("Provided client does not support chat.completions API.")

# Aliases expected by integration tests
SentinelOpenAIProxy = OpenAIProxyWrapper