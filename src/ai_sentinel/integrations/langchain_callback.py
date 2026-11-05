from typing import Any, Dict, List, Optional
from ai_sentinel.core.shield import BioImmuneShield

try:
    from langchain_core.callbacks.base import BaseCallbackHandler
    LANGCHAIN_AVAILABLE = True
except ImportError:
    LANGCHAIN_AVAILABLE = False
    # Fallback dummy class if langchain isn't installed in the environment
    class BaseCallbackHandler:
        pass

class SentinelLangChainCallback(BaseCallbackHandler):
    """
    LangChain callback handler that intercepts chat model starts
    to inspect and sanitize prompt chains automatically.
    """
    def __init__(self, shield: Optional[BioImmuneShield] = None):
        if not LANGCHAIN_AVAILABLE:
            raise ImportError("langchain-core is not installed. Run 'pip install langchain-core'.")
        self.shield = shield or BioImmuneShield()

    def on_chat_model_start(
        self, serialized: Dict[str, Any], messages: List[List[Any]], *, run_id: Any, **kwargs: Any
    ) -> None:
        """Inspects messages right before they hit the chat model."""
        for message_list in messages:
            for message in message_list:
                if hasattr(message, "content") and isinstance(message.content, str):
                    verdict = self.shield.inspect(message.content)
                    if verdict.action == "BLOCK":
                        raise ValueError(f"AI-Sentinel LangChain Gate Blocked Prompt: {verdict.reason}")
                    message.content = verdict.sanitized_text