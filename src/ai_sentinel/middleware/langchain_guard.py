"""
LangChain Guardrail Decorator for AI-Sentinel.
Inspects input strings or dictionaries before passing them into LangChain runnables or chains.
"""

from typing import Callable, Any, Optional
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.core.audit import AuditLogger

def secure_langchain_input(shield: Optional[SecurityShield] = None, audit_logger: Optional[AuditLogger] = None):
    """
    Decorator for LangChain chains or execution functions to inspect inputs for prompt injection.
    """
    _shield = shield or SecurityShield()
    _audit_logger = audit_logger or AuditLogger(service_name="ai-sentinel-langchain")

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(*args, **kwargs):
            input_data = args[0] if args else kwargs.get("input") or kwargs.get("text") or ""
            prompt = ""
            if isinstance(input_data, str):
                prompt = input_data
            elif isinstance(input_data, dict):
                prompt = input_data.get("input") or input_data.get("prompt") or str(input_data)

            if prompt:
                verdict, score, reasons = _shield.inspect(prompt)
                _audit_logger.log_event(
                    action=verdict,
                    risk_score=score,
                    client_id="langchain-wrapper",
                    reasons=reasons
                )
                if verdict == "BLOCK":
                    raise ValueError(f"AI-Sentinel LangChain Security Block: {reasons}")

            return func(*args, **kwargs)
        return wrapper
    return decorator
