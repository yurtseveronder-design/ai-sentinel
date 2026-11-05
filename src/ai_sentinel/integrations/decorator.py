from functools import wraps
from typing import Optional
from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict

class PromptBlockedError(PermissionError):
    def __init__(self, verdict: ShieldVerdict):
        self.verdict = verdict
        super().__init__(f"Prompt blocked by AI-Sentinel: {verdict.reason}")

def secure_prompt(shield: Optional[BioImmuneShield] = None, session_id: Optional[str] = None):
    """
    Decorator that inspects and sanitizes string prompt arguments before execution.
    Raises PromptBlockedError if the shield blocks the input.
    """
    active_shield = shield or BioImmuneShield()

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract prompt from first positional argument or keyword argument 'prompt'/'text'
            prompt = None
            arg_idx = None
            kwarg_key = None

            if args and isinstance(args[0], str):
                prompt = args[0]
                arg_idx = 0
            elif "prompt" in kwargs and isinstance(kwargs["prompt"], str):
                prompt = kwargs["prompt"]
                kwarg_key = "prompt"
            elif "text" in kwargs and isinstance(kwargs["text"], str):
                prompt = kwargs["text"]
                kwarg_key = "text"

            if prompt is not None:
                verdict = active_shield.inspect(prompt, session_id=session_id)
                if verdict.action == "BLOCK":
                    raise PromptBlockedError(verdict)
                
                # Replace with sanitized text
                if arg_idx is not None:
                    args = (verdict.sanitized_text,) + args[1:]
                elif kwarg_key is not None:
                    kwargs[kwarg_key] = verdict.sanitized_text

            return func(*args, **kwargs)
        return wrapper
    return decorator