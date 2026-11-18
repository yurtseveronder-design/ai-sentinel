# SentinelClient: copy-paste patterns

Standard library only. Install: `pip install "git+https://github.com/yurtseveronder-design/ai-sentinel.git"`.

```python
from ai_sentinel.client import SentinelClient, PromptBlocked, SentinelError

guard = SentinelClient("http://localhost:8000", api_key="change-me", timeout=5.0)
```

| Method | Returns | Raises |
|---|---|---|
| `scan(text)` | Full verdict dict, even for BLOCK | `SentinelError` if the gateway cannot answer |
| `check(text)` | Verdict dict if allowed | `PromptBlocked` on BLOCK; `SentinelError` on failure |
| `scan_output(text)` | Output verdict dict | `SentinelError` |
| `redact_output(text)` | Text with personal data masked | `PromptBlocked` if it contains a secret |

**Fail closed.** `SentinelError` means no verdict. Treat it as "do not proceed", not as "allowed".

## 1. Guard a chat call

```python
def answer(user_text: str) -> str:
    try:
        guard.check(user_text)
    except PromptBlocked as blocked:
        return "Sorry, I can't help with that."
    except SentinelError:
        return "The safety check is unavailable, please try again later."
    return call_your_llm(user_text)
```

## 2. Guard input and output

```python
def safe_answer(user_text: str) -> str:
    guard.check(user_text)                      # may raise PromptBlocked / SentinelError
    reply = call_your_llm(user_text)
    return guard.redact_output(reply)           # masks emails etc.; raises PromptBlocked on secrets
```

## 3. RAG: check retrieved documents before they enter the prompt

Indirect injection hides instructions inside documents. Check each chunk.

```python
def safe_context(chunks: list[str]) -> list[str]:
    kept = []
    for chunk in chunks:
        verdict = guard.scan(chunk)
        if verdict["action"] == "ALLOW":
            kept.append(chunk)
        else:
            log_dropped_chunk(reasons=verdict["reasons"])   # never log the chunk text itself
    return kept
```

## 4. Agents: check tool inputs and tool results

```python
def run_tool(name: str, argument: str) -> str:
    guard.check(argument)                       # what the model asks the tool to do
    result = TOOLS[name](argument)
    guard.check(result)                         # what comes back (web pages, files, emails)
    return result
```

## 5. Shadow mode: see the effect without blocking

Run the gateway with `AI_SENTINEL_MODE=shadow`. Responses always say `ALLOW`, so read the truth from the extra field:

```python
verdict = guard.scan(user_text)
if verdict.get("would_have_blocked"):
    metrics.count("sentinel_would_block")
```

## 6. Async code

The client is synchronous; run it in a thread.

```python
import asyncio
verdict = await asyncio.to_thread(guard.scan, user_text)
```

## 7. Retry on rate limit

`SentinelError` hides the status code in its message. For simple back-off:

```python
import time
for attempt in range(3):
    try:
        guard.check(user_text); break
    except SentinelError as exc:
        if "429" in str(exc) and attempt < 2:
            time.sleep(2 ** attempt); continue
        raise
```

Without Python: call the endpoints in [API.md](API.md) directly, or give an AI agent [`openapi.json`](../openapi.json).
