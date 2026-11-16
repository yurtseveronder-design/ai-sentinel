"""Small client so an application can write `guard.check(prompt)` instead of raw HTTP. Standard library only.

    from ai_sentinel.client import SentinelClient, PromptBlocked
    guard = SentinelClient("http://localhost:8000", api_key="...")
    guard.check(user_text)            # raises PromptBlocked if the gateway says BLOCK
    verdict = guard.scan(user_text)   # full response dict, never raises on BLOCK
    answer = guard.redact_output(model_answer)   # raises on secrets, masks personal data
"""

import json
import urllib.error
import urllib.request
from typing import Optional


class SentinelError(RuntimeError):
    """The gateway could not give a verdict (unreachable, auth error, bad response)."""


class PromptBlocked(Exception):
    def __init__(self, verdict: dict):
        super().__init__("; ".join(verdict.get("reasons") or ["blocked"]))
        self.verdict = verdict


class SentinelClient:
    def __init__(self, base_url: str, api_key: str, timeout: float = 5.0):
        self.base_url, self.api_key, self.timeout = base_url.rstrip("/"), api_key, timeout

    def _post(self, path: str, payload: dict) -> dict:
        req = urllib.request.Request(
            self.base_url + path, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Content-Type": "application/json", "X-API-Key": self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise SentinelError(f"gateway returned HTTP {exc.code}") from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise SentinelError(f"gateway unavailable: {exc}") from exc

    def scan(self, prompt: str) -> dict:
        return self._post("/v1/scan", {"prompt": prompt})

    def check(self, prompt: str) -> dict:
        """Returns the verdict if the prompt may go on; raises PromptBlocked otherwise. Fails closed on errors."""
        verdict = self.scan(prompt)
        if verdict.get("action") == "BLOCK":
            raise PromptBlocked(verdict)
        return verdict

    def scan_output(self, text: str) -> dict:
        return self._post("/v1/scan-output", {"text": text})

    def redact_output(self, text: str) -> str:
        """Returns the answer with personal data masked; raises PromptBlocked if it leaks a secret."""
        result = self.scan_output(text)
        if result.get("action") == "BLOCK":
            raise PromptBlocked(result)
        return result.get("redacted_text", text)
