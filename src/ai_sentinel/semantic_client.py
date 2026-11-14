"""Optional client for the sentinel-semantic service.

Enabled by setting SENTINEL_SEMANTIC_URL (e.g. http://sentinel-semantic:8100).
Uses only the standard library. If the service is unreachable or errors (network, timeout, 5xx),
analyze() returns None and the gateway keeps its rule-based verdict (fail open). If the service
REJECTS the input (HTTP 4xx, for example 422 for an over-long prompt) analyze() raises
SemanticRejected, because the text was never judged. Long prompts are analysed in overlapping
windows so an attack at the end is not cut off.
"""

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

log = logging.getLogger("ai_sentinel.semantic")

ANALYZE_PATH = "/api/v1/semantic/analyze"
WINDOW_CHARS = 4000
WINDOW_OVERLAP = 400
MAX_WINDOWS = 6


class SemanticRejected(RuntimeError):
    """sentinel-semantic answered with a 4xx: the input was refused, not judged."""


def _windows(text: str):
    if len(text) <= WINDOW_CHARS:
        return [text]
    step = WINDOW_CHARS - WINDOW_OVERLAP
    return [text[i:i + WINDOW_CHARS] for i in range(0, len(text), step)][:MAX_WINDOWS]


def semantic_enabled() -> bool:
    return bool(os.getenv("SENTINEL_SEMANTIC_URL"))


def _analyze_one(base: str, prompt: str) -> Optional[Dict[str, Any]]:
    headers = {"Content-Type": "application/json"}
    key = os.getenv("SENTINEL_SEMANTIC_API_KEY")
    if key:
        headers["X-API-Key"] = key
    timeout = float(os.getenv("SENTINEL_SEMANTIC_TIMEOUT", "1.5"))
    request = urllib.request.Request(
        base.rstrip("/") + ANALYZE_PATH,
        data=json.dumps({"prompt": prompt}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - URL comes from operator config
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (401, 403, 408, 429):
            raise SemanticRejected(f"HTTP {exc.code}") from exc
        log.warning("semantic layer unavailable: HTTP %s", exc.code)  # includes auth/rate problems: operator issue
        return None
    except Exception as exc:  # fail open by design
        log.warning("semantic layer unavailable: %s", exc)
        return None


def analyze(prompt: str) -> Optional[Dict[str, Any]]:
    """Analyse a prompt. Returns the most severe window's analysis, or None if the service is unavailable."""
    base = os.getenv("SENTINEL_SEMANTIC_URL")
    if not base or not prompt:
        return None
    worst = None
    for window in _windows(prompt):
        analysis = _analyze_one(base, window)
        if analysis is None:
            return worst  # keep what we learned; the service went away mid-way
        if worst is None:
            worst = analysis
        if analysis.get("route", {}).get("guardrail_profile") == "maximum_security_block":
            return analysis
    return worst


def summarize(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """The subset of the analysis that is safe and useful to return to callers."""
    route = analysis.get("route", {})
    return {
        "intent": route.get("primary_intent"),
        "guardrail_profile": route.get("guardrail_profile"),
        "requires_rag": route.get("requires_rag"),
        "sensitivity_tags": route.get("sensitivity_tags", []),
        "filters": analysis.get("vector_db_filter", {}),
        "engine": analysis.get("engine"),
    }
