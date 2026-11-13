"""Optional client for the sentinel-semantic service.

Enabled by setting SENTINEL_SEMANTIC_URL (e.g. http://sentinel-semantic:8100).
Uses only the standard library and fails open: any error returns None so the
gateway keeps working on its own rule-based verdict.
"""

import json
import logging
import os
import urllib.request
from typing import Any, Dict, Optional

log = logging.getLogger("ai_sentinel.semantic")

ANALYZE_PATH = "/api/v1/semantic/analyze"


def semantic_enabled() -> bool:
    return bool(os.getenv("SENTINEL_SEMANTIC_URL"))


def analyze(prompt: str) -> Optional[Dict[str, Any]]:
    """Return the semantic analysis for a prompt, or None if unavailable."""
    base = os.getenv("SENTINEL_SEMANTIC_URL")
    if not base or not prompt:
        return None
    headers = {"Content-Type": "application/json"}
    key = os.getenv("SENTINEL_SEMANTIC_API_KEY")
    if key:
        headers["X-API-Key"] = key
    timeout = float(os.getenv("SENTINEL_SEMANTIC_TIMEOUT", "1.5"))
    request = urllib.request.Request(
        base.rstrip("/") + ANALYZE_PATH,
        data=json.dumps({"prompt": prompt[:8000]}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - URL comes from operator config
            return json.loads(response.read().decode("utf-8"))
    except Exception as exc:  # fail open by design
        log.warning("semantic layer unavailable: %s", exc)
        return None


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
