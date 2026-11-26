"""Optional client for the sentinel-semantic service.

Enabled by setting SENTINEL_SEMANTIC_URL (e.g. http://sentinel-semantic:8100).
Uses only the standard library. If the service is unreachable or errors (network, timeout, 5xx),
analyze() returns None; the gateway then refuses to answer (503) unless fail-open was chosen on
purpose with SENTINEL_SEMANTIC_REQUIRED=false. If the service
REJECTS the input (HTTP 4xx, for example 422 for an over-long prompt) analyze() raises
SemanticRejected, because the text was never judged. Long prompts are analysed in overlapping
windows so an attack at the end is not cut off.
"""

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

log = logging.getLogger("ai_sentinel.semantic")

ANALYZE_PATH = "/api/v1/semantic/analyze"
WINDOW_CHARS = 4000
WINDOW_OVERLAP = 400
MAX_WINDOWS = 6


# Outcome of the most recent REAL analyze call. /ready uses it, so a semantic service whose /health says "ok"
# but whose analyses fail (HTTP 5xx, timeouts, garbage replies, a crashing classifier) is reported as not ready
# without sending an extra request to the model on every probe.
_LAST = {"ok": None, "at": 0.0}


def _note(ok: bool) -> None:
    _LAST["ok"], _LAST["at"] = ok, time.time()


def last_call_failed() -> bool:
    """True if the latest real analysis failed within SENTINEL_READY_FAILURE_TTL seconds (default 60)."""
    try:
        ttl = float(os.getenv("SENTINEL_READY_FAILURE_TTL", "60"))
    except ValueError:
        ttl = 60.0
    return _LAST["ok"] is False and (time.time() - _LAST["at"]) <= ttl


def reset_state() -> None:
    _LAST["ok"], _LAST["at"] = None, 0.0


class SemanticUnavailable(RuntimeError):
    """The semantic service could not be reached or failed, and the caller asked for strict behaviour."""


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
            result = json.loads(response.read().decode("utf-8"))
        _note(True)
        return result
    except urllib.error.HTTPError as exc:
        if 400 <= exc.code < 500 and exc.code not in (401, 403, 408, 429):
            _note(True)  # it answered; it refused this input
            raise SemanticRejected(f"HTTP {exc.code}") from exc
        _note(False)
        log.warning("semantic layer unavailable: HTTP %s", exc.code)  # includes auth/rate problems: operator issue
        return None
    except Exception as exc:  # returns None; the caller decides (fail closed by default when a layer is configured)
        _note(False)
        log.warning("semantic layer unavailable: %s", exc)
        return None


def probe() -> bool:
    """Is the configured semantic service answering its /health? (Used by /ready.)"""
    base = os.getenv("SENTINEL_SEMANTIC_URL")
    if not base:
        return True
    try:
        timeout = float(os.getenv("SENTINEL_SEMANTIC_TIMEOUT", "1.5"))
        with urllib.request.urlopen(base.rstrip("/") + "/health", timeout=timeout) as response:  # nosec B310
            return 200 <= response.status < 300
    except Exception:
        return False


def analyze(prompt: str, strict: bool = False) -> Optional[Dict[str, Any]]:
    """Analyse a prompt. Returns the most severe window's analysis, or None if the service is unavailable.

    strict=True (SENTINEL_SEMANTIC_REQUIRED): raise SemanticUnavailable instead of returning None, so the
    caller can refuse to answer rather than silently running without the layer that was configured."""
    base = os.getenv("SENTINEL_SEMANTIC_URL")
    if not base or not prompt:
        return None
    worst = None
    for window in _windows(prompt):
        analysis = _analyze_one(base, window)
        if analysis is None:
            if strict:
                raise SemanticUnavailable("semantic layer did not answer")
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
