"""
FastAPI API Gateway for AI Sentinel.

Request correlation IDs, security headers, a byte-counted payload limit, a per-API-key rate limit
(authenticated requests only; client addresses and proxy headers are never trusted) and an audit ledger.
"""

import base64
import hashlib
import hmac
import os
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ai_sentinel import semantic_client
from ai_sentinel.core.shield import SecurityShield

# Enforce API key check at module import time for fail-closed startup validation
API_KEY = os.getenv("AI_SENTINEL_API_KEY")
if not API_KEY or not API_KEY.strip():
  raise SystemExit("CRITICAL: AI_SENTINEL_API_KEY environment variable is mandatory and must not be blank.")

app = FastAPI(
    title="AI Sentinel API Gateway",
    description="Prompt-injection scanning gateway: rule shield plus optional semantic layer.",
    version="1.2.0",
)

# Initialize Security Shield with fail-closed configuration
BLOCK_THRESHOLD = float(os.getenv("AI_SENTINEL_BLOCK_THRESHOLD", "0.7"))
shield = SecurityShield(block_threshold=BLOCK_THRESHOLD)

# Traffic Control & Protection Constants
MAX_PAYLOAD_SIZE_BYTES = 16 * 1024  # 16 KB limit
RATE_LIMIT_MAX_REQUESTS = int(os.getenv("SENTINEL_RATE_LIMIT_MAX", "50"))  # raise for benchmarks
RATE_LIMIT_WINDOW_SECONDS = 60
_request_counts: Dict[str, list] = {}  # keyed by a hash of the API key, never by client address


class ScanRequest(BaseModel):
  prompt: Optional[str] = Field(None, description="The prompt or text payload to scan.")
  encoded_prompt: Optional[str] = Field(None, description="Base64 encoded prompt payload.")


def _log_audit_event(request_id: str, client_ip: str, prompt: str, action: str, risk_score: float, reasons: list) -> None:
  """Appends a structured audit event with correlation ID to audit_ledger.jsonl."""
  audit_entry = {
      "request_id": request_id,
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "client_ip": client_ip,
      "prompt_chars": len(prompt or ""),
      "prompt_sha256": hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()[:16],
      "action": action,
      "risk_score": risk_score,
      "reasons": reasons,
  }
  try:
    with open("audit_ledger.jsonl", "a", encoding="utf-8") as f:
      f.write(json.dumps(audit_entry) + "\n")
  except Exception:
    pass


class BodyTooLarge(BaseException):
  """Raised from the receive channel once more than MAX_PAYLOAD_SIZE_BYTES were actually read."""


class BodyLimitMiddleware:
  """Counts bytes actually received, so chunked bodies without Content-Length are limited too."""

  def __init__(self, app, max_bytes: int):
    self.app, self.max_bytes = app, max_bytes

  async def __call__(self, scope, receive, send):
    if scope["type"] != "http":
      return await self.app(scope, receive, send)
    total, started = 0, False

    async def counting_receive():
      nonlocal total
      message = await receive()
      if message["type"] == "http.request":
        total += len(message.get("body", b""))
        if total > self.max_bytes:
          raise BodyTooLarge()
      return message

    async def tracking_send(message):
      nonlocal started
      started = started or message["type"] == "http.response.start"
      await send(message)

    try:
      await self.app(scope, counting_receive, tracking_send)
    except BodyTooLarge:
      if not started:
        await JSONResponse(
            {"detail": "Payload size exceeds maximum allowed limit (16KB)."},
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        )(scope, receive, send)


app.add_middleware(BodyLimitMiddleware, max_bytes=MAX_PAYLOAD_SIZE_BYTES)


@app.middleware("http")
async def tracing_and_headers_middleware(request: Request, call_next):
  """Correlation ID, early Content-Length rejection and security headers."""
  request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
  request.state.request_id = request_id

  content_length = request.headers.get("content-length")
  if content_length and content_length.isdigit() and int(content_length) > MAX_PAYLOAD_SIZE_BYTES:
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={"detail": "Payload size exceeds maximum allowed limit (16KB)."},
        headers={"X-Request-ID": request_id},
    )

  response = await call_next(request)
  response.headers["X-Request-ID"] = request_id
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["Content-Security-Policy"] = "default-src 'none'"
  return response


def _key_is_valid(candidate: Optional[str]) -> bool:
  """Constant-time comparison; blank or missing keys are never valid."""
  if not candidate or not candidate.strip():
    return False
  return hmac.compare_digest(candidate.encode("utf-8"), API_KEY.encode("utf-8"))


def _rate_limited(api_key: str) -> bool:
  """Sliding window per API key. Called only after authentication, so unauthenticated traffic and /health
  cannot use up a caller's budget, and a spoofed X-Forwarded-For cannot create new budgets."""
  bucket = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
  now = time.time()
  timestamps = [t for t in _request_counts.get(bucket, []) if now - t < RATE_LIMIT_WINDOW_SECONDS]
  if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
    _request_counts[bucket] = timestamps
    return True
  timestamps.append(now)
  _request_counts[bucket] = timestamps
  return False


@app.get("/health")
def health_check() -> dict:
  """Health check endpoint matching expected status format."""
  return {"status": "ok"}


@app.post("/v1/scan")
def scan_prompt(payload: ScanRequest, request: Request, x_api_key: Optional[str] = Header(None)) -> dict:
  """Scans an incoming prompt payload for prompt injection and security violations."""
  if not _key_is_valid(x_api_key):
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key.")
  if _rate_limited(x_api_key):
    raise HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail="Rate limit exceeded. Please try again later.",
        headers={"X-Request-ID": getattr(request.state, "request_id", "unknown")},
    )

  request_id = getattr(request.state, "request_id", "unknown")

  # Resolve prompt from normal or base64 field if needed
  text_to_scan = payload.prompt
  if not text_to_scan and payload.encoded_prompt:
    try:
      text_to_scan = base64.b64decode(payload.encoded_prompt).decode("utf-8")
    except Exception:
      text_to_scan = ""

  if not text_to_scan:
    text_to_scan = ""

  client_ip = request.client.host if request.client else "unknown"

  # Run evaluation through SecurityShield
  verdict = shield.inspect(prompt=text_to_scan)

  action = verdict.action
  risk_score = verdict.risk_score
  reasons = list(verdict.reasons)

  # Optional semantic enrichment (sentinel-semantic). If the service is unreachable the rule-based verdict
  # stands on its own (fail open, by design). If it REJECTS the input (HTTP 4xx, e.g. 422) that is not
  # "unavailable": the text was never judged, so the request is blocked.
  semantic = None
  if semantic_client.semantic_enabled() and text_to_scan:
    try:
      analysis = semantic_client.analyze(text_to_scan)
    except semantic_client.SemanticRejected:
      analysis = None
      if action != "BLOCK":
        action = "BLOCK"
        risk_score = max(risk_score, BLOCK_THRESHOLD)
        reasons.append("Semantic layer rejected the input; blocked because it could not be judged")
    if analysis:
      semantic = semantic_client.summarize(analysis)
      if semantic["guardrail_profile"] == "maximum_security_block" and action != "BLOCK":
        action = "BLOCK"
        risk_score = max(risk_score, BLOCK_THRESHOLD)
        reasons.append("Semantic layer: potential jailbreak intent")

  # Log event with request tracing ID
  _log_audit_event(
      request_id=request_id,
      client_ip=client_ip,
      prompt=text_to_scan,
      action=action,
      risk_score=risk_score,
      reasons=reasons,
  )

  result = {
      "status": "blocked" if action == "BLOCK" else "allowed",
      "action": action,
      "risk_score": risk_score,
      "reasons": reasons,
  }
  if semantic is not None:
    result["semantic"] = semantic
  return result