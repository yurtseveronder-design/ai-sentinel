"""
FastAPI API Gateway for AI Sentinel.
Ultimate enterprise-grade variant featuring request correlation tracing,
security headers, rate limiting, payload constraints, and audit ledger integration.
"""

import os
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, Optional
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ai_sentinel.core.shield import SecurityShield

# Enforce API key check at module import time for fail-closed startup validation
API_KEY = os.getenv("AI_SENTINEL_API_KEY")
if not API_KEY:
  raise SystemExit("CRITICAL: AI_SENTINEL_API_KEY environment variable is mandatory.")

app = FastAPI(
    title="AI Sentinel API Gateway",
    description="Ultimate enterprise-grade secure routing and evaluation gateway for RAG pipelines.",
    version="1.2.0",
)

# Initialize Security Shield with fail-closed configuration
BLOCK_THRESHOLD = float(os.getenv("AI_SENTINEL_BLOCK_THRESHOLD", "0.7"))
shield = SecurityShield(block_threshold=BLOCK_THRESHOLD)

# Traffic Control & Protection Constants
MAX_PAYLOAD_SIZE_BYTES = 16 * 1024  # 16 KB limit
RATE_LIMIT_MAX_REQUESTS = 50
RATE_LIMIT_WINDOW_SECONDS = 60
_request_counts: Dict[str, list] = {}


class ScanRequest(BaseModel):
  prompt: Optional[str] = Field(None, description="The prompt or text payload to scan.")
  encoded_prompt: Optional[str] = Field(None, description="Base64 encoded prompt payload.")


def _log_audit_event(request_id: str, client_ip: str, prompt: str, action: str, risk_score: float, reasons: list) -> None:
  """Appends a structured audit event with correlation ID to audit_ledger.jsonl."""
  audit_entry = {
      "request_id": request_id,
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "client_ip": client_ip,
      "prompt_preview": (prompt[:100] if prompt else ""),
      "action": action,
      "risk_score": risk_score,
      "reasons": reasons,
  }
  try:
    with open("audit_ledger.jsonl", "a", encoding="utf-8") as f:
      f.write(json.dumps(audit_entry) + "\n")
  except Exception:
    pass


@app.middleware("http")
async def ultimate_enterprise_middleware(request: Request, call_next):
  """Bundled middleware for Correlation Tracing, Security Headers, Payload Size, and Rate Limiting."""
  client_ip = request.client.host if request.client else "unknown"

  # 1. Distributed Request Correlation Tracing
  request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))
  request.state.request_id = request_id

  # 2. Payload Size Control
  content_length = request.headers.get("content-length")
  if content_length and int(content_length) > MAX_PAYLOAD_SIZE_BYTES:
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={"detail": "Payload size exceeds maximum allowed limit (16KB)."},
        headers={"X-Request-ID": request_id}
    )

  # 3. Sliding-Window Rate Limiting
  now = time.time()
  timestamps = _request_counts.get(client_ip, [])
  timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]

  if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later."},
        headers={"X-Request-ID": request_id}
    )

  timestamps.append(now)
  _request_counts[client_ip] = timestamps

  response = await call_next(request)

  # 4. Inject Security Headers and Correlation ID into all responses
  response.headers["X-Request-ID"] = request_id
  response.headers["X-Content-Type-Options"] = "nosniff"
  response.headers["X-Frame-Options"] = "DENY"
  response.headers["Content-Security-Policy"] = "default-src 'none'"

  return response


@app.get("/health")
def health_check() -> dict:
  """Health check endpoint matching expected status format."""
  return {"status": "ok"}


@app.post("/v1/scan")
def scan_prompt(payload: ScanRequest, request: Request, x_api_key: Optional[str] = Header(None)) -> dict:
  """Scans an incoming prompt payload for prompt injection and security violations."""
  if not x_api_key or x_api_key != API_KEY:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API key.")

  request_id = getattr(request.state, "request_id", "unknown")

  # Resolve prompt from normal or base64 field if needed
  text_to_scan = payload.prompt
  if not text_to_scan and payload.encoded_prompt:
    import base64
    try:
      text_to_scan = base64.b64decode(payload.encoded_prompt).decode("utf-8")
    except Exception:
      text_to_scan = ""

  if not text_to_scan:
    text_to_scan = ""

  client_ip = request.client.host if request.client else "unknown"

  # Run evaluation through SecurityShield
  verdict = shield.inspect(prompt=text_to_scan)

  # Log event with request tracing ID
  _log_audit_event(
      request_id=request_id,
      client_ip=client_ip,
      prompt=text_to_scan,
      action=verdict.action,
      risk_score=verdict.risk_score,
      reasons=verdict.reasons,
  )

  return {
      "status": "blocked" if verdict.action == "BLOCK" else "allowed",
      "action": verdict.action,
      "risk_score": verdict.risk_score,
      "reasons": verdict.reasons,
  }