"""
FastAPI API Gateway for AI Sentinel.
Production-grade enterprise variant featuring rate limiting, payload size constraints,
and structured audit ledger integration.
"""

import os
import json
import time
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
    description="Production-grade secure routing and evaluation gateway for RAG pipelines.",
    version="1.1.0",
)

# Initialize Security Shield with fail-closed configuration
BLOCK_THRESHOLD = float(os.getenv("AI_SENTINEL_BLOCK_THRESHOLD", "0.7"))
shield = SecurityShield(block_threshold=BLOCK_THRESHOLD)

# Traffic Control & Cost Protection Constants
MAX_PAYLOAD_SIZE_BYTES = 16 * 1024  # 16 KB limit to prevent resource exhaustion
RATE_LIMIT_MAX_REQUESTS = 50        # Max requests per window
RATE_LIMIT_WINDOW_SECONDS = 60      # Window size in seconds
_request_counts: Dict[str, list] = {}


class ScanRequest(BaseModel):
  prompt: Optional[str] = Field(None, description="The prompt or text payload to scan.")
  encoded_prompt: Optional[str] = Field(None, description="Base64 encoded prompt payload.")


def _log_audit_event(client_ip: str, prompt: str, action: str, risk_score: float, reasons: list) -> None:
  """Appends a structured audit event to audit_ledger.jsonl."""
  audit_entry = {
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
async def enterprise_gateway_middleware(request: Request, call_next):
  """Bundled middleware for Payload Size Protection and Sliding-Window Rate Limiting."""
  client_ip = request.client.host if request.client else "unknown"

  # 1. Payload Size Control (Cost & Resource Protection)
  content_length = request.headers.get("content-length")
  if content_length and int(content_length) > MAX_PAYLOAD_SIZE_BYTES:
    return JSONResponse(
        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        content={"detail": "Payload size exceeds maximum allowed limit (16KB)."}
    )

  # 2. Sliding-Window Rate Limiting (Traffic Control)
  now = time.time()
  timestamps = _request_counts.get(client_ip, [])
  timestamps = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW_SECONDS]

  if len(timestamps) >= RATE_LIMIT_MAX_REQUESTS:
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Rate limit exceeded. Please try again later."}
    )

  timestamps.append(now)
  _request_counts[client_ip] = timestamps

  response = await call_next(request)
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

  # Log event to audit ledger
  _log_audit_event(
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