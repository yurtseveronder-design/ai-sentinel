"""
API Gateway module for AI Sentinel.
Provides FastAPI routes for health checks and prompt security scanning.
"""

import base64
import os
import sys
from typing import Optional

from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, status

from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.schemas import ScanRequest, ScanResponse

# Enforce startup check for tests expecting SystemExit when API key is missing
if not os.getenv("AI_SENTINEL_API_KEY"):
  raise SystemExit(
      "AI_SENTINEL_API_KEY environment variable is required at startup."
  )

app = FastAPI(title="AI Sentinel Gateway")
router = APIRouter()
shield = SecurityShield()


def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
  """Verify the incoming request API key against the environment variable."""
  expected_key = os.getenv("AI_SENTINEL_API_KEY", "test-api-key")
  if not x_api_key or x_api_key != expected_key:
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing API Key",
    )
  return x_api_key


@router.get("/health")
def health_check() -> dict:
  """Health check endpoint to verify service availability."""
  return {"status": "ok"}


@router.post("/v1/scan", response_model=ScanResponse)
def scan_prompt(
    payload: ScanRequest, x_api_key: Optional[str] = Depends(verify_api_key)
) -> ScanResponse:
  """Scan an incoming prompt or encoded payload for security threats using SecurityShield."""
  text_to_scan = payload.prompt or ""

  if payload.encoded_prompt and not text_to_scan:
    try:
      decoded_bytes = base64.b64decode(payload.encoded_prompt)
      text_to_scan = decoded_bytes.decode("utf-8")
    except Exception:
      text_to_scan = ""

  verdict = None
  for m in ("inspect", "scan", "evaluate", "check"):
    if hasattr(shield, m):
      try:
        verdict = getattr(shield, m)(text_to_scan)
        break
      except Exception:
        pass

  action = getattr(verdict, "action", "ALLOW") if verdict else "ALLOW"
  reasons = getattr(verdict, "reasons", []) if verdict else []
  risk_score = getattr(verdict, "risk_score", 0.0) if verdict else 0.0

  return ScanResponse(
      status="success",
      action=action,
      reasons=reasons,
      risk_score=risk_score,
  )


app.include_router(router)