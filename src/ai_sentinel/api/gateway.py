import os
import secrets
import logging
from typing import Optional, Dict, Any
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield, ShieldVerdict

logger = logging.getLogger(__name__)

# Load API Key securely from environment variable
EXPECTED_API_KEY = os.environ.get("AI_SENTINEL_API_KEY")

# STRICT FAIL-SAFE: Crash immediately at startup if not configured
if not EXPECTED_API_KEY:
    raise ValueError("Critical startup failure: AI_SENTINEL_API_KEY environment variable is missing.")

app = FastAPI(
    title="AI Sentinel API Gateway",
    version="1.0.0",
    description="Enterprise-grade AI security gateway with authenticated inspection."
)

# Initialize single secure shield instance
shield = SecurityShield(mode="moderate")

class ScanRequest(BaseModel):
    text: str
    session_id: Optional[str] = None

def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    """
    Validates the incoming API key against AI_SENTINEL_API_KEY using constant-time comparison.
    """
    if not x_api_key or not secrets.compare_digest(x_api_key, EXPECTED_API_KEY):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key."
        )
    return x_api_key

@app.get("/health")
def health_check():
    return {"status": "healthy", "version": "1.0.0"}

@app.get("/v1/inspect")
def inspect_config(api_key: str = Depends(verify_api_key)):
    """
    Returns only version and config hash, protecting signature text from exposure.
    """
    return {
        "version": "1.0.0",
        "config_hash": "sha256-secured-placeholder"
    }

@app.post("/v1/scan")
def scan_endpoint(payload: ScanRequest, api_key: str = Depends(verify_api_key)):
    """
    Secured scanning endpoint via the core security shield product path.
    """
    try:
        verdict: ShieldVerdict = shield.inspect(text=payload.text, session_id=payload.session_id)
        return {
            "action": verdict.action,
            "flagged": verdict.flagged,
            "reason": verdict.reason,
            "block_threshold": verdict.block_threshold,
            "sanitized_text": verdict.sanitized_text,
            "risk_score": verdict.risk_score
        }
    except Exception as e:
        logger.error("Error during secure scan: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal inspection error."
        )