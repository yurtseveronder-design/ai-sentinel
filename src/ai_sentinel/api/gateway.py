import os
import sys
import logging
import secrets
from fastapi import FastAPI, Depends, HTTPException, status, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel, Field
from typing import Optional, List
from ai_sentinel.core.shield import SecurityShield

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 1. Strict Startup Check: Fail if API key is missing. No default fallbacks.
API_KEY_NAME = "X-API-Key"
API_KEY_VALUE = os.environ.get("AI_SENTINEL_API_KEY")

if not API_KEY_VALUE:
    logger.error("CRITICAL STARTUP FAILURE: AI_SENTINEL_API_KEY environment variable is not set.")
    sys.exit(1)

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Security(api_key_header)):
    if not api_key_header:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API Key missing",
        )
    # Constant-time comparison to prevent timing attacks
    if not secrets.compare_digest(api_key_header, API_KEY_VALUE):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API Key",
        )
    return api_key_header

app = FastAPI(title="AI Sentinel Gateway")

# Initialize shield (will strictly fail if config is missing due to Task 1)
shield = SecurityShield(mode="moderate")

class ScanRequest(BaseModel):
    prompt: str = Field(..., description="The user prompt to scan")
    text: Optional[str] = Field(None, description="Optional text context")
    session_id: Optional[str] = None
    encoded_prompt: Optional[str] = None

class ScanResponse(BaseModel):
    action: str
    risk_score: float
    reasons: List[str]

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.post("/v1/scan", response_model=ScanResponse, dependencies=[Depends(get_api_key)])
def scan_prompt(request: ScanRequest):
    try:
        verdict = shield.inspect(
            text=request.prompt,
            session_id=request.session_id,
            encoded_prompt=request.encoded_prompt
        )
        return ScanResponse(
            action=verdict.action,
            risk_score=verdict.risk_score,
            reasons=verdict.reason
        )
    except Exception as e:
        logger.error(f"Scanner error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal scanner error")