import os
import secrets
import base64
import logging
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield, ShieldVerdict

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Sentinel API Gateway",
    version="1.0.0",
    description="Enterprise-grade AI security gateway with authenticated inspection."
)

shield = SecurityShield(mode="moderate")
EXPECTED_API_KEY = os.environ.get("AI_SENTINEL_API_KEY", "test-api-key")

class ScanRequest(BaseModel):
    text: Optional[str] = None
    prompt: Optional[str] = None
    encoded_prompt: Optional[str] = None
    chunks: Optional[List[str]] = None
    session_id: Optional[str] = None

def verify_api_key(x_api_key: Optional[str] = Header(None)) -> str:
    if not EXPECTED_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Server misconfiguration: API key authentication is not configured."
        )
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
    return {
        "version": "1.0.0",
        "config_hash": "sha256-secured-placeholder"
    }

@app.post("/v1/scan")
def scan_endpoint(payload: ScanRequest, api_key: str = Depends(verify_api_key)):
    try:
        text_to_scan = payload.text or payload.prompt or ""
        if payload.encoded_prompt:
            text_to_scan += " " + payload.encoded_prompt

        verdict: ShieldVerdict = shield.inspect(text=text_to_scan, session_id=payload.session_id)
        
        is_flagged = verdict.flagged
        reasons = list(verdict.reason)
        max_risk = verdict.risk_score

        if payload.chunks:
            for idx, chunk in enumerate(payload.chunks):
                chunk_verdict = shield.inspect(text=chunk, session_id=payload.session_id)
                if chunk_verdict.flagged:
                    is_flagged = True
                    reasons.append(f"Chunk {idx}: threat detected")
                    max_risk = max(max_risk, chunk_verdict.risk_score)

        action = "BLOCK" if is_flagged else "ALLOW"

        return {
            "action": action,
            "flagged": is_flagged,
            "is_blocked": is_flagged,
            "reason": reasons,
            "block_threshold": verdict.block_threshold,
            "sanitized_text": "" if is_flagged else text_to_scan,
            "risk_score": max_risk
        }
    except Exception as e:
        logger.error("Error during scan: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal inspection error."
        )