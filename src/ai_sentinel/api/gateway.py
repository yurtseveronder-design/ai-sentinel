import os
import secrets
import logging
from typing import Optional, Dict, Any, List
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
    text: Optional[str] = None
    prompt: Optional[str] = None
    encoded_prompt: Optional[str] = None
    chunks: Optional[List[str]] = None
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
    Secured scanning endpoint via the core security shield product path with input size checks and comprehensive RAG chunk scanning.
    """
    # Collect all text fields and chunks to evaluate total input size
    all_texts = [payload.text, payload.prompt, payload.encoded_prompt]
    if payload.chunks:
        all_texts.extend(payload.chunks)
    
    combined_input = " ".join([t for t in all_texts if t]).strip()
    if len(combined_input) > 32000:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Input size exceeds maximum allowed limit of 32,000 characters."
        )
    
    # Gather all components to inspect (prompts, text, and every individual RAG chunk)
    texts_to_inspect = []
    if payload.text:
        texts_to_inspect.append(payload.text)
    if payload.prompt:
        texts_to_inspect.append(payload.prompt)
    if payload.encoded_prompt:
        texts_to_inspect.append(payload.encoded_prompt)
    if payload.chunks:
        texts_to_inspect.extend(payload.chunks)

    if not texts_to_inspect:
        texts_to_inspect = [""]

    try:
        overall_flagged = False
        max_risk = 0.0
        all_reasons = []
        sanitized_texts = []

        # Inspect each text and chunk individually to catch hidden prompt injections in RAG data
        for t in texts_to_inspect:
            verdict: ShieldVerdict = shield.inspect(
                text=t, 
                session_id=payload.session_id,
                encoded_prompt=payload.encoded_prompt
            )
            if verdict.flagged:
                overall_flagged = True
            max_risk = max(max_risk, verdict.risk_score)
            if verdict.reason:
                all_reasons.extend(verdict.reason)
            if verdict.sanitized_text:
                sanitized_texts.append(verdict.sanitized_text)

        if not all_reasons:
            all_reasons = ["Input safe"]

        action = "BLOCK" if overall_flagged else "ALLOW"

        return {
            "action": action,
            "flagged": overall_flagged,
            "is_blocked": overall_flagged,
            "reason": list(set(all_reasons)),
            "block_threshold": shield.block_threshold,
            "sanitized_text": " ".join(sanitized_texts),
            "risk_score": max_risk
        }
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error("Error during secure scan: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal inspection error."
        )