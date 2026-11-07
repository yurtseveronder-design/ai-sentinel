import os
import secrets
import base64
import logging
import re
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Header, HTTPException, Depends, status
from pydantic import BaseModel

from ai_sentinel.core.shield import SecurityShield, ShieldVerdict
from ai_sentinel.core.audit import AuditLogger, SessionRiskEngine

logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Sentinel API Gateway",
    version="1.0.0",
    description="Enterprise-grade AI security gateway with authenticated inspection and cryptographic auditing."
)

shield = SecurityShield(mode="moderate")
audit_logger = AuditLogger()
session_engine = SessionRiskEngine()

# Task 2: Eliminate default fallback key and enforce strict environment variable requirement
EXPECTED_API_KEY = os.environ.get("AI_SENTINEL_API_KEY")
if not EXPECTED_API_KEY:
    raise RuntimeError("Critical startup failure: AI_SENTINEL_API_KEY environment variable is not set.")

MAX_INPUT_CHARS = 32000

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
        
        # Enforce input size limit (HTTP 413 Payload Too Large)
        total_len = len(text_to_scan)
        if payload.chunks:
            total_len += sum(len(c) for c in payload.chunks)
            
        if total_len > MAX_INPUT_CHARS:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Input size exceeds maximum allowed limit of {MAX_INPUT_CHARS} characters."
            )

        # Strict Token-by-Token Base64 Inspection
        if payload.encoded_prompt:
            b64_pattern = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')
            tokens = payload.encoded_prompt.split()
            decoded_additions = []
            
            for token in tokens:
                if b64_pattern.match(token):
                    try:
                        padded = token + '=' * (-len(token) % 4)
                        decoded_bytes = base64.b64decode(padded, validate=True)
                        decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                        if decoded_str.strip():
                            decoded_additions.append(decoded_str)
                    except Exception as e:
                        logger.debug(f"Base64 token decode failed securely: {e}")
            
            if decoded_additions:
                text_to_scan += " " + " ".join(decoded_additions)

        # Scan the main prompt first
        verdict: ShieldVerdict = shield.inspect(text=text_to_scan, session_id=payload.session_id)
        
        is_flagged = verdict.flagged
        reasons = list(verdict.reason)
        max_risk = verdict.risk_score
        flagged_chunk_indices = []

        # Explicitly scan EVERY chunk independently
        if payload.chunks:
            for idx, chunk in enumerate(payload.chunks):
                if len(chunk) > MAX_INPUT_CHARS:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Chunk {idx} exceeds maximum allowed limit."
                    )
                chunk_verdict = shield.inspect(text=chunk, session_id=payload.session_id)
                if chunk_verdict.flagged:
                    is_flagged = True
                    flagged_chunk_indices.append(idx)
                    reasons.append(f"Chunk {idx}: threat detected")
                    max_risk = max(max_risk, chunk_verdict.risk_score)

        action = "BLOCK" if is_flagged else "ALLOW"

        # Apply Session Risk Decay & JSON-Lines Audit Logging
        cumulative_risk = max_risk
        if payload.session_id:
            cumulative_risk = session_engine.update_and_get_risk(payload.session_id, max_risk)

        audit_logger.log_event(
            session_id=payload.session_id,
            text=text_to_scan,
            action=action,
            risk_score=cumulative_risk,
            reasons=reasons
        )

        response_data = {
            "action": action,
            "flagged": is_flagged,
            "is_blocked": is_flagged,
            "reason": reasons,
            "block_threshold": verdict.block_threshold,
            "sanitized_text": "" if is_flagged else text_to_scan,
            "risk_score": cumulative_risk
        }
        
        if payload.chunks:
            response_data["flagged_chunks"] = flagged_chunk_indices

        return response_data

    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error("Error during scan: %s", e, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal inspection error."
        )