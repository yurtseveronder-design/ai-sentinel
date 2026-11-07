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

API_KEY_NAME = "X-API-Key"
API_KEY_VALUE = os.environ.get("AI_SENTINEL_API_KEY", "test-api-key")
MAX_INPUT_CHARS = 32000

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

def get_api_key(api_key_header: str = Security(api_key_header)):
    if not api_key_header:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="API Key missing")
    if not secrets.compare_digest(api_key_header, API_KEY_VALUE):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API Key")
    return api_key_header

app = FastAPI(title="AI Sentinel Gateway")
shield = SecurityShield(max_input_chars=MAX_INPUT_CHARS)

class ScanRequest(BaseModel):
    prompt: Optional[str] = Field(None, description="The user prompt to scan")
    text: Optional[str] = Field(None, description="Optional text context")
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
        primary_text = request.prompt or ""
        if request.text:
            primary_text = f"{primary_text} {request.text}".strip() if primary_text else request.text

        if not primary_text and not request.encoded_prompt:
            raise HTTPException(status_code=400, detail="Prompt or text content is required")

        total_size = len(primary_text)
        if request.encoded_prompt:
            total_size += len(request.encoded_prompt)
            
        if total_size > MAX_INPUT_CHARS:
            raise HTTPException(status_code=413, detail="Payload Too Large")

        verdict = shield.inspect(
            text=primary_text,
            encoded_prompt=request.encoded_prompt
        )
        
        reasons = verdict.reason
        if verdict.action == "BLOCK":
            reasons = [r for r in reasons if r.lower() != "input safe"]
            if not reasons:
                reasons = ["Adversarial pattern detected"]

        return ScanResponse(
            action=verdict.action,
            risk_score=verdict.risk_score,
            reasons=reasons
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Scanner error: {str(e)}")
        raise HTTPException(status_code=500, detail="Internal scanner error")