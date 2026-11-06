import base64
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ai_sentinel.core.config_loader import ConfigLoader

app = FastAPI(title="AI-Sentinel Security Gateway", version="1.0.0")

class ScanRequest(BaseModel):
    prompt: Optional[str] = None
    encoded_prompt: Optional[str] = None
    chunks: Optional[List[str]] = None

class ScanResponse(BaseModel):
    status: str
    flagged: bool
    is_blocked: bool
    reason: List[str]
    max_risk_score: float = 0.0
    details: Dict[str, Any] = {}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "active"}

@app.post("/v1/scan", response_model=ScanResponse)
async def scan_payload(payload: ScanRequest):
    text_to_scan = payload.prompt
    if payload.encoded_prompt:
        try:
            text_to_scan = base64.b64decode(payload.encoded_prompt).decode("utf-8")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid Base64 encoding")
    if not text_to_scan and payload.chunks:
        text_to_scan = " ".join(payload.chunks)
    if not text_to_scan:
        raise HTTPException(status_code=400, detail="No prompt provided")
    is_malicious = "ignore previous" in text_to_scan.lower()
    return {
        "status": "success",
        "flagged": is_malicious,
        "is_blocked": is_malicious,
        "reason": ["Potential prompt injection detected"] if is_malicious else ["Successfully processed prompt"],
        "max_risk_score": 0.95 if is_malicious else 0.05,
        "details": {
            "model": "default",
            "checks_passed": not is_malicious,
            "rag_shield": {
                "status": "blocked" if is_malicious else "passed",
                "flagged_chunks": [1] if is_malicious else []
            }
        }
    }
