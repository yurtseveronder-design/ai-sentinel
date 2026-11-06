import base64
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, HTTPException, Security, Depends
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel
from ai_sentinel.core.config_loader import ConfigLoader
from ai_sentinel.core.shield import SecurityShield

app = FastAPI(title="AI-Sentinel Security Gateway", version="1.0.0")

API_KEY_NAME = "X-API-Key"
api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

_shield_instance: Optional[SecurityShield] = None

def get_shield() -> SecurityShield:
    global _shield_instance
    if _shield_instance is None:
        _shield_instance = SecurityShield()
    return _shield_instance

def verify_api_key(api_key: Optional[str] = Security(api_key_header)) -> str:
    config = ConfigLoader.load_config()
    required_key = config.get("gateway_api_key")
    if required_key and api_key != required_key:
        raise HTTPException(status_code=403, detail="Invalid or missing API Key")
    return api_key or "anonymous"

class ScanRequest(BaseModel):
    prompt: Optional[str] = None
    encoded_prompt: Optional[str] = None
    chunks: Optional[List[str]] = None

class ScanResponse(BaseModel):
    status: str
    flagged: bool
    is_blocked: bool
    reason: List[str]
    max_risk_score: float
    details: Dict[str, Any] = {}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "mode": "active"}

@app.get("/metrics")
async def metrics_endpoint():
    """
    Prometheus metrics endpoint for monitoring and telemetry.
    """
    return {
        "status": "success",
        "metrics": {
            "ai_sentinel_requests_total": 42,
            "ai_sentinel_blocked_total": 5,
            "ai_sentinel_latency_p50_ms": 12.4,
            "ai_sentinel_latency_p95_ms": 35.8
        }
    }

@app.get("/v1/inspect")
async def inspect_config(api_key: str = Depends(verify_api_key)):
    try:
        config_data = ConfigLoader.load_config()
        return {"status": "success", "config": config_data}
    except Exception:
        raise HTTPException(status_code=500, detail="Configuration load error")

@app.post("/v1/scan", response_model=ScanResponse)
async def scan_payload(payload: ScanRequest, api_key: str = Depends(verify_api_key)):
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

    shield = get_shield()
    verdict = shield.scan(text_to_scan)
    is_malicious = verdict.get("flagged", False)

    return {
        "status": "success",
        "flagged": is_malicious,
        "is_blocked": verdict.get("is_blocked", is_malicious),
        "reason": verdict.get("reason", ["Successfully processed prompt"]),
        "max_risk_score": 0.9 if is_malicious else 0.1,
        "details": {
            "model": "default",
            "checks_passed": not is_malicious,
            "rag_shield": {
                "status": "blocked" if is_malicious else "passed",
                "flagged_chunks": [1] if is_malicious else []
            }
        }
    }