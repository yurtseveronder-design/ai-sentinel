import time
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentinel_core.shield import BioImmuneShield
from scripts.production_telemetry import GuardrailTelemetry

app = FastAPI(title="AI Sentinel Guardrail API", version="1.0.0")
shield = BioImmuneShield()
telemetry = GuardrailTelemetry()

class ScanRequest(BaseModel):
    prompt: str

class ScanResponse(BaseModel):
    safe: bool
    threat_pattern: str | None = None
    confidence: float
    latency_ms: float

@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "ai-sentinel"}

@app.post("/api/v1/scan", response_model=ScanResponse)
def scan_prompt(payload: ScanRequest):
    start_time = time.perf_counter()
    result = shield.scan(payload.prompt)
    latency_ms = round((time.perf_counter() - start_time) * 1000, 3)
    
    telemetry.log_scan(
        input_text=payload.prompt,
        scan_result=result,
        latency_ms=latency_ms
    )
    
    return {
        "safe": result["safe"],
        "threat_pattern": result.get("threat_pattern"),
        "confidence": result["confidence"],
        "latency_ms": latency_ms
    }
