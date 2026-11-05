from fastapi import FastAPI, Request, Response, HTTPException
from pydantic import BaseModel
from typing import Optional
import time
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from ai_sentinel.core.shield import BioImmuneShield

app = FastAPI(title="BioImmuneShield AI Gateway", version="1.0.0")

# Initialize shield instance (default moderate mode)
shield = BioImmuneShield(mode="moderate")

# Prometheus Metrics Instrumentation
REQUEST_COUNT = Counter("sentinel_requests_total", "Total requests inspected", ["action", "mode"])
REQUEST_LATENCY = Histogram("sentinel_request_latency_seconds", "Inspection latency in seconds")
THREAT_COUNTER = Counter("sentinel_threats_detected_total", "Total threats caught", ["rule"])

class PromptRequest(BaseModel):
    prompt: str
    session_id: Optional[str] = None

@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    REQUEST_LATENCY.observe(duration)
    return response

@app.post("/v1/inspect")
async def inspect_endpoint(payload: PromptRequest, response: Response):
    start_time = time.time()
    
    # Inspect payload through BioImmuneShield
    verdict = shield.inspect_payload(payload.prompt, session_id=payload.session_id)
    
    # Record Prometheus telemetry
    REQUEST_COUNT.labels(action=verdict.action, mode=shield.mode).inc()
    for rule in verdict.matched_rules:
        THREAT_COUNTER.labels(rule=rule).inc()

    # Set custom gateway headers
    response.headers["X-Shield-Verdict"] = verdict.action
    response.headers["X-Risk-Score"] = str(verdict.risk_score)
    if verdict.session_id:
        response.headers["X-Session-ID"] = verdict.session_id
    if verdict.cumulative_risk is not None:
        response.headers["X-Cumulative-Risk"] = str(verdict.cumulative_risk)

    if verdict.action == "BLOCK":
        raise HTTPException(
            status_code=403, 
            detail={
                "error": "Request blocked by BioImmuneShield",
                "reason": verdict.reason,
                "matched_rules": verdict.matched_rules
            }
        )

    return {
        "action": verdict.action,
        "confidence": verdict.confidence,
        "risk_score": verdict.risk_score,
        "sanitized_text": verdict.sanitized_text,
        "matched_rules": verdict.matched_rules,
        "reason": verdict.reason
    }

@app.get("/metrics")
async def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)