import time
import threading
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List
from ai_sentinel.core.shield import BioImmuneShield

app = FastAPI(
    title="AI-Sentinel API Gateway",
    description="Lightweight educational input inspection and RAG security proxy prototype.",
    version="0.1.0"
)

shield = BioImmuneShield(mode="moderate")

# In-memory rate limiter state (Token bucket / sliding window per IP)
RATE_LIMIT_WINDOW = 60  # seconds
MAX_REQUESTS_PER_WINDOW = 60
request_counts = {}
rate_lock = threading.Lock()

def check_rate_limit(client_ip: str) -> bool:
    now = time.time()
    with rate_lock:
        if client_ip not in request_counts:
            request_counts[client_ip] = []
        
        # Filter timestamps within current window
        window_start = now - RATE_LIMIT_WINDOW
        request_counts[client_ip] = [t for t in request_counts[client_ip] if t > window_start]
        
        if len(request_counts[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
            return False
        
        request_counts[client_ip].append(now)
        return True

class InspectionRequest(BaseModel):
    prompt: str = Field(..., description="Raw user prompt to inspect")
    session_id: Optional[str] = Field(None, description="Optional tracking session ID")

class InspectionResponse(BaseModel):
    action: str
    confidence: float
    risk_score: float
    sanitized_text: str
    matched_rules: List[str]
    reason: str
    session_id: Optional[str] = None
    cumulative_risk: Optional[float] = None

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if request.url.path.startswith("/v1/inspect"):
        if not check_rate_limit(client_ip):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded. Too many inspection requests."}
            )
    response = await call_next(request)
    return response

@app.post("/v1/inspect", response_model=InspectionResponse)
async def inspect_prompt(payload: InspectionRequest):
    try:
        verdict = shield.inspect(payload.prompt, session_id=payload.session_id)
        return InspectionResponse(
            action=verdict.action,
            confidence=verdict.confidence,
            risk_score=verdict.risk_score,
            sanitized_text=verdict.sanitized_text,
            matched_rules=verdict.matched_rules,
            reason=verdict.reason,
            session_id=verdict.session_id,
            cumulative_risk=verdict.cumulative_risk
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "ai-sentinel-gateway"}