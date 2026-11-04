from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict
import time

app = FastAPI(
    title="AI Sentinel Security Shield",
    description="Production-grade security shield powered by BioImmuneShield core engine.",
    version="1.1.0"
)

# Initialize the single decision point shield instance
shield = BioImmuneShield()

class InspectRequest(BaseModel):
    text: str

@app.middleware("http")
async def security_telemetry_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Process-Time"] = str(round(process_time, 4))
    response.headers["X-Shield-Engine"] = "BioImmuneShield-v1.1"
    return response

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "ai-sentinel",
        "message": "AI Sentinel Security Shield is active with expanded threat detection"
    }

@app.post("/inspect", response_model=ShieldVerdict)
def inspect_payload(request: InspectRequest):
    try:
        # Single decision point invocation
        verdict = shield.inspect_payload(request.text)
        return verdict
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))