from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ai_sentinel.core.shield import BioImmuneShield, ShieldVerdict

app = FastAPI(
    title="AI Sentinel Security Shield",
    description="Production-grade security shield powered by BioImmuneShield core engine.",
    version="1.0.0"
)

# Initialize the single decision point shield instance
shield = BioImmuneShield()

class InspectRequest(BaseModel):
    payload: str

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "ai-sentinel",
        "message": "AI Sentinel Security Shield is active"
    }

@app.post("/inspect", response_model=ShieldVerdict)
def inspect_payload(request: InspectRequest):
    try:
        verdict = shield.inspect_payload(request.payload)
        return verdict
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))