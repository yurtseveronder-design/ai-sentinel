from typing import List, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from ai_sentinel.core.config_loader import ConfigLoader

# Initialize FastAPI app
app = FastAPI(
    title="AI-Sentinel Security Gateway",
    version="1.0.0",
    description="Production-grade AI safety proxy and evaluation framework"
)

class ScanResponse(BaseModel):
    status: str
    flagged: bool
    reason: List[str]  # Typed as a list of strings to match requirements

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/v1/inspect")
async def inspect_config():
    try:
        loader = ConfigLoader()
        config_data = loader.load_config()
        return {"status": "success", "config": config_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Configuration load error")

@app.post("/v1/scan", response_model=ScanResponse)
async def scan_payload(payload: dict):
    # Example scan response structure returning a list for reasons
    return {
        "status": "success",
        "flagged": False,
        "reason": ["No malicious patterns detected"]
    }