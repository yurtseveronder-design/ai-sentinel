from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentinel_core.shield import BioImmuneShield

app = FastAPI(title="AI-Sentinel: Organic Defense Shield")
shield = BioImmuneShield()

class PayloadRequest(BaseModel):
    text: str

@app.post("/inspect")
def inspect_payload(payload: PayloadRequest):
    if not payload.text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    result = shield.inspect_payload(payload.text)
    return {
        "status": result["status"],
        "shield_stance": result.get("shield_stance", "Boundary maintained."),
        "normalized_text": result["cleaned"]
    }
