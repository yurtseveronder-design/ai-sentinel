from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from sentinel_core.shield import BioImmuneShield

app = FastAPI(title="AI-Sentinel API")
shield = BioImmuneShield()

class PayloadRequest(BaseModel):
    text: str

@app.post("/inspect")
def inspect_payload(payload: PayloadRequest):
    if not payload.text:
        raise HTTPException(status_code=400, detail="Text cannot be empty")
    result = shield.inspect_payload(payload.text)
    cleaned = result.get("cleaned", result.get("normalized", result.get("text", "")))
    return {"status": result.get("status", "NEUTRAL"), "cleaned_text": cleaned}
