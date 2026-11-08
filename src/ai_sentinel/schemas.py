from pydantic import BaseModel, Field
from typing import List, Optional

class ScanRequest(BaseModel):
    prompt: Optional[str] = None
    encoded_prompt: Optional[str] = None
    context: Optional[str] = None

class ScanResponse(BaseModel):
    status: str
    action: str = "ALLOW"
    reasons: List[str] = Field(default_factory=list)
    risk_score: Optional[float] = 0.0