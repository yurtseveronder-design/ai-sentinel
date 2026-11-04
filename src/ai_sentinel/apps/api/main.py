from fastapi import FastAPI
from pydantic import BaseModel
import time
from ai_sentinel.core.shield import BioImmuneShield
from ai_sentinel.telemetry.logger import SentinelTelemetry

app = FastAPI()
shield = BioImmuneShield()

class Payload(BaseModel):
    text: str

@app.post("/inspect")
def inspect_payload(payload: Payload):
    start_time = time.perf_counter()
    result = shield.inspect_payload(payload.text)
    latency = (time.perf_counter() - start_time) * 1000
    SentinelTelemetry.log_inspection(payload.text, result, latency)
    return result
