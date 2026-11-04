from fastapi import FastAPI
from sentinel_core.shield import BioImmuneShield
from api_tester.runner import APISecurityRunner

app = FastAPI(title="AI Sentinel UI")
shield = BioImmuneShield()
runner = APISecurityRunner()

@app.post("/scan")
def scan_prompt(payload: str):
    return runner.validate_endpoint(payload)