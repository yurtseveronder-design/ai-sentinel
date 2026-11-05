from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from ai_sentinel.core.shield import BioImmuneShield

class SentinelMiddleware(BaseHTTPMiddleware):
    """
    ASGI/FastAPI middleware that intercepts incoming POST requests,
    inspects JSON prompt payloads via BioImmuneShield, and blocks malicious injections.
    """
    def __init__(self, app, shield: BioImmuneShield = None, mode: str = "moderate"):
        super().__init__(app)
        self.shield = shield or BioImmuneShield(mode=mode)
        
    async def dispatch(self, request: Request, call_next):
        if request.method == "POST":
            try:
                body = await request.json()
                prompt = body.get("prompt", "") or body.get("text", "")
                if prompt:
                    verdict = self.shield.inspect(prompt)
                    if verdict.action == "BLOCK":
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Blocked by AI-Sentinel Security Proxy",
                                "risk_score": verdict.risk_score,
                                "reason": verdict.reason
                            }
                        )
            except Exception:
                pass
        
        response = await call_next(request)
        return response