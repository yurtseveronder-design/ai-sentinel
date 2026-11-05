from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import Request
from fastapi.responses import JSONResponse
from ai_sentinel.core.shield import BioImmuneShield

class SentinelMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that intercepts incoming requests and inspects JSON payloads
    using BioImmuneShield, returning a clean 403 JSONResponse when blocked.
    """
    def __init__(self, app, mode: str = "moderate", config_path=None):
        super().__init__(app)
        self.shield = BioImmuneShield(mode=mode, config_path=config_path)

    async def dispatch(self, request: Request, call_next):
        if request.method == "POST" and "application/json" in request.headers.get("content-type", ""):
            try:
                body = await request.json()
                prompt = body.get("prompt") or body.get("text") or body.get("message")
                session_id = request.headers.get("X-Session-ID") or body.get("session_id")
                
                if prompt:
                    verdict = self.shield.inspect(prompt, session_id=session_id)
                    if verdict.action == "BLOCK":
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Request blocked by AI-Sentinel",
                                "reasons": verdict.reason,
                                "risk_score": verdict.risk_score
                            }
                        )
            except Exception:
                pass  # Fallthrough for malformed json or non-prompt payloads

        response = await call_next(request)
        return response