"""
FastAPI Middleware for AI-Sentinel.
Intercepts incoming requests, inspects prompts via SecurityShield,
adds strict security headers, correlation tracing IDs, and structured error responses.
"""

import json
import uuid
from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
from ai_sentinel.core.shield import SecurityShield

class AISentinelFastAPIMiddleware(BaseHTTPMiddleware):
    """
    Middleware that inspects incoming JSON requests for prompt injection
    and security threats, applying security headers, correlation IDs, and structured responses.
    """
    def __init__(self, app, shield: SecurityShield = None, **kwargs):
        super().__init__(app)
        self.shield = shield if shield is not None else SecurityShield()
        self.config_kwargs = kwargs

    async def dispatch(self, request: Request, call_next):
        # Extract or generate correlation ID for tracing
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid.uuid4())
        
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                body_bytes = await request.body()
                if body_bytes:
                    async def receive():
                        return {"type": "http.request", "body": body_bytes}
                    
                    request._receive = receive

                    try:
                        body_data = json.loads(body_bytes.decode("utf-8"))
                    except Exception:
                        body_data = {}

                    prompt = body_data.get("prompt") or body_data.get("text") or body_data.get("message")
                    if not prompt and isinstance(body_data, dict) and body_data:
                        prompt = list(body_data.values())[0]

                    if prompt and isinstance(prompt, str):
                        result = self.shield.inspect(prompt)
                        action = getattr(result, "action", None) or (result[0] if isinstance(result, tuple) else "ALLOW")
                        
                        if action == "BLOCK":
                            reasons = getattr(result, "reasons", ["Security policy violation detected"])
                            detail_msg = reasons[0] if reasons else "Request blocked by AI-Sentinel"
                            if "blocked by AI-Sentinel" not in detail_msg:
                                detail_msg = f"{detail_msg} (blocked by AI-Sentinel)"

                            response = JSONResponse(
                                status_code=400,
                                content={
                                    "type": "https://tools.ietf.org/html/rfc7807",
                                    "title": "Prompt Injection or Security Violation Detected",
                                    "status": 400,
                                    "detail": detail_msg,
                                    "reasons": reasons,
                                    "correlation_id": correlation_id
                                }
                            )
                            response.headers["X-Correlation-ID"] = correlation_id
                            response.headers["X-Content-Type-Options"] = "nosniff"
                            response.headers["X-Frame-Options"] = "DENY"
                            response.headers["X-AI-Sentinel-Protected"] = "true"
                            return response
            except Exception:
                pass

        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-AI-Sentinel-Protected"] = "true"
        return response

# Alias expected by test_fastapi_middleware.py
AISentinelMiddleware = AISentinelFastAPIMiddleware