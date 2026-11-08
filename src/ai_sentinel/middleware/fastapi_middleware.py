"""
FastAPI Middleware and Decorators for AI-Sentinel.
Provides automated security guardrails, rate limiting, and audit logging for FastAPI apps.
"""

import json
import time
from typing import Callable, Optional
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from ai_sentinel.core.shield import SecurityShield
from ai_sentinel.core.rate_limiter import SimpleRateLimiter
from ai_sentinel.core.audit import AuditLogger


class AISentinelMiddleware(BaseHTTPMiddleware):
    """
    Drop-in FastAPI middleware that intercepts incoming requests,
    enforces rate limits, inspects prompts for injection/threats, and logs audits.
    """

    def __init__(
        self,
        app,
        shield: Optional[SecurityShield] = None,
        rate_limiter: Optional[SimpleRateLimiter] = None,
        audit_logger: Optional[AuditLogger] = None,
        requests_per_minute: int = 60
    ):
        super().__init__(app)
        self.shield = shield or SecurityShield()
        self.rate_limiter = rate_limiter or SimpleRateLimiter(max_requests=requests_per_minute, window_seconds=60)
        self.audit_logger = audit_logger or AuditLogger(service_name="ai-sentinel-gateway")

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"

        # 1. Rate Limiting Check
        if not self.rate_limiter.allow_request(client_ip):
            self.audit_logger.log_event(
                action="BLOCK",
                risk_score=1.0,
                client_id=client_ip,
                reasons=["Rate limit exceeded"]
            )
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Too many requests."}
            )

        # 2. Inspect JSON payload if present
        if request.method in ["POST", "PUT"]:
            try:
                body = await request.json()
                prompt = body.get("prompt") or body.get("text") or body.get("message")
                if prompt and isinstance(prompt, str):
                    verdict, score, reasons = self.shield.inspect(prompt)
                    self.audit_logger.log_event(
                        action=verdict,
                        risk_score=score,
                        client_id=client_ip,
                        reasons=reasons
                    )
                    if verdict == "BLOCK":
                        return JSONResponse(
                            status_code=400,
                            content={"detail": f"Request blocked by AI-Sentinel security policy: {reasons}"}
                        )
            except (json.JSONDecodeError, Exception):
                pass

        response = await call_next(request)
        return response