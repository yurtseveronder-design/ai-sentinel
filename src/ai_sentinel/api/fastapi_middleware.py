import logging
from fastapi import Request, HTTPException, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

class SentinelFastAPIMiddleware(BaseHTTPMiddleware):
    """
    FastAPI security middleware that enforces inspection on incoming requests
    and fails closed on JSON decoding or internal evaluation errors.
    """
    async def dispatch(self, request: Request, call_next):
        if request.method in ["POST", "PUT", "PATCH"]:
            try:
                # Attempt to parse body if JSON content type
                content_type = request.headers.get("content-type", "")
                if "application/json" in content_type:
                    body = await request.json()
                    if not isinstance(body, (dict, list)):
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={"detail": "Invalid JSON body structure."}
                        )
            except Exception as e:
                logger.error("Middleware failed to parse request JSON: %s", e)
                # Fail closed on malformed JSON
                return JSONResponse(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    content={"detail": "Malformed JSON payload or inspection failure."}
                )

        response = await call_next(request)
        return response