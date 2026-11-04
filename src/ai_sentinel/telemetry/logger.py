import logging
import json
from datetime import datetime, UTC

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("ai_sentinel")

class SentinelTelemetry:
    @staticmethod
    def log_inspection(payload_snippet: str, result: dict, latency_ms: float):
        log_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "snippet": payload_snippet[:50] + ("..." if len(payload_snippet) > 50 else ""),
            "status": result.get("status"),
            "confidence": result.get("confidence"),
            "threats": result.get("threats", []),
            "latency_ms": round(latency_ms, 2)
        }
        logger.info(json.dumps(log_entry))
