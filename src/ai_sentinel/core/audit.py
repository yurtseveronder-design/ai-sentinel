"""
Experimental Audit Logger for SecurityShield Lab.
Records structured security events and threat telemetry.
"""

import logging
import json
from datetime import datetime, timezone
from typing import Dict, Any

logger = logging.getLogger("security_shield.audit")


class AuditLogger:
    """
    Structured audit trail generator for threat detections and gateway actions.
    """

    def __init__(self, service_name: str = "securityshield-lab"):
        self.service_name = service_name

    def log_event(self, action: str, risk_score: float, client_id: str, reasons: list) -> str:
        """
        Generates a structured JSON audit record for a security inspection event.
        """
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": self.service_name,
            "action": action,
            "risk_score": risk_score,
            "client_id": client_id,
            "reasons": reasons
        }
        log_payload = json.dumps(event)
        if action == "BLOCK":
            logger.warning("AUDIT_ALERT: %s", log_payload)
        else:
            logger.info("AUDIT_INFO: %s", log_payload)
        return log_payload