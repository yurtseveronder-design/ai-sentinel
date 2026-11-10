"""Security telemetry.

Structured audit records for inspection decisions, plus a local SQLite trail
for sanitization rules, injection triggers, and drift between audit windows.
"""

from ai_sentinel.core.audit import AuditLogger
from ai_sentinel.telemetry.logger import (
    AuditEvent,
    DetectionTriggerLog,
    DriftReport,
    SanitizationRuleLog,
    TelemetryLogger,
)

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "DetectionTriggerLog",
    "DriftReport",
    "SanitizationRuleLog",
    "TelemetryLogger",
]
