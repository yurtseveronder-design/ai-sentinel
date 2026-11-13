"""Local telemetry and drift monitor.

Writes an audit trail to a SQLite database. Each event stores a timestamp,
the SHA-256 hash of the raw input, the sanitization rules that were applied,
and the injection-detection triggers that fired. The raw input itself is not
stored.

Drift is the change between the newest events and the baseline window that
precedes them: block rate, mean confidence, sanitization-rule mix, and
trigger names that were absent from the baseline.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TypeVar

HASH_ALGORITHM = "sha256"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    input_hash TEXT NOT NULL,
    hash_algorithm TEXT NOT NULL,
    safe INTEGER NOT NULL CHECK (safe IN (0, 1)),
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    sanitization_rules TEXT NOT NULL,
    detection_triggers TEXT NOT NULL,
    client_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_events_timestamp
    ON audit_events (timestamp, id);
CREATE INDEX IF NOT EXISTS idx_audit_events_input_hash
    ON audit_events (input_hash);
"""


@dataclass(frozen=True, slots=True)
class SanitizationRuleLog:
    """One sanitization rule recorded on an audit event."""

    name: str
    pattern: str = ""
    replacement: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or self.name == "":
            raise ValueError("sanitization rule name must be a non-empty string")
        if not isinstance(self.pattern, str) or not isinstance(self.replacement, str):
            raise TypeError("sanitization rule pattern and replacement must be strings")

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "pattern": self.pattern,
            "replacement": self.replacement,
        }


@dataclass(frozen=True, slots=True)
class DetectionTriggerLog:
    """One injection-detection trigger recorded on an audit event."""

    name: str
    category: str = ""
    confidence: float | None = None
    excerpt: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or self.name == "":
            raise ValueError("detection trigger name must be a non-empty string")
        if not isinstance(self.category, str) or not isinstance(self.excerpt, str):
            raise TypeError("detection trigger category and excerpt must be strings")
        if self.confidence is not None:
            _require_unit_interval(self.confidence, "trigger confidence")

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "category": self.category,
            "confidence": self.confidence,
            "excerpt": self.excerpt,
        }

    @property
    def key(self) -> str:
        """Stable identity used when comparing trigger sets across windows."""
        if self.category:
            return f"{self.category}:{self.name}"
        return self.name


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """One persisted audit-trail row."""

    id: int
    timestamp: str
    input_hash: str
    hash_algorithm: str
    safe: bool
    confidence: float
    sanitization_rules: tuple[SanitizationRuleLog, ...]
    detection_triggers: tuple[DetectionTriggerLog, ...]
    client_id: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.id, int) or isinstance(self.id, bool) or self.id < 1:
            raise ValueError("audit event id must be a positive integer")
        if not isinstance(self.safe, bool):
            raise TypeError("safe must be a bool")
        _require_unit_interval(self.confidence, "confidence")
        if self.hash_algorithm != HASH_ALGORITHM:
            raise ValueError(f"hash_algorithm must be {HASH_ALGORITHM}")
        if len(self.input_hash) != 64 or any(char not in "0123456789abcdef" for char in self.input_hash):
            raise ValueError("input_hash must be a sha256 hex digest")

    def as_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "input_hash": self.input_hash,
            "hash_algorithm": self.hash_algorithm,
            "safe": self.safe,
            "confidence": self.confidence,
            "sanitization_rules": [rule.as_dict() for rule in self.sanitization_rules],
            "detection_triggers": [trigger.as_dict() for trigger in self.detection_triggers],
            "client_id": self.client_id,
        }


@dataclass(frozen=True, slots=True)
class DriftReport:
    """Difference between the newest audit window and the baseline before it.

    Block rate is the fraction of events whose safety flag is false.
    Deltas are current minus baseline. ``drifted`` is true when both windows
    have at least ``min_samples`` events and a configured threshold is met.
    """

    sampled_at: str
    current_count: int
    baseline_count: int
    current_block_rate: float
    baseline_block_rate: float
    block_rate_delta: float
    current_mean_confidence: float
    baseline_mean_confidence: float
    confidence_delta: float
    new_triggers: tuple[str, ...]
    top_rule_shift: str
    rule_rate_delta: float
    drifted: bool
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "sampled_at": self.sampled_at,
            "current_count": self.current_count,
            "baseline_count": self.baseline_count,
            "current_block_rate": self.current_block_rate,
            "baseline_block_rate": self.baseline_block_rate,
            "block_rate_delta": self.block_rate_delta,
            "current_mean_confidence": self.current_mean_confidence,
            "baseline_mean_confidence": self.baseline_mean_confidence,
            "confidence_delta": self.confidence_delta,
            "new_triggers": list(self.new_triggers),
            "top_rule_shift": self.top_rule_shift,
            "rule_rate_delta": self.rule_rate_delta,
            "drifted": self.drifted,
            "reasons": list(self.reasons),
        }


class TelemetryLogger:
    """SQLite audit trail and drift monitor for local inspections.

    Args:
        database: Filesystem path of the SQLite database, or ``":memory:"``.
            The default file is ``ai_sentinel_telemetry.db`` in the working
            directory.
        drift_window: Number of newest events in the current drift window.
        drift_baseline: Number of preceding events used as the baseline.
        min_samples: Minimum events required in each window before a shift
            can be reported as drift.
        block_rate_threshold: Absolute block-rate change that counts as drift.
        confidence_threshold: Absolute mean-confidence change that counts as drift.
        rule_rate_threshold: Absolute sanitization-rule rate change that
            counts as drift.

    Raises:
        TypeError: A threshold or size has the wrong type.
        ValueError: A size is below 1, ``min_samples`` exceeds either window,
            or a threshold is outside 0 to 1.
        OSError: The database directory cannot be created.
    """

    def __init__(
        self,
        database: str | Path = "ai_sentinel_telemetry.db",
        *,
        drift_window: int = 50,
        drift_baseline: int = 200,
        min_samples: int = 20,
        block_rate_threshold: float = 0.25,
        confidence_threshold: float = 0.15,
        rule_rate_threshold: float = 0.30,
    ) -> None:
        self.drift_window = _require_positive_int(drift_window, "drift_window")
        self.drift_baseline = _require_positive_int(drift_baseline, "drift_baseline")
        self.min_samples = _require_positive_int(min_samples, "min_samples")
        if self.min_samples > self.drift_window or self.min_samples > self.drift_baseline:
            raise ValueError("min_samples cannot exceed drift_window or drift_baseline")
        self.block_rate_threshold = _require_unit_interval(
            block_rate_threshold, "block_rate_threshold"
        )
        self.confidence_threshold = _require_unit_interval(
            confidence_threshold, "confidence_threshold"
        )
        self.rule_rate_threshold = _require_unit_interval(
            rule_rate_threshold, "rule_rate_threshold"
        )
        self.database = database
        self._lock = threading.Lock()
        self._connection = _connect(database)
        self._connection.executescript(_SCHEMA)
        self._connection.commit()

    def __enter__(self) -> TelemetryLogger:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Close the database connection. Further calls raise ``RuntimeError``."""
        with self._lock:
            connection = self._connection
            self._connection = None
        if connection is not None:
            connection.close()

    @staticmethod
    def hash_input(raw_input: str) -> str:
        """Return the SHA-256 hex digest of a raw user string.

        Args:
            raw_input: Exact raw input, before sanitization.

        Returns:
            Lowercase hex digest.

        Raises:
            TypeError: ``raw_input`` is not a string.
        """
        if not isinstance(raw_input, str):
            raise TypeError(f"raw_input must be a str, got {type(raw_input).__name__}")
        return hashlib.sha256(raw_input.encode("utf-8")).hexdigest()

    def log(
        self,
        raw_input: str,
        *,
        sanitization_rules: Sequence[object] | object | None = None,
        detection_triggers: Sequence[object] | object | None = None,
        detection: object | None = None,
        safe: bool | None = None,
        confidence: float | None = None,
        client_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditEvent:
        """Append one audit event and commit it.

        ``sanitization_rules`` accepts rule names, mappings, or objects with
        ``name``, ``pattern``, and ``replacement`` attributes (including
        ``CleaningPattern``). ``detection`` accepts an injection scan result
        with ``safe``, ``confidence``, and ``pattern_logs``. Explicit
        ``safe``, ``confidence``, and ``detection_triggers`` override that
        result. Trigger excerpts are stored; the raw input is only hashed.

        Args:
            raw_input: Raw user string. Only its hash is persisted.
            sanitization_rules: Rules applied while sanitizing this input.
            detection_triggers: Injection signatures that fired.
            detection: Scan result used when the explicit fields are omitted.
            safe: Safety flag. Defaults to the scan result, then to whether
                any trigger fired.
            confidence: Match confidence from 0 to 1.
            client_id: Optional caller identifier.
            timestamp: Timezone-aware event time. Defaults to the current UTC time.

        Returns:
            The stored audit event, including its database id.

        Raises:
            TypeError: An argument has the wrong type.
            ValueError: Confidence or a timestamp is not usable.
            RuntimeError: The logger is closed.
        """
        rules = _coerce_rules(sanitization_rules)
        triggers = _coerce_triggers(detection_triggers, detection)
        resolved_safe = _resolve_safe(detection, safe, triggers)
        resolved_confidence = _resolve_confidence(detection, confidence, triggers)
        if client_id is not None and not isinstance(client_id, str):
            raise TypeError("client_id must be a string or None")
        event_timestamp = _format_timestamp(timestamp)
        input_hash = self.hash_input(raw_input)
        rules_json = json.dumps([rule.as_dict() for rule in rules], ensure_ascii=False)
        triggers_json = json.dumps(
            [trigger.as_dict() for trigger in triggers],
            ensure_ascii=False,
        )

        with self._lock:
            connection = self._require_open()
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, input_hash, hash_algorithm, safe, confidence,
                    sanitization_rules, detection_triggers, client_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_timestamp,
                    input_hash,
                    HASH_ALGORITHM,
                    1 if resolved_safe else 0,
                    resolved_confidence,
                    rules_json,
                    triggers_json,
                    client_id,
                ),
            )
            connection.commit()
            event_id = int(cursor.lastrowid or 0)

        return AuditEvent(
            id=event_id,
            timestamp=event_timestamp,
            input_hash=input_hash,
            hash_algorithm=HASH_ALGORITHM,
            safe=resolved_safe,
            confidence=resolved_confidence,
            sanitization_rules=rules,
            detection_triggers=triggers,
            client_id=client_id,
        )

    def recent(self, limit: int = 50) -> tuple[AuditEvent, ...]:
        """Return the newest audit events, newest first.

        Args:
            limit: Maximum number of events to return.

        Raises:
            ValueError: ``limit`` is not a positive integer.
            RuntimeError: The logger is closed.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        with self._lock:
            connection = self._require_open()
            rows = connection.execute(
                """
                SELECT id, timestamp, input_hash, hash_algorithm, safe, confidence,
                       sanitization_rules, detection_triggers, client_id
                FROM audit_events
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return tuple(_event_from_row(row) for row in rows)

    def drift(
        self,
        *,
        window: int | None = None,
        baseline: int | None = None,
    ) -> DriftReport:
        """Compare the newest events with the baseline window before them.

        Windows are taken from committed rows in timestamp order, then id.
        The report is computed when it is requested, so a reader sees events
        already committed by ``log``.

        Args:
            window: Current-window size. Defaults to the logger setting.
            baseline: Baseline size. Defaults to the logger setting.

        Raises:
            ValueError: A window size is not a positive integer.
            RuntimeError: The logger is closed.
        """
        current_size = self.drift_window if window is None else _require_positive_int(window, "window")
        baseline_size = (
            self.drift_baseline if baseline is None else _require_positive_int(baseline, "baseline")
        )
        with self._lock:
            connection = self._require_open()
            rows = connection.execute(
                """
                SELECT id, timestamp, input_hash, hash_algorithm, safe, confidence,
                       sanitization_rules, detection_triggers, client_id
                FROM audit_events
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
                """,
                (current_size + baseline_size,),
            ).fetchall()
        events = tuple(_event_from_row(row) for row in rows)
        current = events[:current_size]
        history = events[current_size : current_size + baseline_size]
        return _build_drift_report(
            current,
            history,
            min_samples=self.min_samples,
            block_rate_threshold=self.block_rate_threshold,
            confidence_threshold=self.confidence_threshold,
            rule_rate_threshold=self.rule_rate_threshold,
        )

    def _require_open(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("telemetry logger is closed")
        return self._connection


def _connect(database: str | Path) -> sqlite3.Connection:
    if str(database) == ":memory:":
        target = ":memory:"
    else:
        path = Path(database)
        path.parent.mkdir(parents=True, exist_ok=True)
        target = str(path)
    connection = sqlite3.connect(target, timeout=5.0, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def _require_positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{label} must be a positive integer")
    return value


def _require_unit_interval(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{label} must be a number between 0 and 1")
    number = float(value)
    if not 0.0 <= number <= 1.0:
        raise ValueError(f"{label} must be between 0 and 1")
    return number


def _format_timestamp(value: datetime | None) -> str:
    if value is None:
        value = datetime.now(timezone.utc)
    elif not isinstance(value, datetime):
        raise TypeError("timestamp must be a datetime or None")
    elif value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(timezone.utc).isoformat()


def _has_name(value: object) -> bool:
    name = getattr(value, "name", None)
    return isinstance(name, str) and name != ""


_Item = TypeVar("_Item")


def _as_items(
    values: object,
    coerce: Callable[[object], _Item],
    kind: str,
) -> tuple[_Item, ...]:
    if values is None:
        return ()
    single = isinstance(values, (str, Mapping)) or (
        not isinstance(values, Sequence) and _has_name(values)
    )
    if single:
        return (coerce(values),)
    if isinstance(values, Sequence):
        return tuple(coerce(item) for item in values)
    raise TypeError(f"{kind} must be one item or a sequence of items")


def _coerce_rules(values: object) -> tuple[SanitizationRuleLog, ...]:
    return _as_items(values, _coerce_rule, "sanitization_rules")


def _coerce_rule(rule: object) -> SanitizationRuleLog:
    if isinstance(rule, SanitizationRuleLog):
        return rule
    if isinstance(rule, str):
        return SanitizationRuleLog(name=rule)
    if isinstance(rule, Mapping):
        name = rule.get("name", "")
        pattern = rule.get("pattern", "")
        replacement = rule.get("replacement", "")
        if not isinstance(name, str) or not isinstance(pattern, str) or not isinstance(replacement, str):
            raise TypeError("sanitization rule mapping fields must be strings")
        return SanitizationRuleLog(name=name, pattern=pattern, replacement=replacement)
    if _has_name(rule):
        pattern_value = getattr(rule, "pattern", "")
        if isinstance(pattern_value, str):
            pattern = pattern_value
        else:
            source = getattr(pattern_value, "pattern", "")
            pattern = source if isinstance(source, str) else ""
        replacement = getattr(rule, "replacement", "")
        if not isinstance(replacement, str):
            replacement = ""
        return SanitizationRuleLog(
            name=str(getattr(rule, "name")),
            pattern=pattern,
            replacement=replacement,
        )
    raise TypeError(
        "sanitization rule must be a string, mapping, or object with a name"
    )


def _coerce_triggers(
    values: object,
    detection: object | None,
) -> tuple[DetectionTriggerLog, ...]:
    if values is not None:
        return _as_items(values, _coerce_trigger, "detection_triggers")
    if detection is None:
        return ()
    logs = getattr(detection, "pattern_logs", ())
    if not isinstance(logs, Sequence) or isinstance(logs, str):
        raise TypeError("detection.pattern_logs must be a sequence")
    return tuple(_coerce_trigger(item) for item in logs)


def _coerce_trigger(trigger: object) -> DetectionTriggerLog:
    if isinstance(trigger, DetectionTriggerLog):
        return trigger
    if isinstance(trigger, str):
        return DetectionTriggerLog(name=trigger)
    if isinstance(trigger, Mapping):
        return _trigger_from_mapping(trigger)
    if _has_name(trigger):
        category = getattr(trigger, "category", "")
        excerpt = getattr(trigger, "excerpt", "")
        return DetectionTriggerLog(
            name=str(getattr(trigger, "name")),
            category=category if isinstance(category, str) else "",
            confidence=_optional_confidence(getattr(trigger, "confidence", None)),
            excerpt=excerpt if isinstance(excerpt, str) else "",
        )
    raise TypeError(
        "detection trigger must be a string, mapping, or object with a name"
    )


def _trigger_from_mapping(trigger: Mapping[str, object]) -> DetectionTriggerLog:
    name = trigger.get("name", "")
    category = trigger.get("category", "")
    excerpt = trigger.get("excerpt", "")
    if not isinstance(name, str) or not isinstance(category, str) or not isinstance(excerpt, str):
        raise TypeError("detection trigger mapping fields must be strings")
    return DetectionTriggerLog(
        name=name,
        category=category,
        excerpt=excerpt,
        confidence=_optional_confidence(trigger.get("confidence")),
    )


def _optional_confidence(value: object) -> float | None:
    if value is None:
        return None
    return _require_unit_interval(value, "trigger confidence")


def _resolve_safe(
    detection: object | None,
    safe: bool | None,
    triggers: Sequence[DetectionTriggerLog],
) -> bool:
    if safe is not None:
        if not isinstance(safe, bool):
            raise TypeError("safe must be a bool")
        return safe
    detected = getattr(detection, "safe", None)
    if isinstance(detected, bool):
        return detected
    return not bool(triggers)


def _resolve_confidence(
    detection: object | None,
    confidence: float | None,
    triggers: Sequence[DetectionTriggerLog],
) -> float:
    if confidence is not None:
        return _require_unit_interval(confidence, "confidence")
    detected = getattr(detection, "confidence", None)
    if detected is not None and not isinstance(detected, bool):
        return _require_unit_interval(detected, "confidence")
    scored = [trigger.confidence for trigger in triggers if trigger.confidence is not None]
    if not scored:
        return 0.0
    return _require_unit_interval(max(scored), "confidence")


def _event_from_row(row: sqlite3.Row) -> AuditEvent:
    rules_payload = json.loads(row["sanitization_rules"])
    triggers_payload = json.loads(row["detection_triggers"])
    if not isinstance(rules_payload, list) or not isinstance(triggers_payload, list):
        raise ValueError(f"audit event {row['id']} has invalid JSON columns")
    return AuditEvent(
        id=int(row["id"]),
        timestamp=str(row["timestamp"]),
        input_hash=str(row["input_hash"]),
        hash_algorithm=str(row["hash_algorithm"]),
        safe=bool(row["safe"]),
        confidence=float(row["confidence"]),
        sanitization_rules=tuple(_coerce_rule(item) for item in rules_payload),
        detection_triggers=tuple(_coerce_trigger(item) for item in triggers_payload),
        client_id=None if row["client_id"] is None else str(row["client_id"]),
    )


def _block_rate(events: Sequence[AuditEvent]) -> float:
    if not events:
        return 0.0
    blocked = sum(1 for event in events if not event.safe)
    return blocked / len(events)


def _mean_confidence(events: Sequence[AuditEvent]) -> float:
    if not events:
        return 0.0
    return sum(event.confidence for event in events) / len(events)


def _rule_rates(events: Sequence[AuditEvent]) -> dict[str, float]:
    if not events:
        return {}
    counts: dict[str, int] = {}
    for event in events:
        for rule in {item.name for item in event.sanitization_rules}:
            counts[rule] = counts.get(rule, 0) + 1
    total = len(events)
    return {name: count / total for name, count in counts.items()}


def _build_drift_report(
    current: Sequence[AuditEvent],
    baseline: Sequence[AuditEvent],
    *,
    min_samples: int,
    block_rate_threshold: float,
    confidence_threshold: float,
    rule_rate_threshold: float,
) -> DriftReport:
    current_rules = _rule_rates(current)
    baseline_rules = _rule_rates(baseline)
    shift_name, shift_delta = _top_rule_shift(current_rules, baseline_rules)
    current_trigger_names = {trigger.key for event in current for trigger in event.detection_triggers}
    baseline_trigger_names = {
        trigger.key for event in baseline for trigger in event.detection_triggers
    }
    new_triggers = tuple(sorted(current_trigger_names - baseline_trigger_names))
    current_block = _block_rate(current)
    baseline_block = _block_rate(baseline)
    current_confidence = _mean_confidence(current)
    baseline_confidence = _mean_confidence(baseline)
    block_delta = current_block - baseline_block
    confidence_delta = current_confidence - baseline_confidence

    reasons: list[str] = []
    enough = len(current) >= min_samples and len(baseline) >= min_samples
    if not enough:
        reasons.append("insufficient_history")
    else:
        if abs(block_delta) >= block_rate_threshold:
            reasons.append("block_rate_shift")
        if abs(confidence_delta) >= confidence_threshold:
            reasons.append("confidence_shift")
        if new_triggers:
            reasons.append("new_triggers")
        if abs(shift_delta) >= rule_rate_threshold:
            reasons.append("sanitization_rule_shift")

    return DriftReport(
        sampled_at=_format_timestamp(None),
        current_count=len(current),
        baseline_count=len(baseline),
        current_block_rate=round(current_block, 4),
        baseline_block_rate=round(baseline_block, 4),
        block_rate_delta=round(block_delta, 4),
        current_mean_confidence=round(current_confidence, 4),
        baseline_mean_confidence=round(baseline_confidence, 4),
        confidence_delta=round(confidence_delta, 4),
        new_triggers=new_triggers,
        top_rule_shift=shift_name if shift_delta else "",
        rule_rate_delta=round(shift_delta, 4),
        drifted=enough and bool(reasons),
        reasons=tuple(reasons),
    )


def _top_rule_shift(
    current: Mapping[str, float],
    baseline: Mapping[str, float],
) -> tuple[str, float]:
    names = set(current) | set(baseline)
    if not names:
        return "", 0.0
    ranked = sorted(
        ((name, current.get(name, 0.0) - baseline.get(name, 0.0)) for name in names),
        key=lambda item: (-abs(item[1]), item[0]),
    )
    return ranked[0]
