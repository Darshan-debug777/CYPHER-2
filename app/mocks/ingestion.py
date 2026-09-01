"""Mock ingestion/normalization (KV placeholder)."""

import logging
from datetime import datetime

from app.core.errors import EmptyResultError, ValidationError
from app.mocks.sample_logs import SAMPLE_RAW_LOGS
from app.schemas.enums import Severity
from app.schemas.events import NormalizedEvent, SecurityEvent

logger = logging.getLogger(__name__)

_EVENT_TYPE_MAP = {
    "failed login": "failed_login",
    "successful login": "successful_login",
    "vpn session": "vpn_session",
    "powershell": "process_execution",
    "smb connection": "lateral_movement",
    "sensitive file": "sensitive_file_access",
}


class MockIngestionService:
    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]:
        logs = raw_logs if raw_logs is not None else SAMPLE_RAW_LOGS
        if not logs:
            raise EmptyResultError("ingestion", "No raw logs provided")

        normalized: list[NormalizedEvent] = []
        for entry in logs:
            try:
                raw = SecurityEvent.model_validate(entry)
            except Exception as exc:
                raise ValidationError(
                    f"Malformed log entry: {entry.get('event_id', 'unknown')}",
                    details={"error": str(exc), "entry": entry},
                ) from exc

            msg_lower = raw.raw_message.lower()
            event_type = "unknown"
            severity = Severity.LOW
            actor = raw.metadata.get("user") or raw.metadata.get("src_ip")
            target = raw.metadata.get("host") or raw.metadata.get("dst_host") or raw.metadata.get("file")

            for keyword, etype in _EVENT_TYPE_MAP.items():
                if keyword in msg_lower:
                    event_type = etype
                    break

            if event_type == "failed_login":
                severity = Severity.MEDIUM
            elif event_type in ("process_execution", "lateral_movement", "sensitive_file_access"):
                severity = Severity.HIGH
            elif event_type == "successful_login":
                severity = Severity.MEDIUM

            normalized.append(
                NormalizedEvent(
                    event_id=f"norm-{raw.event_id}",
                    source=raw.source,
                    timestamp=raw.timestamp,
                    event_type=event_type,
                    actor=str(actor) if actor else None,
                    target=str(target) if target else None,
                    severity_hint=severity,
                    attributes=dict(raw.metadata),
                    raw_event_id=raw.event_id,
                )
            )

        if not normalized:
            raise EmptyResultError("ingestion", "Normalization produced no events")

        logger.info("Mock ingestion normalized %d events", len(normalized))
        return normalized
