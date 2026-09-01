"""Mock event correlation (MRUN placeholder)."""

import logging
import uuid

from app.core.errors import EmptyResultError
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)


class MockCorrelationService:
    async def correlate(
        self,
        events: list[NormalizedEvent],
        detections: list[DetectionResult],
    ) -> CorrelatedIncident:
        if not events or not detections:
            raise EmptyResultError("correlation", "Insufficient data for correlation")

        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        timestamps = [e.timestamp for e in events]
        categories = [d.category for d in detections]
        severities = [d.severity for d in detections]

        primary = ThreatCategory.LATERAL_MOVEMENT if ThreatCategory.LATERAL_MOVEMENT in categories else categories[-1]
        max_severity = max(severities, key=lambda s: ["low", "medium", "high", "critical"].index(s.value))

        incident = CorrelatedIncident(
            incident_id=incident_id,
            title="Multi-Stage Intrusion: Brute Force to Sensitive Data Access",
            summary=(
                "Correlated sequence of failed logins, successful authentication from unknown IP, "
                "PowerShell execution, lateral movement, and sensitive file access on finance server."
            ),
            related_event_ids=[e.event_id for e in events],
            detections=detections,
            normalized_events=events,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            primary_category=primary,
            severity=max_severity,
        )

        logger.info("Mock correlation created incident %s", incident_id)
        return incident
