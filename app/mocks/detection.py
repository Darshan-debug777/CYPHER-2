"""Mock threat detection (MRUN placeholder)."""

import logging

from app.core.errors import EmptyResultError
from app.schemas.detection import DetectionResult
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent

logger = logging.getLogger(__name__)

_DETECTION_RULES: dict[str, tuple[str, ThreatCategory, Severity, float, list[str]]] = {
    "failed_login": (
        "Brute Force Attempt",
        ThreatCategory.AUTHENTICATION,
        Severity.MEDIUM,
        0.75,
        ["T1110"],
    ),
    "successful_login": (
        "Suspicious Successful Login After Failures",
        ThreatCategory.AUTHENTICATION,
        Severity.HIGH,
        0.82,
        ["T1078"],
    ),
    "vpn_session": (
        "Remote Access from Unknown Location",
        ThreatCategory.RECONNAISSANCE,
        Severity.MEDIUM,
        0.70,
        ["T1133"],
    ),
    "process_execution": (
        "Suspicious PowerShell Execution",
        ThreatCategory.EXECUTION,
        Severity.HIGH,
        0.88,
        ["T1059.001"],
    ),
    "lateral_movement": (
        "Lateral Movement via SMB",
        ThreatCategory.LATERAL_MOVEMENT,
        Severity.HIGH,
        0.85,
        ["T1021.002"],
    ),
    "sensitive_file_access": (
        "Access to Sensitive Financial Data",
        ThreatCategory.EXFILTRATION,
        Severity.CRITICAL,
        0.92,
        ["T1005", "T1039"],
    ),
}


class MockDetectionService:
    async def detect(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        if not events:
            raise EmptyResultError("detection", "No events to analyze")

        detections: list[DetectionResult] = []
        for event in events:
            rule = _DETECTION_RULES.get(event.event_type)
            if not rule:
                continue
            threat_type, category, severity, confidence, indicators = rule
            detections.append(
                DetectionResult(
                    detection_id=f"det-{event.event_id}",
                    event_id=event.event_id,
                    threat_type=threat_type,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    indicators=indicators,
                    description=f"{threat_type} detected on {event.source} involving {event.actor or 'unknown actor'}",
                )
            )

        if not detections:
            raise EmptyResultError("detection", "No threats detected in event stream")

        logger.info("Mock detection found %d threats", len(detections))
        return detections
