"""Detection and correlation schemas (MRUN-owned pipeline stages)."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent


class DetectionResult(BaseModel):
    """Output of threat/anomaly detection on normalized events."""

    detection_id: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    threat_type: str = Field(..., min_length=1)
    category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity
    confidence: float = Field(..., ge=0.0, le=1.0)
    indicators: list[str] = Field(default_factory=list)
    description: str = Field(..., min_length=1)


class CorrelatedIncident(BaseModel):
    """Grouped detections forming a single incident candidate."""

    incident_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    related_event_ids: list[str] = Field(..., min_length=1)
    detections: list[DetectionResult] = Field(..., min_length=1)
    normalized_events: list[NormalizedEvent] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    primary_category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity
