"""Event-related schemas (KV-owned pipeline stages)."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.enums import Severity, ThreatCategory


class SecurityEvent(BaseModel):
    """Raw security log event before normalization."""

    event_id: str = Field(..., min_length=1, description="Unique raw event identifier")
    source: str = Field(..., min_length=1, description="Log source e.g. auth, firewall, edr")
    timestamp: datetime
    raw_message: str = Field(..., min_length=1)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        return value.strip().lower()


class NormalizedEvent(BaseModel):
    """Standardized event after ingestion/normalization."""

    event_id: str = Field(..., min_length=1)
    source: str = Field(..., min_length=1)
    timestamp: datetime
    event_type: str = Field(..., min_length=1, description="e.g. failed_login, process_start")
    actor: str | None = Field(default=None, description="User, IP, or host initiating action")
    target: str | None = Field(default=None, description="Affected resource or host")
    severity_hint: Severity = Severity.LOW
    attributes: dict[str, Any] = Field(default_factory=dict)
    raw_event_id: str = Field(..., min_length=1, description="Link back to SecurityEvent")
