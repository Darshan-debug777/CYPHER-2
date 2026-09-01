"""Schema validation tests."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.schemas.events import NormalizedEvent, SecurityEvent
from app.schemas.investigation import Evidence, RiskAssessment
from app.schemas.enums import RiskLevel, Severity, ThreatCategory


def test_security_event_valid():
    event = SecurityEvent(
        event_id="e1",
        source="auth",
        timestamp=datetime.now(timezone.utc),
        raw_message="Failed login",
    )
    assert event.source == "auth"


def test_security_event_rejects_empty_message():
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="e1",
            source="auth",
            timestamp=datetime.now(timezone.utc),
            raw_message="",
        )


def test_risk_score_bounds():
    with pytest.raises(ValidationError):
        RiskAssessment(
            incident_id="INC-1",
            risk_score=150,
            risk_level=RiskLevel.HIGH,
            confidence=0.5,
            business_impact="test",
            assessed_at=datetime.now(timezone.utc),
        )


def test_evidence_confidence_bounds():
    with pytest.raises(ValidationError):
        Evidence(
            evidence_id="ev1",
            event_id="e1",
            source="auth",
            description="test",
            snippet="test snippet",
            confidence=1.5,
            supports="claim",
        )


def test_normalized_event_links_raw():
    event = NormalizedEvent(
        event_id="norm-1",
        source="auth",
        timestamp=datetime.now(timezone.utc),
        event_type="failed_login",
        raw_event_id="raw-1",
    )
    assert event.raw_event_id == "raw-1"
