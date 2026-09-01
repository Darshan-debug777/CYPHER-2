"""Unit tests for Context Agent.

Tests cover normal context, unusual context, insufficient context, multiple events,
contradictory evidence, error handling, hallucination prevention, and prompt formatting.
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.agents.context import ContextAgent, ContextAnalysis
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.services.llm_client import LLMClient, LLMOutputParseError, MockLLMProvider


@pytest.fixture
def base_timestamp():
    """Base timestamp for context events."""
    return datetime(2024, 1, 15, 14, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_normalized_events(base_timestamp):
    """Sample normalized security events."""
    return [
        NormalizedEvent(
            event_id="EVT-001",
            source="auth_log",
            timestamp=base_timestamp,
            event_type="failed_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"src_ip": "203.0.113.45", "user": "admin"},
            raw_event_id="raw-001",
        ),
        NormalizedEvent(
            event_id="EVT-002",
            source="auth_log",
            timestamp=base_timestamp + timedelta(minutes=5),
            event_type="successful_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"src_ip": "203.0.113.45", "user": "admin"},
            raw_event_id="raw-002",
        ),
        NormalizedEvent(
            event_id="EVT-003",
            source="process_log",
            timestamp=base_timestamp + timedelta(minutes=10),
            event_type="process_start",
            actor="admin",
            target="server-01",
            severity_hint=Severity.HIGH,
            attributes={"process": "powershell.exe", "host": "server-01"},
            raw_event_id="raw-003",
        ),
        NormalizedEvent(
            event_id="EVT-004",
            source="auth_log",
            timestamp=base_timestamp + timedelta(minutes=30),
            event_type="maintenance_login",
            actor="backup_service",
            target="server-01",
            severity_hint=Severity.LOW,
            attributes={"user": "backup_service", "scheduled": "true"},
            raw_event_id="raw-004",
        ),
    ]


@pytest.fixture
def sample_detections():
    """Sample detections."""
    return [
        DetectionResult(
            detection_id="DET-001",
            event_id="EVT-001",
            threat_type="credential_attack",
            category=ThreatCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=0.75,
            indicators=["multiple_failed_attempts"],
            description="Failed login attempt",
        ),
        DetectionResult(
            detection_id="DET-002",
            event_id="EVT-002",
            threat_type="account_compromise",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            confidence=0.85,
            indicators=["unusual_ip"],
            description="Successful login from unusual IP",
        ),
    ]


@pytest.fixture
def sample_incident(base_timestamp, sample_normalized_events, sample_detections):
    """Sample correlated incident."""
    return CorrelatedIncident(
        incident_id="INC-2024-CTX",
        title="Context Analysis Incident",
        summary="Admin and backup account activity on server-01",
        related_event_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        detections=sample_detections,
        normalized_events=sample_normalized_events,
        first_seen=base_timestamp,
        last_seen=base_timestamp + timedelta(minutes=30),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.HIGH,
    )


# ============================================================================
# Test Cases
# ============================================================================


@pytest.mark.asyncio
async def test_context_agent_normal_context(sample_incident):
    """Test when activity is evaluated as expected/routine in context."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Activity appears largely consistent with scheduled maintenance operations.",
        indicators=[
            "Backup service account executed scheduled job",
            "Routine administrative maintenance window",
        ],
        relevant_factors=[
            "Backup service user is pre-authorized",
            "Target server-01 is designated backup host",
        ],
        supporting_evidence_ids=[],
        contradicting_evidence_ids=["EVT-004"],
        explanation="The backup service operations match standard baseline schedules and authorization profiles.",
        uncertainty="Baseline for admin user from external IP is incomplete.",
        confidence=0.80,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    assert analysis.incident_id == "INC-2024-CTX"
    assert "maintenance" in analysis.contextual_assessment.lower()
    assert "EVT-004" in analysis.contradicting_evidence_ids
    assert analysis.confidence == 0.80


@pytest.mark.asyncio
async def test_context_agent_unusual_context(sample_incident):
    """Test when activity is evaluated as highly unusual in context."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Highly unusual activity with off-hours administrative access from external IP.",
        indicators=[
            "Admin login originating from non-corporate external IP (203.0.113.45)",
            "PowerShell execution immediately following authentication",
        ],
        relevant_factors=[
            "Admin account has full domain privileges",
            "Host server-01 stores sensitive production data",
            "Source IP is not in VPN pool or corporate CIDR",
        ],
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        contradicting_evidence_ids=[],
        explanation="External IP authentication combined with shell execution represents a severe deviation from normal admin behavior.",
        uncertainty="Historical travel schedule for user admin is not available in logs.",
        confidence=0.90,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    assert len(analysis.supporting_evidence_ids) == 3
    assert "EVT-002" in analysis.supporting_evidence_ids
    assert len(analysis.indicators) == 2
    assert analysis.confidence >= 0.85


@pytest.mark.asyncio
async def test_context_agent_insufficient_context(sample_incident):
    """Test explicit reporting of uncertainty when baselines are missing."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Ambiguous activity; insufficient baseline data to determine normal vs anomalous.",
        indicators=[
            "Single login attempt from external IP",
            "Lack of historical access logs for user admin",
        ],
        relevant_factors=[
            "No historical IP whitelist available",
            "No shift schedules provided in logs",
        ],
        supporting_evidence_ids=["EVT-002"],
        contradicting_evidence_ids=[],
        explanation="Cannot definitively classify behavior without baseline access profiles or historical login frequencies.",
        uncertainty="Critical baseline missing: no 30-day login history, no geolocation profile, no authorized tool list.",
        confidence=0.40,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    assert analysis.confidence <= 0.5
    assert "baseline missing" in analysis.uncertainty.lower()
    assert len(analysis.uncertainty) > 20


@pytest.mark.asyncio
async def test_context_agent_multiple_events(sample_incident):
    """Test analysis across multiple events and contextual factors."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Multi-faceted contextual event stream with both suspicious and legitimate actions.",
        indicators=[
            "Brute force followed by success",
            "Automated scheduled backup",
        ],
        relevant_factors=["Multi-user event sequence", "Heterogeneous log sources"],
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        contradicting_evidence_ids=["EVT-004"],
        explanation="Events 1-3 indicate intrusion context while event 4 is confirmed routine backup.",
        uncertainty="Limited visibility into process parent-child hierarchy.",
        confidence=0.85,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    assert len(analysis.supporting_evidence_ids) == 3
    assert len(analysis.contradicting_evidence_ids) == 1


@pytest.mark.asyncio
async def test_context_agent_contradictory_evidence(sample_incident):
    """Test context agent properly segregates supporting vs contradicting evidence."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Mixed context containing both hostile anomalies and normal background operations.",
        indicators=["Suspicious PowerShell", "Legitimate Backup"],
        relevant_factors=["Target host server-01"],
        supporting_evidence_ids=["EVT-003"],
        contradicting_evidence_ids=["EVT-004"],
        explanation="PowerShell execution is anomalous, whereas backup login is routine.",
        uncertainty="Need command-line arguments to confirm PowerShell intent.",
        confidence=0.75,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    assert "EVT-003" in analysis.supporting_evidence_ids
    assert "EVT-004" in analysis.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_context_agent_invalid_llm_output(sample_incident):
    """Test handling of invalid/malformed LLM output."""
    invalid_response = {"invalid": "payload"}

    mock_provider = MockLLMProvider(response=invalid_response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    with pytest.raises(LLMOutputParseError):
        await agent.analyze(sample_incident)


@pytest.mark.asyncio
async def test_context_agent_hallucinated_event_ids(sample_incident):
    """Test that hallucinated event IDs are safely purged."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Testing hallucination filter.",
        indicators=["Unusual activity"],
        relevant_factors=["Test factor"],
        supporting_evidence_ids=["EVT-001", "EVT-FAKE-999", "EVT-002"],
        contradicting_evidence_ids=["EVT-GHOST-888", "EVT-004"],
        explanation="Testing ID verification.",
        uncertainty="None.",
        confidence=0.80,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    analysis = await agent.analyze(sample_incident)

    # Hallucinated IDs must be stripped
    assert "EVT-FAKE-999" not in analysis.supporting_evidence_ids
    assert "EVT-GHOST-888" not in analysis.contradicting_evidence_ids
    # Valid IDs must remain
    assert "EVT-001" in analysis.supporting_evidence_ids
    assert "EVT-002" in analysis.supporting_evidence_ids
    assert "EVT-004" in analysis.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_context_agent_confidence_bounds():
    """Test confidence validation bounds."""
    response = ContextAnalysis(
        incident_id="INC-2024-CTX",
        contextual_assessment="Valid assessment.",
        indicators=[],
        relevant_factors=[],
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        explanation="Valid reasoning.",
        uncertainty="Valid uncertainty.",
        confidence=0.72,
    )
    assert 0.0 <= response.confidence <= 1.0


@pytest.mark.asyncio
async def test_context_agent_empty_uncertainty_raises():
    """Test that empty uncertainty string raises validation error."""
    with pytest.raises(ValueError):
        ContextAnalysis(
            incident_id="INC-2024-CTX",
            contextual_assessment="Assessment.",
            indicators=[],
            relevant_factors=[],
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            explanation="Explanation.",
            uncertainty="",  # Invalid - min_length=1
            confidence=0.5,
        )


@pytest.mark.asyncio
async def test_context_agent_format_prompt(sample_incident):
    """Test prompt placeholder formatting."""
    mock_provider = MockLLMProvider(
        response=ContextAnalysis(
            incident_id="INC-2024-CTX",
            contextual_assessment="Test.",
            indicators=[],
            relevant_factors=[],
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            explanation="Test.",
            uncertainty="Test.",
            confidence=0.5,
        )
    )

    llm_client = LLMClient(provider=mock_provider)
    agent = ContextAgent(llm_client=llm_client)

    prompt = agent._format_prompt(sample_incident)

    assert "INC-2024-CTX" in prompt
    assert "Context Analysis Incident" in prompt
    assert "EVT-001" in prompt
    assert "powershell.exe" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
