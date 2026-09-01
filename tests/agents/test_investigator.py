"""Unit tests for Investigator Agent.

Tests cover normal investigation, edge cases, error handling, and validation.
"""

import pytest
from datetime import datetime, timedelta

from app.agents.investigator import InvestigatorAgent, InvestigatorAnalysis
from app.schemas.detection import DetectionResult, CorrelatedIncident
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.schemas.graph import AttackGraph, GraphNode, GraphEdge, IncidentTimeline, TimelineEntry
from app.services.llm_client import MockLLMProvider, LLMClient, LLMOutputParseError


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def base_timestamp():
    """Base timestamp for events."""
    return datetime(2024, 1, 15, 10, 0, 0)


@pytest.fixture
def sample_normalized_events(base_timestamp):
    """Sample normalized events."""
    return [
        NormalizedEvent(
            event_id="EVT-001",
            source="auth_log",
            timestamp=base_timestamp,
            event_type="failed_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"description": "Failed login attempt for admin account"},
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
            attributes={"description": "Successful login from unusual IP"},
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
            attributes={"description": "Suspicious process cmd.exe started"},
            raw_event_id="raw-003",
        ),
        NormalizedEvent(
            event_id="EVT-004",
            source="network_log",
            timestamp=base_timestamp + timedelta(minutes=15),
            event_type="data_transfer",
            actor="server-01",
            target="external-ip-192.168.1.100",
            severity_hint=Severity.CRITICAL,
            attributes={"description": "Large data transfer to external IP"},
            raw_event_id="raw-004",
        ),
    ]


@pytest.fixture
def sample_detections(sample_normalized_events):
    """Sample detection results."""
    return [
        DetectionResult(
            detection_id="DET-001",
            event_id="EVT-001",
            threat_type="credential_attack",
            category=ThreatCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=0.75,
            indicators=["multiple_failed_attempts"],
            description="Failed login indicates credential attack attempt",
        ),
        DetectionResult(
            detection_id="DET-002",
            event_id="EVT-002",
            threat_type="account_compromise",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            confidence=0.85,
            indicators=["unusual_ip", "successful_after_failures"],
            description="Account compromised after credential attack",
        ),
        DetectionResult(
            detection_id="DET-003",
            event_id="EVT-003",
            threat_type="command_execution",
            category=ThreatCategory.EXECUTION,
            severity=Severity.HIGH,
            confidence=0.90,
            indicators=["cmd_exe_suspicious"],
            description="Suspicious command execution by compromised account",
        ),
        DetectionResult(
            detection_id="DET-004",
            event_id="EVT-004",
            threat_type="data_exfiltration",
            category=ThreatCategory.EXFILTRATION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            indicators=["large_transfer", "external_ip"],
            description="Data exfiltration to external system",
        ),
    ]


@pytest.fixture
def sample_correlated_incident(base_timestamp, sample_normalized_events, sample_detections):
    """Sample correlated incident."""
    return CorrelatedIncident(
        incident_id="INC-2024-001",
        title="Credential Compromise and Data Exfiltration",
        summary="Admin account compromised with suspicious process execution and data transfer",
        related_event_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        detections=sample_detections,
        normalized_events=sample_normalized_events,
        first_seen=base_timestamp,
        last_seen=base_timestamp + timedelta(minutes=15),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def sample_attack_graph():
    """Sample attack graph."""
    return AttackGraph(
        incident_id="INC-2024-001",
        nodes=[
            GraphNode(
                node_id="N-001",
                label="Attacker",
                node_type="ip",
                attributes={"ip": "192.168.1.50"},
            ),
            GraphNode(
                node_id="N-002",
                label="server-01",
                node_type="host",
                attributes={"os": "Windows", "role": "admin_server"},
            ),
            GraphNode(
                node_id="N-003",
                label="admin",
                node_type="user",
                attributes={"privileged": "true"},
            ),
            GraphNode(
                node_id="N-004",
                label="external-ip-192.168.1.100",
                node_type="ip",
                attributes={"ip": "192.168.1.100"},
            ),
        ],
        edges=[
            GraphEdge(
                edge_id="E-001",
                source_id="N-001",
                target_id="N-003",
                relationship="credential_attack",
                event_id="EVT-001",
                timestamp=datetime(2024, 1, 15, 10, 0, 0),
            ),
            GraphEdge(
                edge_id="E-002",
                source_id="N-003",
                target_id="N-002",
                relationship="authenticated_to",
                event_id="EVT-002",
                timestamp=datetime(2024, 1, 15, 10, 5, 0),
            ),
            GraphEdge(
                edge_id="E-003",
                source_id="N-002",
                target_id="N-004",
                relationship="data_transfer",
                event_id="EVT-004",
                timestamp=datetime(2024, 1, 15, 10, 15, 0),
            ),
        ],
        entry_point="N-001",
        objective="data_theft",
    )


@pytest.fixture
def sample_incident_timeline(base_timestamp):
    """Sample incident timeline."""
    return IncidentTimeline(
        incident_id="INC-2024-001",
        entries=[
            TimelineEntry(
                entry_id="TL-001",
                timestamp=base_timestamp,
                event_id="EVT-001",
                stage="initial_access",
                description="Attacker attempts credential compromise",
                severity=Severity.MEDIUM,
                mitre_technique="T1078",
            ),
            TimelineEntry(
                entry_id="TL-002",
                timestamp=base_timestamp + timedelta(minutes=5),
                event_id="EVT-002",
                stage="execution",
                description="Compromised admin account logs in from unusual location",
                severity=Severity.HIGH,
                mitre_technique="T1021",
            ),
            TimelineEntry(
                entry_id="TL-003",
                timestamp=base_timestamp + timedelta(minutes=10),
                event_id="EVT-003",
                stage="impact",
                description="Suspicious command execution on compromised host",
                severity=Severity.HIGH,
                mitre_technique="T1059",
            ),
            TimelineEntry(
                entry_id="TL-004",
                timestamp=base_timestamp + timedelta(minutes=15),
                event_id="EVT-004",
                stage="exfiltration",
                description="Data transfer to external system",
                severity=Severity.CRITICAL,
                mitre_technique="T1048",
            ),
        ],
        attack_chain=["T1078", "T1021", "T1059", "T1048"],
    )


@pytest.fixture
def valid_investigator_response():
    """Valid response from investigator analysis."""
    return InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Admin credentials were compromised via brute force attack, enabling attacker to log in, execute commands, and exfiltrate data.",
        summary="Attacker initiated a brute force attack on the admin account, gained access, executed suspicious commands, and transferred sensitive data to an external system.",
        reasoning=(
            "Timeline shows failed login (EVT-001) followed by successful login from unusual IP (EVT-002), "
            "then immediate suspicious process execution (EVT-003), and finally data transfer to external IP (EVT-004). "
            "This progression is consistent with credential compromise leading to command execution and exfiltration."
        ),
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        observed_facts=[
            "Multiple failed login attempts targeting admin account (EVT-001)",
            "Successful login from unusual IP after failed attempts (EVT-002)",
            "Command execution by admin account immediately after login (EVT-003)",
            "Large data transfer to external IP (EVT-004)",
        ],
        suspected_attack_type="AUTHENTICATION",
        uncertainty="Timeline is clear but we cannot confirm attacker identity or full scope of exfiltration without network logs.",
        confidence=0.88,
    )


# ============================================================================
# Test Cases
# ============================================================================


@pytest.mark.asyncio
async def test_investigator_normal_investigation(
    sample_correlated_incident,
    sample_attack_graph,
    sample_incident_timeline,
    valid_investigator_response,
):
    """Test normal investigation with valid incident and data."""
    # Setup mock LLM to return valid response
    mock_provider = MockLLMProvider(response=valid_investigator_response)
    llm_client = LLMClient(provider=mock_provider)

    agent = InvestigatorAgent(llm_client=llm_client)

    # Run investigation
    analysis = await agent.investigate(
        incident=sample_correlated_incident,
        graph=sample_attack_graph,
        timeline=sample_incident_timeline,
    )

    # Verify output
    assert analysis.incident_id == "INC-2024-001"
    assert analysis.confidence >= 0.8
    assert len(analysis.supporting_evidence_ids) >= 1
    assert len(analysis.observed_facts) >= 1
    assert analysis.uncertainty != ""
    assert "EVT-001" in analysis.supporting_evidence_ids


@pytest.mark.asyncio
async def test_investigator_multiple_evidence_events(
    sample_correlated_incident,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test investigation with multiple evidence events."""
    # Response with all events as supporting evidence
    response = InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Multi-stage attack with credential compromise, execution, and exfiltration.",
        summary="Comprehensive attack chain observed across four distinct stages.",
        reasoning="All events connected chronologically and logically.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        observed_facts=[
            f"Event EVT-001: {e.event_type}"
            for e in sample_correlated_incident.normalized_events
        ],
        suspected_attack_type="LATERAL_MOVEMENT",
        uncertainty="Minimal uncertainty given clear attack chain.",
        confidence=0.92,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    analysis = await agent.investigate(
        incident=sample_correlated_incident,
        graph=sample_attack_graph,
        timeline=sample_incident_timeline,
    )

    # All four events should be in supporting evidence
    assert len(analysis.supporting_evidence_ids) == 4
    assert all(f"EVT-{i:03d}" in analysis.supporting_evidence_ids for i in range(1, 5))


@pytest.mark.asyncio
async def test_investigator_no_evidence():
    """Test investigation with no normalized events but valid incident structure."""
    # Create incident with minimal data (required by schema)
    single_detection = DetectionResult(
        detection_id="DET-001",
        event_id="EVT-001",
        threat_type="suspicious",
        category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
        confidence=0.5,
        indicators=[],
        description="Minimal detection",
    )

    incident = CorrelatedIncident(
        incident_id="INC-2024-002",
        title="Minimal Evidence Incident",
        summary="Incident with single minimal event",
        related_event_ids=["EVT-001"],
        detections=[single_detection],
        normalized_events=[],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        primary_category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
    )

    valid_graph = AttackGraph(
        incident_id="INC-2024-002",
        nodes=[GraphNode(node_id="N-1", label="host", node_type="host")],
        edges=[],
        entry_point="N-1",
    )

    timeline = IncidentTimeline(
        incident_id="INC-2024-002",
        entries=[
            TimelineEntry(
                entry_id="TL-1",
                timestamp=datetime.now(),
                event_id="EVT-001",
                stage="unknown",
                description="Minimal event",
                severity=Severity.LOW,
            )
        ],
    )

    response = InvestigatorAnalysis(
        incident_id="INC-2024-002",
        hypothesis="Minimal data available to form hypothesis.",
        summary="Insufficient evidence to analyze.",
        reasoning="No events were recorded for this incident.",
        supporting_evidence_ids=[],
        observed_facts=["No normalized events available"],
        suspected_attack_type="UNKNOWN",
        uncertainty="Complete uncertainty due to lack of evidence.",
        confidence=0.1,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    # Should work but with low confidence
    analysis = await agent.investigate(
        incident=incident,
        graph=valid_graph,
        timeline=timeline,
    )

    assert analysis.confidence <= 0.2
    assert len(analysis.supporting_evidence_ids) == 0


@pytest.mark.asyncio
async def test_investigator_invalid_llm_output():
    """Test handling of invalid LLM output."""
    # Mock provider that returns non-InvestigatorAnalysis object
    invalid_response = {"invalid": "structure"}

    mock_provider = MockLLMProvider(response=invalid_response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    # Create valid incident with minimal data
    detection = DetectionResult(
        detection_id="DET-001",
        event_id="EVT-1",
        threat_type="test",
        category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
        confidence=0.5,
        indicators=[],
        description="Test",
    )

    event = NormalizedEvent(
        event_id="EVT-1",
        source="test",
        timestamp=datetime.now(),
        event_type="test",
        attributes={},
        raw_event_id="raw-1",
    )

    incident = CorrelatedIncident(
        incident_id="INC-2024-003",
        title="Test",
        summary="Test",
        related_event_ids=["EVT-1"],
        detections=[detection],
        normalized_events=[event],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        primary_category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
    )

    graph = AttackGraph(
        incident_id="INC-2024-003",
        nodes=[GraphNode(node_id="N-1", label="h", node_type="host")],
        edges=[],
        entry_point="N-1",
    )

    timeline = IncidentTimeline(
        incident_id="INC-2024-003",
        entries=[
            TimelineEntry(
                entry_id="TL-1",
                timestamp=datetime.now(),
                event_id="EVT-1",
                stage="test",
                description="test",
                severity=Severity.LOW,
            )
        ],
    )

    # Should raise error when trying to cast to InvestigatorAnalysis
    with pytest.raises(LLMOutputParseError):
        await agent.investigate(
            incident=incident,
            graph=graph,
            timeline=timeline,
        )


@pytest.mark.asyncio
async def test_investigator_hallucinated_evidence_ids(
    sample_correlated_incident,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test handling of hallucinated/non-existent evidence IDs."""
    # Response that references non-existent events
    response = InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Attack occurred but references invalid events.",
        summary="Test hallucination handling.",
        reasoning="Invalid event IDs should be filtered out.",
        supporting_evidence_ids=[
            "EVT-001",
            "EVT-INVALID-1",
            "EVT-002",
            "EVT-FAKE-999",
        ],
        observed_facts=[
            "Valid event EVT-001",
            "Invalid event EVT-INVALID-1",
        ],
        suspected_attack_type="UNKNOWN",
        uncertainty="Agent hallucinated evidence.",
        confidence=0.5,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    analysis = await agent.investigate(
        incident=sample_correlated_incident,
        graph=sample_attack_graph,
        timeline=sample_incident_timeline,
    )

    # Invalid IDs should be removed
    assert "EVT-INVALID-1" not in analysis.supporting_evidence_ids
    assert "EVT-FAKE-999" not in analysis.supporting_evidence_ids
    # Valid IDs should remain
    assert "EVT-001" in analysis.supporting_evidence_ids
    assert "EVT-002" in analysis.supporting_evidence_ids


@pytest.mark.asyncio
async def test_investigator_uncertain_incident(
    sample_correlated_incident,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test investigation with high uncertainty."""
    # Response with high uncertainty
    response = InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Possible credential compromise, but could also be legitimate admin activity.",
        summary="Ambiguous incident with multiple plausible interpretations.",
        reasoning="Events are consistent with credential compromise OR legitimate admin accessing from new location.",
        supporting_evidence_ids=["EVT-001", "EVT-002"],
        observed_facts=[
            "Failed login attempt (EVT-001) - could be user error",
            "Login from unusual IP (EVT-002) - could be VPN or travel",
        ],
        suspected_attack_type="CREDENTIAL_ACCESS",
        uncertainty=(
            "High uncertainty: Failed login could be user error (typo). "
            "Successful login from new IP could be legitimate admin traveling. "
            "Need more context: Is admin known to travel? Was VPN used? "
            "Missing: Geo-IP data, endpoint detection, account login history."
        ),
        confidence=0.45,
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    analysis = await agent.investigate(
        incident=sample_correlated_incident,
        graph=sample_attack_graph,
        timeline=sample_incident_timeline,
    )

    # Should express low confidence in uncertain situation
    assert analysis.confidence < 0.6
    assert "uncertainty" in analysis.uncertainty.lower()
    assert len(analysis.uncertainty) > 50  # Should explain uncertainty in detail


@pytest.mark.asyncio
async def test_investigator_confidence_bounds():
    """Test that confidence is always within 0.0-1.0 bounds."""
    response = InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Test incident.",
        summary="Testing confidence bounds.",
        reasoning="Confidence must be between 0 and 1.",
        supporting_evidence_ids=[],
        observed_facts=[],
        suspected_attack_type="UNKNOWN",
        uncertainty="None.",
        confidence=0.75,  # Valid
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    # Should be valid
    assert 0.0 <= response.confidence <= 1.0


@pytest.mark.asyncio
async def test_investigator_empty_uncertainty_raises():
    """Test that empty uncertainty field raises validation error."""
    # InvestigatorAnalysis requires non-empty uncertainty
    with pytest.raises(ValueError):
        InvestigatorAnalysis(
            incident_id="INC-2024-001",
            hypothesis="Test.",
            summary="Test.",
            reasoning="Test.",
            supporting_evidence_ids=[],
            observed_facts=[],
            suspected_attack_type="UNKNOWN",
            uncertainty="",  # Invalid - must be min_length=1
            confidence=0.5,
        )


@pytest.mark.asyncio
async def test_investigator_format_prompt():
    """Test that prompt is formatted correctly."""
    detection = DetectionResult(
        detection_id="DET-1",
        event_id="EVT-1",
        threat_type="test",
        category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
        confidence=0.5,
        indicators=[],
        description="Test",
    )

    event = NormalizedEvent(
        event_id="EVT-1",
        source="test",
        timestamp=datetime.now(),
        event_type="test_event",
        attributes={"description": "Test description"},
        raw_event_id="raw-1",
    )

    incident = CorrelatedIncident(
        incident_id="INC-TEST-001",
        title="Test Incident",
        summary="Test summary",
        related_event_ids=["EVT-1"],
        detections=[detection],
        normalized_events=[event],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        primary_category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
    )

    graph = AttackGraph(
        incident_id="INC-TEST-001",
        nodes=[GraphNode(node_id="N-1", label="test", node_type="host")],
        edges=[],
        entry_point="N-1",
        objective="test",
    )

    timeline = IncidentTimeline(
        incident_id="INC-TEST-001",
        entries=[
            TimelineEntry(
                entry_id="TL-1",
                timestamp=datetime.now(),
                event_id="EVT-1",
                stage="test",
                description="test",
                severity=Severity.LOW,
            )
        ],
    )

    mock_provider = MockLLMProvider(
        response=InvestigatorAnalysis(
            incident_id="INC-TEST-001",
            hypothesis="Test.",
            summary="Test.",
            reasoning="Test.",
            supporting_evidence_ids=["EVT-1"],
            observed_facts=["Test fact"],
            suspected_attack_type="UNKNOWN",
            uncertainty="None",
            confidence=0.5,
        )
    )

    llm_client = LLMClient(provider=mock_provider)
    agent = InvestigatorAgent(llm_client=llm_client)

    # Verify prompt formatting by checking internal method
    prompt = agent._format_prompt(incident, graph, timeline)

    # Prompt should contain incident data
    assert "INC-TEST-001" in prompt
    assert "Test Incident" in prompt
    assert "EVT-1" in prompt
    assert "test_event" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
