"""Unit tests for Threat Hunter Agent.

Tests cover evidence discovery, contradiction detection, edge cases, and error handling.
"""

import pytest
from datetime import datetime, timedelta

from app.agents.threat_hunter import ThreatHunterAgent, ThreatHunterAnalysis
from app.agents.investigator import InvestigatorAnalysis
from app.schemas.detection import DetectionResult, CorrelatedIncident
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.schemas.graph import AttackGraph, GraphNode, IncidentTimeline, TimelineEntry
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
    """Comprehensive event set with both investigated and uninvestigated events."""
    return [
        # Events likely investigated
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
        # Additional events for hunter to discover
        NormalizedEvent(
            event_id="EVT-005",
            source="auth_log",
            timestamp=base_timestamp + timedelta(minutes=-20),
            event_type="suspicious_login_attempt",
            actor="admin",
            target="server-01",
            severity_hint=Severity.LOW,
            attributes={"description": "Login attempt from same external IP, 20 min before main attack"},
            raw_event_id="raw-005",
        ),
        NormalizedEvent(
            event_id="EVT-006",
            source="firewall_log",
            timestamp=base_timestamp + timedelta(minutes=8),
            event_type="network_connection",
            actor="server-01",
            target="192.168.1.50",
            severity_hint=Severity.MEDIUM,
            attributes={"description": "Connection to C2 infrastructure IP range"},
            raw_event_id="raw-006",
        ),
        NormalizedEvent(
            event_id="EVT-007",
            source="process_log",
            timestamp=base_timestamp + timedelta(minutes=13),
            event_type="file_access",
            actor="admin",
            target="server-01",
            severity_hint=Severity.HIGH,
            attributes={"description": "Suspicious access to credential store"},
            raw_event_id="raw-007",
        ),
        # Event that might contradict hypothesis
        NormalizedEvent(
            event_id="EVT-008",
            source="vpn_log",
            timestamp=base_timestamp + timedelta(minutes=12),
            event_type="vpn_disconnect",
            actor="admin",
            target="vpn-gw",
            severity_hint=Severity.LOW,
            attributes={"description": "Admin VPN session terminated, suggesting legitimate logout"},
            raw_event_id="raw-008",
        ),
        # Additional background event
        NormalizedEvent(
            event_id="EVT-009",
            source="system_log",
            timestamp=base_timestamp + timedelta(minutes=3),
            event_type="system_event",
            actor="system",
            target="server-01",
            severity_hint=Severity.LOW,
            attributes={"description": "Regular system maintenance"},
            raw_event_id="raw-009",
        ),
    ]


@pytest.fixture
def sample_detections(sample_normalized_events):
    """Detection results for subset of events."""
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
            description="Suspicious command execution",
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
        DetectionResult(
            detection_id="DET-005",
            event_id="EVT-006",
            threat_type="c2_communication",
            category=ThreatCategory.EXECUTION,
            severity=Severity.CRITICAL,
            confidence=0.88,
            indicators=["known_c2_ip"],
            description="Communication with C2 infrastructure",
        ),
    ]


@pytest.fixture
def sample_correlated_incident(base_timestamp, sample_normalized_events, sample_detections):
    """Sample correlated incident with multiple events."""
    return CorrelatedIncident(
        incident_id="INC-2024-001",
        title="Credential Compromise and Data Exfiltration",
        summary="Admin account compromised with suspicious activity and data transfer",
        related_event_ids=[f"EVT-{i:03d}" for i in range(1, 10)],
        detections=sample_detections,
        normalized_events=sample_normalized_events,
        first_seen=base_timestamp - timedelta(minutes=20),
        last_seen=base_timestamp + timedelta(minutes=15),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def investigator_analysis():
    """Sample investigator analysis with hypothesis."""
    return InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Admin credentials compromised via brute force, enabling attacker to execute commands and exfiltrate data.",
        summary="Failed login attempts preceded successful access from unusual IP, followed by suspicious process execution and data transfer.",
        reasoning="EVT-001 failed logins, EVT-002 successful from new IP, EVT-003 cmd.exe execution, EVT-004 data transfer.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        observed_facts=[
            "Failed logins to admin account (EVT-001)",
            "Successful login from external IP (EVT-002)",
            "Command execution by admin (EVT-003)",
            "Data transfer to external IP (EVT-004)",
        ],
        suspected_attack_type="AUTHENTICATION",
        uncertainty="Cannot confirm attacker identity or full data scope without network logs.",
        confidence=0.88,
    )


@pytest.fixture
def sample_attack_graph():
    """Sample attack graph."""
    return AttackGraph(
        incident_id="INC-2024-001",
        nodes=[
            GraphNode(node_id="N-001", label="Attacker", node_type="ip"),
            GraphNode(node_id="N-002", label="server-01", node_type="host"),
            GraphNode(node_id="N-003", label="admin", node_type="user"),
            GraphNode(node_id="N-004", label="external-ip", node_type="ip"),
        ],
        edges=[],
        entry_point="N-001",
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
                description="Failed login attempts",
                severity=Severity.MEDIUM,
            ),
            TimelineEntry(
                entry_id="TL-002",
                timestamp=base_timestamp + timedelta(minutes=5),
                event_id="EVT-002",
                stage="execution",
                description="Successful login",
                severity=Severity.HIGH,
            ),
        ],
    )


@pytest.fixture
def valid_threat_hunter_response():
    """Valid threat hunter analysis response."""
    return ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="If credentials were compromised, we should find early reconnaissance attempts and command-and-control communications.",
        findings="Found early suspicious login attempt (EVT-005) 20 minutes before main attack and C2 communication (EVT-006) during execution phase. These strongly support the credential compromise hypothesis.",
        discovered_evidence_ids=["EVT-005", "EVT-006"],
        supporting_evidence_ids=["EVT-007"],
        contradicting_evidence_ids=["EVT-008"],
        unexplored_areas=[
            "Check if other admin accounts were targeted",
            "Search for lateral movement to other servers",
            "Look for persistence mechanisms installed",
        ],
        confidence=0.82,
        uncertainty="VPN disconnect (EVT-008) timing is ambiguous - could be legitimate logout or attacker cover.",
    )


# ============================================================================
# Test Cases
# ============================================================================


@pytest.mark.asyncio
async def test_threat_hunter_finds_related_events(
    sample_correlated_incident,
    investigator_analysis,
    sample_attack_graph,
    sample_incident_timeline,
    valid_threat_hunter_response,
):
    """Test that threat hunter discovers related events."""
    mock_provider = MockLLMProvider(response=valid_threat_hunter_response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    # Run hunt
    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    # Should find additional evidence
    assert len(analysis.discovered_evidence_ids) > 0
    assert "EVT-005" in analysis.discovered_evidence_ids
    assert "EVT-006" in analysis.discovered_evidence_ids


@pytest.mark.asyncio
async def test_threat_hunter_finds_multiple_clues(
    sample_correlated_incident,
    investigator_analysis,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test that hunter finds multiple types of evidence."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Testing multiple discovery paths.",
        findings="Multiple clues discovered across different event types.",
        discovered_evidence_ids=["EVT-005", "EVT-006", "EVT-007"],
        supporting_evidence_ids=["EVT-005", "EVT-006"],
        contradicting_evidence_ids=[],
        unexplored_areas=["Check for persistence", "Search for lateral movement"],
        confidence=0.85,
        uncertainty="Some events may have alternative interpretations.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    assert len(analysis.discovered_evidence_ids) == 3
    assert len(analysis.supporting_evidence_ids) == 2


@pytest.mark.asyncio
async def test_threat_hunter_no_additional_evidence(
    sample_correlated_incident,
    investigator_analysis,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test when no additional evidence is found."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Investigator already found all available evidence.",
        findings="All events align with investigator's hypothesis. No contradictions detected.",
        discovered_evidence_ids=[],
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        unexplored_areas=["Would need external threat intel", "Need cross-correlation with other incidents"],
        confidence=0.7,
        uncertainty="No additional evidence in provided logs. Investigator appears to have comprehensive view.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    assert len(analysis.discovered_evidence_ids) == 0
    assert len(analysis.supporting_evidence_ids) == 0


@pytest.mark.asyncio
async def test_threat_hunter_invalid_llm_output():
    """Test handling of invalid LLM output."""
    invalid_response = {"invalid": "structure"}

    mock_provider = MockLLMProvider(response=invalid_response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

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

    incident = CorrelatedIncident(
        incident_id="INC-TEST",
        title="Test",
        summary="Test",
        related_event_ids=["EVT-1"],
        detections=[detection],
        normalized_events=[
            NormalizedEvent(
                event_id="EVT-1",
                source="test",
                timestamp=datetime.now(),
                event_type="test",
                attributes={},
                raw_event_id="raw-1",
            )
        ],
        first_seen=datetime.now(),
        last_seen=datetime.now(),
        primary_category=ThreatCategory.UNKNOWN,
        severity=Severity.LOW,
    )

    investigator = InvestigatorAnalysis(
        incident_id="INC-TEST",
        hypothesis="Test hypothesis.",
        summary="Test.",
        reasoning="Test.",
        supporting_evidence_ids=[],
        observed_facts=[],
        suspected_attack_type="UNKNOWN",
        uncertainty="None.",
        confidence=0.5,
    )

    with pytest.raises(LLMOutputParseError):
        await agent.hunt(incident=incident, investigator_analysis=investigator)


@pytest.mark.asyncio
async def test_threat_hunter_hallucinated_event_ids(
    sample_correlated_incident,
    investigator_analysis,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test handling of hallucinated event IDs."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Testing hallucination handling.",
        findings="Some events were imagined by the model.",
        discovered_evidence_ids=["EVT-005", "EVT-FAKE-999", "EVT-006"],
        supporting_evidence_ids=["EVT-001", "EVT-NONEXISTENT"],
        contradicting_evidence_ids=["EVT-008"],
        unexplored_areas=[],
        confidence=0.5,
        uncertainty="Model may have hallucinated some events.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    # Invalid IDs should be removed
    assert "EVT-FAKE-999" not in analysis.discovered_evidence_ids
    assert "EVT-NONEXISTENT" not in analysis.supporting_evidence_ids
    # Valid IDs should remain
    assert "EVT-005" in analysis.discovered_evidence_ids
    assert "EVT-006" in analysis.discovered_evidence_ids


@pytest.mark.asyncio
async def test_threat_hunter_contradicting_evidence(
    sample_correlated_incident,
    investigator_analysis,
    sample_attack_graph,
    sample_incident_timeline,
):
    """Test discovery of evidence that contradicts hypothesis."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Investigating for contradictory evidence.",
        findings="Found events that challenge credential compromise hypothesis. VPN disconnect suggests legitimate activity.",
        discovered_evidence_ids=[],
        supporting_evidence_ids=["EVT-005", "EVT-006"],
        contradicting_evidence_ids=["EVT-008"],
        unexplored_areas=["Need to verify VPN logs", "Check admin activity elsewhere"],
        confidence=0.65,
        uncertainty="Contradiction makes hypothesis less certain but not impossible.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    # Should identify contradicting evidence
    assert len(analysis.contradicting_evidence_ids) > 0
    assert "EVT-008" in analysis.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_threat_hunter_confidence_bounds():
    """Test that confidence is within valid bounds."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Test.",
        findings="Test.",
        discovered_evidence_ids=[],
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        unexplored_areas=[],
        confidence=0.5,  # Valid
        uncertainty="Test.",
    )

    # Should validate without error
    assert 0.0 <= response.confidence <= 1.0


@pytest.mark.asyncio
async def test_threat_hunter_empty_uncertainty_raises():
    """Test that empty uncertainty field raises validation error."""
    with pytest.raises(ValueError):
        ThreatHunterAnalysis(
            incident_id="INC-2024-001",
            search_reason="Test.",
            findings="Test.",
            discovered_evidence_ids=[],
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            unexplored_areas=[],
            confidence=0.5,
            uncertainty="",  # Invalid - must be min_length=1
        )


@pytest.mark.asyncio
async def test_threat_hunter_format_prompt(
    sample_correlated_incident,
    investigator_analysis,
):
    """Test that prompt is formatted correctly."""
    mock_provider = MockLLMProvider(
        response=ThreatHunterAnalysis(
            incident_id="INC-2024-001",
            search_reason="Test search.",
            findings="Test findings.",
            discovered_evidence_ids=[],
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            unexplored_areas=[],
            confidence=0.5,
            uncertainty="Test uncertainty.",
        )
    )

    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    # Test prompt formatting
    prompt = agent._format_prompt(sample_correlated_incident, investigator_analysis)

    # Prompt should contain incident and investigator data
    assert "INC-2024-001" in prompt
    assert "Credential Compromise" in prompt
    assert "Admin credentials compromised" in prompt


@pytest.mark.asyncio
async def test_threat_hunter_all_evidence_lists(
    sample_correlated_incident,
    investigator_analysis,
):
    """Test that all evidence lists are properly populated."""
    response = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Comprehensive evidence search.",
        findings="Found new evidence, confirmed existing, and identified contradictions.",
        discovered_evidence_ids=["EVT-005"],
        supporting_evidence_ids=["EVT-006", "EVT-007"],
        contradicting_evidence_ids=["EVT-008"],
        unexplored_areas=["Check persistence"],
        confidence=0.75,
        uncertainty="Some ambiguity in interpretation.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = ThreatHunterAgent(llm_client=llm_client)

    analysis = await agent.hunt(
        incident=sample_correlated_incident,
        investigator_analysis=investigator_analysis,
    )

    # All three lists should have content
    assert len(analysis.discovered_evidence_ids) == 1
    assert len(analysis.supporting_evidence_ids) == 2
    assert len(analysis.contradicting_evidence_ids) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
