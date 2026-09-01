"""Unit tests for Skeptic Agent.

Tests cover hypothesis strengthening, weakening with benign alternatives, unchanged verdict,
multi-agent integration, error handling, hallucination prevention, and prompt formatting.
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.agents.context import ContextAnalysis
from app.agents.investigator import InvestigatorAnalysis
from app.agents.skeptic import SkepticAgent, SkepticAnalysis
from app.agents.threat_hunter import ThreatHunterAnalysis
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.services.llm_client import LLMClient, LLMOutputParseError, MockLLMProvider


@pytest.fixture
def base_timestamp():
    """Base timestamp for skeptic events."""
    return datetime(2024, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_normalized_events(base_timestamp):
    """Comprehensive event set for skeptic testing."""
    return [
        NormalizedEvent(
            event_id="EVT-001",
            source="auth_log",
            timestamp=base_timestamp,
            event_type="failed_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"src_ip": "203.0.113.45"},
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
            attributes={"src_ip": "203.0.113.45"},
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
            attributes={"process": "powershell.exe"},
            raw_event_id="raw-003",
        ),
        NormalizedEvent(
            event_id="EVT-004",
            source="vpn_log",
            timestamp=base_timestamp + timedelta(minutes=12),
            event_type="vpn_disconnect",
            actor="admin",
            target="vpn-gw",
            severity_hint=Severity.LOW,
            attributes={"reason": "user_initiated_logout"},
            raw_event_id="raw-004",
        ),
        NormalizedEvent(
            event_id="EVT-005",
            source="maintenance_log",
            timestamp=base_timestamp - timedelta(hours=1),
            event_type="scheduled_patch",
            actor="system",
            target="server-01",
            severity_hint=Severity.LOW,
            attributes={"change_ticket": "CHG-9921"},
            raw_event_id="raw-005",
        ),
    ]


@pytest.fixture
def sample_detections():
    """Sample detections for skeptic testing."""
    return [
        DetectionResult(
            detection_id="DET-001",
            event_id="EVT-001",
            threat_type="credential_attack",
            category=ThreatCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=0.75,
            indicators=["failed_logins"],
            description="Brute force attempt",
        ),
        DetectionResult(
            detection_id="DET-002",
            event_id="EVT-002",
            threat_type="account_compromise",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            confidence=0.85,
            indicators=["external_ip"],
            description="Compromised account access",
        ),
    ]


@pytest.fixture
def sample_incident(base_timestamp, sample_normalized_events, sample_detections):
    """Sample correlated incident."""
    return CorrelatedIncident(
        incident_id="INC-2024-SKP",
        title="Admin Intrusion vs Maintenance",
        summary="Admin access from unusual location followed by process execution",
        related_event_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004", "EVT-005"],
        detections=sample_detections,
        normalized_events=sample_normalized_events,
        first_seen=base_timestamp - timedelta(hours=1),
        last_seen=base_timestamp + timedelta(minutes=12),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.HIGH,
    )


@pytest.fixture
def sample_investigator_analysis():
    """Sample InvestigatorAnalysis output."""
    return InvestigatorAnalysis(
        incident_id="INC-2024-SKP",
        hypothesis="Admin credentials were stolen and used to gain unauthorized shell access.",
        summary="Attacker brute-forced credentials and launched PowerShell on server-01.",
        reasoning="EVT-001 failed login, EVT-002 successful login, EVT-003 powershell execution.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        observed_facts=["Failed login", "Success login from new IP", "PowerShell executed"],
        suspected_attack_type="CREDENTIAL_ACCESS",
        uncertainty="Attacker identity unconfirmed.",
        confidence=0.88,
    )


@pytest.fixture
def sample_threat_hunter_analysis():
    """Sample ThreatHunterAnalysis output."""
    return ThreatHunterAnalysis(
        incident_id="INC-2024-SKP",
        search_reason="Searched for additional evidence supporting or contradicting compromise.",
        findings="Found VPN disconnect (EVT-004) and pre-scheduled patch change ticket (EVT-005).",
        discovered_evidence_ids=["EVT-004", "EVT-005"],
        supporting_evidence_ids=["EVT-002", "EVT-003"],
        contradicting_evidence_ids=["EVT-004", "EVT-005"],
        unexplored_areas=["Verify change ticket approval in ITSM"],
        confidence=0.75,
        uncertainty="Contradicting evidence introduces operational ambiguity.",
    )


@pytest.fixture
def sample_context_analysis():
    """Sample ContextAnalysis output."""
    return ContextAnalysis(
        incident_id="INC-2024-SKP",
        contextual_assessment="Mixed context; admin user known to conduct remote maintenance during change windows.",
        indicators=["Authorized change ticket CHG-9921", "User-initiated VPN disconnect"],
        relevant_factors=["User admin is on-call systems engineer"],
        supporting_evidence_ids=["EVT-003"],
        contradicting_evidence_ids=["EVT-004", "EVT-005"],
        explanation="The timing closely aligns with approved change ticket CHG-9921.",
        uncertainty="Need ITSM change management log to confirm exact script executed.",
        confidence=0.70,
    )


# ============================================================================
# Test Cases
# ============================================================================


@pytest.mark.asyncio
async def test_skeptic_weaken_hypothesis(
    sample_incident,
    sample_investigator_analysis,
    sample_threat_hunter_analysis,
    sample_context_analysis,
):
    """Test skeptic identifies strong benign explanations and weakens confidence."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="WEAKEN",
        critique_summary=(
            "The hypothesis of malicious credential compromise is significantly weakened by "
            "scheduled change ticket CHG-9921 (EVT-005) and clean user-initiated logout (EVT-004)."
        ),
        supporting_evidence_ids=["EVT-001", "EVT-002"],
        contradicting_evidence_ids=["EVT-004", "EVT-005"],
        alternative_explanations=[
            "Authorized sysadmin performing emergency off-hours maintenance per change ticket CHG-9921",
            "Typo during first login attempt followed by successful authenticated VPN session",
        ],
        missing_information=[
            "ITSM change ticket task description",
            "Command-line arguments executed by powershell.exe",
        ],
        investigation_weaknesses=[
            "Investigator assumed malicious intent without cross-referencing maintenance records",
            "Failed login attempt may simply be an everyday password typo",
        ],
        revised_confidence=0.45,
        uncertainty="Cannot confirm malicious intent until PowerShell command parameters are retrieved.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
        threat_hunter_analysis=sample_threat_hunter_analysis,
        context_analysis=sample_context_analysis,
    )

    assert critique.verdict == "WEAKEN"
    assert critique.revised_confidence < sample_investigator_analysis.confidence
    assert len(critique.alternative_explanations) == 2
    assert "EVT-004" in critique.contradicting_evidence_ids
    assert "EVT-005" in critique.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_skeptic_strengthen_hypothesis(
    sample_incident,
    sample_investigator_analysis,
):
    """Test skeptic strengthens hypothesis when evidence is irrefutable."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="STRENGTHEN",
        critique_summary="No credible benign explanation exists for unauthorized PowerShell execution from unknown external IP.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        contradicting_evidence_ids=[],
        alternative_explanations=[],
        missing_information=["Outbound network payload capture"],
        investigation_weaknesses=["None identified; evidence sequence is solid"],
        revised_confidence=0.94,
        uncertainty="Minimal; malicious pattern is unambiguous.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
    )

    assert critique.verdict == "STRENGTHEN"
    assert critique.revised_confidence >= sample_investigator_analysis.confidence
    assert len(critique.contradicting_evidence_ids) == 0


@pytest.mark.asyncio
async def test_skeptic_unchanged_hypothesis(
    sample_incident,
    sample_investigator_analysis,
):
    """Test skeptic leaves hypothesis confidence unchanged when evidence is balanced."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="UNCHANGED",
        critique_summary="The investigator's hypothesis remains plausible and adequately calibrated.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        contradicting_evidence_ids=[],
        alternative_explanations=["Low probability of administrative error"],
        missing_information=["Full endpoint telemetry"],
        investigation_weaknesses=["Minor reliance on single log source"],
        revised_confidence=0.88,
        uncertainty="Standard telemetry gaps present.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
    )

    assert critique.verdict == "UNCHANGED"
    assert critique.revised_confidence == sample_investigator_analysis.confidence


@pytest.mark.asyncio
async def test_skeptic_insufficient_information_gaps(
    sample_incident,
    sample_investigator_analysis,
):
    """Test skeptic identifies critical missing information and gaps."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="WEAKEN",
        critique_summary="Significant information gaps prevent definitive conclusion.",
        supporting_evidence_ids=["EVT-002"],
        contradicting_evidence_ids=[],
        alternative_explanations=["Unknown remote user activity"],
        missing_information=[
            "Command-line audit logging (Event ID 4688)",
            "Network flow logs for outbound connections",
            "MFA challenge logs for external session",
        ],
        investigation_weaknesses=["Hypothesis jumps from login to compromise without intermediate process lineage"],
        revised_confidence=0.50,
        uncertainty="High uncertainty due to absent endpoint visibility.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
    )

    assert len(critique.missing_information) == 3
    assert "Command-line audit logging" in critique.missing_information[0]


@pytest.mark.asyncio
async def test_skeptic_multi_agent_integration(
    sample_incident,
    sample_investigator_analysis,
    sample_threat_hunter_analysis,
    sample_context_analysis,
):
    """Test skeptic incorporates findings across Investigator, ThreatHunter, and ContextAgent."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="WEAKEN",
        critique_summary="Synthesized findings across all three agents indicate strong likelihood of authorized maintenance.",
        supporting_evidence_ids=["EVT-003"],
        contradicting_evidence_ids=["EVT-004", "EVT-005"],
        alternative_explanations=["Scheduled maintenance task CHG-9921"],
        missing_information=["ITSM ticket approval"],
        investigation_weaknesses=["Investigator missed change ticket context"],
        revised_confidence=0.52,
        uncertainty="Pending ticket confirmation.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
        threat_hunter_analysis=sample_threat_hunter_analysis,
        context_analysis=sample_context_analysis,
    )

    assert critique.incident_id == "INC-2024-SKP"
    assert len(critique.contradicting_evidence_ids) == 2


@pytest.mark.asyncio
async def test_skeptic_invalid_llm_output(
    sample_incident,
    sample_investigator_analysis,
):
    """Test handling of invalid LLM output structure."""
    invalid_response = {"broken": "output"}

    mock_provider = MockLLMProvider(response=invalid_response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    with pytest.raises(LLMOutputParseError):
        await agent.critique(
            incident=sample_incident,
            investigator_analysis=sample_investigator_analysis,
        )


@pytest.mark.asyncio
async def test_skeptic_hallucinated_event_ids(
    sample_incident,
    sample_investigator_analysis,
):
    """Test that hallucinated event IDs are removed from skeptic output."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="WEAKEN",
        critique_summary="Testing hallucination filter in skeptic agent.",
        supporting_evidence_ids=["EVT-001", "EVT-HALLUCINATED-999"],
        contradicting_evidence_ids=["EVT-004", "EVT-GHOST-777"],
        alternative_explanations=["Test alternative"],
        missing_information=["Test missing"],
        investigation_weaknesses=["Test weakness"],
        revised_confidence=0.60,
        uncertainty="None.",
    )

    mock_provider = MockLLMProvider(response=response)
    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    critique = await agent.critique(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
    )

    # Hallucinated IDs must be filtered
    assert "EVT-HALLUCINATED-999" not in critique.supporting_evidence_ids
    assert "EVT-GHOST-777" not in critique.contradicting_evidence_ids
    # Valid IDs must remain
    assert "EVT-001" in critique.supporting_evidence_ids
    assert "EVT-004" in critique.contradicting_evidence_ids


@pytest.mark.asyncio
async def test_skeptic_confidence_bounds():
    """Test confidence validation bounds."""
    response = SkepticAnalysis(
        incident_id="INC-2024-SKP",
        verdict="UNCHANGED",
        critique_summary="Valid critique.",
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        alternative_explanations=[],
        missing_information=[],
        investigation_weaknesses=[],
        revised_confidence=0.65,
        uncertainty="Valid uncertainty.",
    )
    assert 0.0 <= response.revised_confidence <= 1.0


@pytest.mark.asyncio
async def test_skeptic_empty_uncertainty_raises():
    """Test that empty uncertainty string raises validation error."""
    with pytest.raises(ValueError):
        SkepticAnalysis(
            incident_id="INC-2024-SKP",
            verdict="UNCHANGED",
            critique_summary="Summary.",
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            alternative_explanations=[],
            missing_information=[],
            investigation_weaknesses=[],
            revised_confidence=0.5,
            uncertainty="",  # Invalid - min_length=1
        )


@pytest.mark.asyncio
async def test_skeptic_format_prompt(
    sample_incident,
    sample_investigator_analysis,
    sample_threat_hunter_analysis,
    sample_context_analysis,
):
    """Test prompt placeholder formatting with all agents."""
    mock_provider = MockLLMProvider(
        response=SkepticAnalysis(
            incident_id="INC-2024-SKP",
            verdict="UNCHANGED",
            critique_summary="Test.",
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            alternative_explanations=[],
            missing_information=[],
            investigation_weaknesses=[],
            revised_confidence=0.5,
            uncertainty="Test.",
        )
    )

    llm_client = LLMClient(provider=mock_provider)
    agent = SkepticAgent(llm_client=llm_client)

    prompt = agent._format_prompt(
        incident=sample_incident,
        investigator_analysis=sample_investigator_analysis,
        threat_hunter_analysis=sample_threat_hunter_analysis,
        context_analysis=sample_context_analysis,
    )

    assert "INC-2024-SKP" in prompt
    assert "Admin Intrusion vs Maintenance" in prompt
    assert "Admin credentials were stolen" in prompt
    assert "CHG-9921" in prompt
    assert "EVT-001" in prompt


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
