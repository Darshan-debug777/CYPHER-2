"""Unit and Integration tests for LLMInvestigationService.

Tests cover:
1. Complete sequential flow (Investigator -> Threat Hunter -> Context -> Skeptic -> Verification)
2. Proper data propagation between agent stages
3. Deterministic evidence verification & hallucination purging
4. Uncertainty and revised confidence propagation
5. Schema compliance of output InvestigationResult
6. Error handling on agent failures / invalid LLM outputs
7. Orchestrator integration test with full 8-stage pipeline using real multi-agent service
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.agents.context import ContextAgent, ContextAnalysis
from app.agents.investigator import InvestigatorAgent, InvestigatorAnalysis
from app.agents.skeptic import SkepticAgent, SkepticAnalysis
from app.agents.threat_hunter import ThreatHunterAgent, ThreatHunterAnalysis
from app.core.errors import InvalidModuleOutputError
from app.factory import ServiceContainer
from app.orchestrator.pipeline import InvestigationOrchestrator
from app.schemas.api import InvestigateRequest
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.enums import IncidentStatus, Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.schemas.graph import AttackGraph, GraphNode, IncidentTimeline, TimelineEntry
from app.schemas.investigation import Evidence, InvestigationResult
from app.services.llm_client import LLMClient, MockLLMProvider
from app.services.llm_investigation import LLMInvestigationService


@pytest.fixture
def base_timestamp():
    """Base timestamp for incident events."""
    return datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def sample_events(base_timestamp):
    """Sample normalized events across the intrusion lifecycle."""
    return [
        NormalizedEvent(
            event_id="EVT-001",
            source="auth_log",
            timestamp=base_timestamp,
            event_type="failed_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"src_ip": "203.0.113.45", "raw_message": "Failed login attempt for admin"},
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
            attributes={"src_ip": "203.0.113.45", "raw_message": "Successful login from external IP"},
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
            attributes={"process": "powershell.exe", "raw_message": "powershell.exe spawned with encoded command"},
            raw_event_id="raw-003",
        ),
        NormalizedEvent(
            event_id="EVT-004",
            source="network_log",
            timestamp=base_timestamp + timedelta(minutes=15),
            event_type="data_transfer",
            actor="server-01",
            target="192.168.1.100",
            severity_hint=Severity.CRITICAL,
            attributes={"bytes": 50000000, "raw_message": "Large data transfer to external IP"},
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
            description="Failed login indicates credential attack attempt",
        ),
        DetectionResult(
            detection_id="DET-002",
            event_id="EVT-002",
            threat_type="account_compromise",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            confidence=0.85,
            indicators=["unusual_ip"],
            description="Account compromised after credential attack",
        ),
        DetectionResult(
            detection_id="DET-003",
            event_id="EVT-003",
            threat_type="command_execution",
            category=ThreatCategory.EXECUTION,
            severity=Severity.HIGH,
            confidence=0.90,
            indicators=["powershell_encoded"],
            description="Suspicious command execution",
        ),
        DetectionResult(
            detection_id="DET-004",
            event_id="EVT-004",
            threat_type="data_exfiltration",
            category=ThreatCategory.EXFILTRATION,
            severity=Severity.CRITICAL,
            confidence=0.95,
            indicators=["large_transfer"],
            description="Data exfiltration to external system",
        ),
    ]


@pytest.fixture
def sample_incident(base_timestamp, sample_events, sample_detections):
    """Sample correlated incident."""
    return CorrelatedIncident(
        incident_id="INC-2024-MULTI",
        title="Multi-Stage Credential Intrusion",
        summary="Admin credentials compromised leading to execution and exfiltration",
        related_event_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        detections=sample_detections,
        normalized_events=sample_events,
        first_seen=base_timestamp,
        last_seen=base_timestamp + timedelta(minutes=15),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def sample_graph():
    """Sample attack graph."""
    return AttackGraph(
        incident_id="INC-2024-MULTI",
        nodes=[
            GraphNode(node_id="N-001", label="203.0.113.45", node_type="ip"),
            GraphNode(node_id="N-002", label="server-01", node_type="host"),
            GraphNode(node_id="N-003", label="admin", node_type="user"),
        ],
        edges=[],
        entry_point="N-001",
        objective="data_theft",
    )


@pytest.fixture
def sample_timeline(base_timestamp):
    """Sample incident timeline."""
    return IncidentTimeline(
        incident_id="INC-2024-MULTI",
        entries=[
            TimelineEntry(
                entry_id="TL-001",
                timestamp=base_timestamp,
                event_id="EVT-001",
                stage="initial_access",
                description="Brute force login attempts",
                severity=Severity.MEDIUM,
                mitre_technique="T1110",
            ),
            TimelineEntry(
                entry_id="TL-002",
                timestamp=base_timestamp + timedelta(minutes=5),
                event_id="EVT-002",
                stage="execution",
                description="Successful login from unusual IP",
                severity=Severity.HIGH,
                mitre_technique="T1078",
            ),
            TimelineEntry(
                entry_id="TL-003",
                timestamp=base_timestamp + timedelta(minutes=10),
                event_id="EVT-003",
                stage="execution",
                description="PowerShell execution",
                severity=Severity.HIGH,
                mitre_technique="T1059.001",
            ),
            TimelineEntry(
                entry_id="TL-004",
                timestamp=base_timestamp + timedelta(minutes=15),
                event_id="EVT-004",
                stage="exfiltration",
                description="Data transfer to external IP",
                severity=Severity.CRITICAL,
                mitre_technique="T1048",
            ),
        ],
        attack_chain=["T1110", "T1078", "T1059.001", "T1048"],
    )


@pytest.fixture
def mock_agent_responses():
    """Mock structured responses for all 4 agents."""
    investigator_resp = InvestigatorAnalysis(
        incident_id="INC-2024-MULTI",
        hypothesis="Admin account compromised via brute force followed by PowerShell command execution.",
        summary="Attacker gained admin access from external IP and executed malicious scripts.",
        reasoning="EVT-001 failed login, EVT-002 login success, EVT-003 process execution.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        observed_facts=["Failed logins on server-01", "PowerShell executed by admin"],
        suspected_attack_type="AUTHENTICATION",
        uncertainty="Network exfiltration volume unverified.",
        confidence=0.88,
    )

    hunter_resp = ThreatHunterAnalysis(
        incident_id="INC-2024-MULTI",
        search_reason="Searched for exfiltration and lateral movement following credential access.",
        findings="Discovered data transfer EVT-004 matching exfiltration stage.",
        discovered_evidence_ids=["EVT-004"],
        supporting_evidence_ids=["EVT-002", "EVT-003"],
        contradicting_evidence_ids=[],
        unexplored_areas=["Search for persistence scheduled tasks"],
        confidence=0.85,
        uncertainty="Need firewall logs to verify C2 destination.",
    )

    context_resp = ContextAnalysis(
        incident_id="INC-2024-MULTI",
        contextual_assessment="Activity represents significant anomaly relative to baseline admin habits.",
        indicators=["External non-VPN source IP", "PowerShell spawned from unusual parent"],
        relevant_factors=["User admin possesses domain admin rights"],
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003"],
        contradicting_evidence_ids=[],
        explanation="Admin user has never authenticated from 203.0.113.45 in the last 90 days.",
        uncertainty="Historical off-hours change schedule not available.",
        confidence=0.90,
    )

    skeptic_resp = SkepticAnalysis(
        incident_id="INC-2024-MULTI",
        verdict="STRENGTHEN",
        critique_summary="Evidence strongly supports compromise; benign administrative alternatives are highly improbable.",
        supporting_evidence_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        contradicting_evidence_ids=[],
        alternative_explanations=["Low possibility of unauthorized penetration test"],
        missing_information=["Command line arguments of PowerShell process"],
        investigation_weaknesses=["Lack of process memory dump"],
        revised_confidence=0.86,
        uncertainty="Pending process argument confirmation.",
    )

    return investigator_resp, hunter_resp, context_resp, skeptic_resp


# ============================================================================
# Unit Tests
# ============================================================================


@pytest.mark.asyncio
async def test_llm_investigation_service_full_flow(
    sample_incident,
    sample_graph,
    sample_timeline,
    mock_agent_responses,
):
    """Test full multi-agent flow: Investigator -> Hunter -> Context -> Skeptic -> Verification."""
    inv_resp, hunt_resp, ctx_resp, skp_resp = mock_agent_responses

    inv_agent = InvestigatorAgent(llm_client=LLMClient(provider=MockLLMProvider(response=inv_resp)))
    hunt_agent = ThreatHunterAgent(llm_client=LLMClient(provider=MockLLMProvider(response=hunt_resp)))
    ctx_agent = ContextAgent(llm_client=LLMClient(provider=MockLLMProvider(response=ctx_resp)))
    skp_agent = SkepticAgent(llm_client=LLMClient(provider=MockLLMProvider(response=skp_resp)))

    service = LLMInvestigationService(
        investigator=inv_agent,
        threat_hunter=hunt_agent,
        context_agent=ctx_agent,
        skeptic=skp_agent,
    )

    result = await service.investigate(sample_incident, sample_graph, sample_timeline)

    # Verify schema compliance
    assert isinstance(result, InvestigationResult)
    assert result.incident_id == "INC-2024-MULTI"
    assert result.threat_classification == ThreatCategory.AUTHENTICATION
    assert result.severity == Severity.CRITICAL
    assert len(result.evidence) >= 1
    assert len(result.agents_used) == 4
    assert "InvestigatorAgent" in result.agents_used
    assert "ThreatHunterAgent" in result.agents_used
    assert "ContextAgent" in result.agents_used
    assert "SkepticAgent" in result.agents_used

    # All 4 verified events must be present in evidence
    evidence_ids = {e.event_id for e in result.evidence}
    assert {"EVT-001", "EVT-002", "EVT-003", "EVT-004"}.issubset(evidence_ids)

    # Confidence must reflect calibrated score from skeptic
    for ev in result.evidence:
        assert 0.0 <= ev.confidence <= 1.0
        assert ev.confidence == pytest.approx(0.86, rel=1e-2)

    # Explanation must include sections from all agents
    assert "Primary Hypothesis (Investigator)" in result.explanation
    assert "Proactive Threat Hunt (Threat Hunter)" in result.explanation
    assert "Context & Baseline Assessment (Context Agent)" in result.explanation
    assert "Critical Evaluation (Skeptic Agent" in result.explanation
    assert "Evidence Verification" in result.explanation


@pytest.mark.asyncio
async def test_llm_investigation_service_hallucination_purging(
    sample_incident,
    sample_graph,
    sample_timeline,
    mock_agent_responses,
):
    """Test that hallucinated event IDs across any agent are purged from final Evidence list."""
    inv_resp, hunt_resp, ctx_resp, skp_resp = mock_agent_responses

    # Inject hallucinated IDs into responses
    inv_hallucinated = inv_resp.model_copy(
        update={"supporting_evidence_ids": ["EVT-001", "EVT-FAKE-111"]}
    )
    hunt_hallucinated = hunt_resp.model_copy(
        update={"discovered_evidence_ids": ["EVT-004", "EVT-GHOST-222"]}
    )

    inv_agent = InvestigatorAgent(llm_client=LLMClient(provider=MockLLMProvider(response=inv_hallucinated)))
    hunt_agent = ThreatHunterAgent(llm_client=LLMClient(provider=MockLLMProvider(response=hunt_hallucinated)))
    ctx_agent = ContextAgent(llm_client=LLMClient(provider=MockLLMProvider(response=ctx_resp)))
    skp_agent = SkepticAgent(llm_client=LLMClient(provider=MockLLMProvider(response=skp_resp)))

    service = LLMInvestigationService(
        investigator=inv_agent,
        threat_hunter=hunt_agent,
        context_agent=ctx_agent,
        skeptic=skp_agent,
    )

    result = await service.investigate(sample_incident, sample_graph, sample_timeline)

    evidence_ids = {e.event_id for e in result.evidence}
    assert "EVT-FAKE-111" not in evidence_ids
    assert "EVT-GHOST-222" not in evidence_ids
    assert "EVT-001" in evidence_ids
    assert "EVT-004" in evidence_ids


@pytest.mark.asyncio
async def test_llm_investigation_service_weaken_verdict_propagation(
    sample_incident,
    sample_graph,
    sample_timeline,
    mock_agent_responses,
):
    """Test skeptic WEAKEN verdict updates evidence confidence and records alternative explanations."""
    inv_resp, hunt_resp, ctx_resp, _ = mock_agent_responses

    skp_weaken = SkepticAnalysis(
        incident_id="INC-2024-MULTI",
        verdict="WEAKEN",
        critique_summary="Hypothesis is heavily challenged by scheduled administrative maintenance records.",
        supporting_evidence_ids=["EVT-001"],
        contradicting_evidence_ids=["EVT-002"],
        alternative_explanations=["Scheduled system backup and healthcheck script", "Password typo"],
        missing_information=["PowerShell script arguments"],
        investigation_weaknesses=["Investigator ignored maintenance window"],
        revised_confidence=0.35,
        uncertainty="High uncertainty due to strong alternative explanations.",
    )

    inv_agent = InvestigatorAgent(llm_client=LLMClient(provider=MockLLMProvider(response=inv_resp)))
    hunt_agent = ThreatHunterAgent(llm_client=LLMClient(provider=MockLLMProvider(response=hunt_resp)))
    ctx_agent = ContextAgent(llm_client=LLMClient(provider=MockLLMProvider(response=ctx_resp)))
    skp_agent = SkepticAgent(llm_client=LLMClient(provider=MockLLMProvider(response=skp_weaken)))

    service = LLMInvestigationService(
        investigator=inv_agent,
        threat_hunter=hunt_agent,
        context_agent=ctx_agent,
        skeptic=skp_agent,
    )

    result = await service.investigate(sample_incident, sample_graph, sample_timeline)

    # Revised lower confidence must propagate
    for ev in result.evidence:
        assert ev.confidence == pytest.approx(0.35, rel=1e-2)

    # Alternative explanations must appear in explanation
    assert "Scheduled system backup" in result.explanation
    assert "Verdict: WEAKEN" in result.explanation


@pytest.mark.asyncio
async def test_llm_investigation_service_empty_events_fallback(
    sample_graph,
    sample_timeline,
    sample_detections,
    mock_agent_responses,
):
    """Test investigation when normalized_events is empty but detections exist."""
    inv_resp, hunt_resp, ctx_resp, skp_resp = mock_agent_responses

    incident_no_events = CorrelatedIncident(
        incident_id="INC-NO-EVENTS",
        title="Detection Only Incident",
        summary="Detections present without normalized raw events",
        related_event_ids=["EVT-001"],
        detections=sample_detections,
        normalized_events=[],
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.HIGH,
    )

    inv_agent = InvestigatorAgent(llm_client=LLMClient(provider=MockLLMProvider(response=inv_resp)))
    hunt_agent = ThreatHunterAgent(llm_client=LLMClient(provider=MockLLMProvider(response=hunt_resp)))
    ctx_agent = ContextAgent(llm_client=LLMClient(provider=MockLLMProvider(response=ctx_resp)))
    skp_agent = SkepticAgent(llm_client=LLMClient(provider=MockLLMProvider(response=skp_resp)))

    service = LLMInvestigationService(
        investigator=inv_agent,
        threat_hunter=hunt_agent,
        context_agent=ctx_agent,
        skeptic=skp_agent,
    )

    result = await service.investigate(incident_no_events, sample_graph, sample_timeline)
    assert len(result.evidence) >= 1
    assert result.incident_id == "INC-NO-EVENTS"


# ============================================================================
# Integration Test (Orchestrator + Real Multi-Agent Investigation Layer)
# ============================================================================


@pytest.mark.asyncio
async def test_full_pipeline_with_real_multi_agent_investigation(mock_agent_responses):
    """Integration test proving the full 8-stage pipeline coordinates successfully
    with the real multi-agent investigation layer (Investigator -> Hunter -> Context -> Skeptic).
    """
    inv_resp, hunt_resp, ctx_resp, skp_resp = mock_agent_responses

    inv_agent = InvestigatorAgent(llm_client=LLMClient(provider=MockLLMProvider(response=inv_resp)))
    hunt_agent = ThreatHunterAgent(llm_client=LLMClient(provider=MockLLMProvider(response=hunt_resp)))
    ctx_agent = ContextAgent(llm_client=LLMClient(provider=MockLLMProvider(response=ctx_resp)))
    skp_agent = SkepticAgent(llm_client=LLMClient(provider=MockLLMProvider(response=skp_resp)))

    real_investigation_service = LLMInvestigationService(
        investigator=inv_agent,
        threat_hunter=hunt_agent,
        context_agent=ctx_agent,
        skeptic=skp_agent,
    )

    # Inject real multi-agent service into orchestrator container
    services = ServiceContainer(
        investigation=real_investigation_service,
    )
    orchestrator = InvestigationOrchestrator(services=services)

    # Run investigation pipeline using sample logs
    request = InvestigateRequest(use_sample_logs=True)
    final_incident = await orchestrator.investigate(request)

    # Assert complete end-to-end incident properties
    assert final_incident.incident_id.startswith("INC-")
    assert final_incident.status == IncidentStatus.AWAITING_APPROVAL
    assert final_incident.investigation is not None
    assert len(final_incident.investigation.evidence) >= 1
    assert len(final_incident.investigation.agents_used) == 4
    assert "InvestigatorAgent" in final_incident.investigation.agents_used
    assert "SkepticAgent" in final_incident.investigation.agents_used
    assert final_incident.risk is not None
    assert final_incident.response is not None
    assert len(final_incident.response.actions) >= 1
    assert final_incident.report is not None
    assert len(final_incident.audit_trail) >= 8


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
