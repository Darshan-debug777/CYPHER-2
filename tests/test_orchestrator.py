"""Orchestrator and mock pipeline tests."""

import pytest

from app.orchestrator.pipeline import InvestigationOrchestrator
from app.schemas.api import InvestigateRequest
from app.schemas.enums import IncidentStatus, Severity, ThreatCategory


@pytest.mark.asyncio
async def test_full_mock_pipeline():
    orchestrator = InvestigationOrchestrator()
    result = await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))

    assert result.incident_id.startswith("INC-")
    assert result.status == IncidentStatus.AWAITING_APPROVAL
    assert result.investigation.threat_classification == ThreatCategory.LATERAL_MOVEMENT
    assert result.investigation.severity == Severity.CRITICAL
    assert len(result.investigation.evidence) >= 5
    assert result.risk.risk_score > 0
    assert len(result.response.actions) >= 3
    assert result.report.markdown_content
    assert len(result.audit_trail) >= 5


@pytest.mark.asyncio
async def test_pipeline_produces_attack_graph_and_timeline():
    orchestrator = InvestigationOrchestrator()
    result = await orchestrator.investigate(InvestigateRequest())

    assert result.investigation.attack_graph is not None
    assert len(result.investigation.attack_graph.nodes) >= 5
    assert result.investigation.timeline is not None
    assert len(result.investigation.timeline.entries) >= 5
    assert len(result.investigation.mitre_techniques) >= 5
