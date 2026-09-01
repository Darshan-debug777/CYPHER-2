"""Mock AI investigation agents (Log Analysis + Threat Investigation)."""

import logging

from app.core.errors import InvalidModuleOutputError
from app.schemas.detection import CorrelatedIncident
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.graph import AttackGraph, IncidentTimeline
from app.schemas.investigation import Evidence, InvestigationResult

logger = logging.getLogger(__name__)


class MockInvestigationService:
    async def investigate(
        self,
        incident: CorrelatedIncident,
        graph: AttackGraph,
        timeline: IncidentTimeline,
    ) -> InvestigationResult:
        if not incident.detections:
            raise InvalidModuleOutputError("investigation", "No detections to investigate")

        evidence: list[Evidence] = []
        for idx, detection in enumerate(incident.detections):
            event = next(
                (e for e in incident.normalized_events if e.event_id == detection.event_id),
                None,
            )
            snippet = event.attributes.get("raw_message", detection.description) if event else detection.description
            if isinstance(snippet, dict):
                snippet = detection.description

            evidence.append(
                Evidence(
                    evidence_id=f"ev-{idx+1:03d}",
                    event_id=detection.event_id,
                    source=event.source if event else "unknown",
                    description=detection.description,
                    snippet=str(snippet)[:500],
                    confidence=detection.confidence,
                    supports=f"Supports classification: {detection.threat_type}",
                )
            )

        explanation = (
            "Log Analysis Agent identified a brute-force authentication pattern (3 failed logins) "
            "followed by a successful login from external IP 203.0.113.45. "
            "Threat Investigation Agent correlated subsequent VPN access, PowerShell execution, "
            "SMB lateral movement to FILE-SERVER-01, and access to /finance/Q1_reports.xlsx. "
            "This sequence matches a credential-based intrusion progressing to data collection."
        )

        result = InvestigationResult(
            incident_id=incident.incident_id,
            summary=incident.summary,
            threat_classification=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.CRITICAL,
            evidence=evidence,
            explanation=explanation,
            mitre_techniques=timeline.attack_chain,
            attack_progression=[e.stage for e in timeline.entries],
            agents_used=["Log Analysis Agent", "Threat Investigation Agent"],
            timeline=timeline,
            attack_graph=graph,
        )

        logger.info("Mock investigation completed for %s", incident.incident_id)
        return result
