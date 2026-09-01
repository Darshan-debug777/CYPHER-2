"""LLM Investigation Service - Multi-Agent Investigation Adapter.

Connects Investigator, Threat Hunter, Context, and Skeptic agents with
deterministic evidence verification to implement the InvestigationService protocol.
"""

import logging
from typing import Any

from app.agents.context import ContextAgent, ContextAnalysis
from app.agents.investigator import InvestigatorAgent, InvestigatorAnalysis
from app.agents.skeptic import SkepticAgent, SkepticAnalysis
from app.agents.threat_hunter import ThreatHunterAgent, ThreatHunterAnalysis
from app.core.errors import InvalidModuleOutputError
from app.core.verification import EvidenceVerifier, VerificationResult
from app.schemas.detection import CorrelatedIncident
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.graph import AttackGraph, IncidentTimeline
from app.schemas.investigation import Evidence, InvestigationResult
from app.services.llm_client import LLMClient

logger = logging.getLogger(__name__)

# Mapping from string representations to ThreatCategory enum
_CATEGORY_MAP: dict[str, ThreatCategory] = {
    "authentication": ThreatCategory.AUTHENTICATION,
    "credential_access": ThreatCategory.AUTHENTICATION,
    "lateral_movement": ThreatCategory.LATERAL_MOVEMENT,
    "execution": ThreatCategory.EXECUTION,
    "command_execution": ThreatCategory.EXECUTION,
    "exfiltration": ThreatCategory.EXFILTRATION,
    "privilege_escalation": ThreatCategory.PRIVILEGE_ESCALATION,
    "reconnaissance": ThreatCategory.RECONNAISSANCE,
}


class LLMInvestigationService:
    """Multi-agent investigation service coordinating four AI agents and evidence verification.

    Executes in sequence:
    1. InvestigatorAgent (Hypothesis generation)
    2. ThreatHunterAgent (Proactive clue discovery)
    3. ContextAgent (Baseline and normality analysis)
    4. SkepticAgent (Critique, alternatives, and confidence calibration)
    5. EvidenceVerifier (Deterministic anti-hallucination verification)
    """

    def __init__(
        self,
        llm_client: LLMClient | None = None,
        investigator: InvestigatorAgent | None = None,
        threat_hunter: ThreatHunterAgent | None = None,
        context_agent: ContextAgent | None = None,
        skeptic: SkepticAgent | None = None,
    ):
        """Initialize service with custom or default agents and LLM client."""
        self.llm_client = llm_client or LLMClient()
        self.investigator = investigator or InvestigatorAgent(llm_client=self.llm_client)
        self.threat_hunter = threat_hunter or ThreatHunterAgent(llm_client=self.llm_client)
        self.context_agent = context_agent or ContextAgent(llm_client=self.llm_client)
        self.skeptic = skeptic or SkepticAgent(llm_client=self.llm_client)

    async def investigate(
        self,
        incident: CorrelatedIncident,
        graph: AttackGraph,
        timeline: IncidentTimeline,
    ) -> InvestigationResult:
        """Run full multi-agent investigation pipeline on an incident.

        Args:
            incident: CorrelatedIncident with normalized events and detections
            graph: AttackGraph of the incident
            timeline: Chronological IncidentTimeline

        Returns:
            InvestigationResult with verified evidence and multi-agent synthesis
        """
        if not incident.normalized_events and not incident.detections:
            raise InvalidModuleOutputError("investigation", "No events or detections to investigate")

        logger.info(f"Starting multi-agent investigation for incident {incident.incident_id}")

        # Step 1: Investigator Agent
        investigator_analysis = await self.investigator.investigate(incident, graph, timeline)

        # Step 2: Threat Hunter Agent (receives investigator hypothesis)
        threat_hunter_analysis = await self.threat_hunter.hunt(incident, investigator_analysis)

        # Step 3: Context Agent (analyzes event normality and environment context)
        context_analysis = await self.context_agent.analyze(incident)

        # Step 4: Skeptic Agent (receives findings from all previous agents)
        skeptic_analysis = await self.skeptic.critique(
            incident=incident,
            investigator_analysis=investigator_analysis,
            threat_hunter_analysis=threat_hunter_analysis,
            context_analysis=context_analysis,
        )

        # Step 5: Evidence Verification (Deterministic validation against incident events)
        agent_outputs = {
            "Investigator": investigator_analysis,
            "ThreatHunter": threat_hunter_analysis,
            "Context": context_analysis,
            "Skeptic": skeptic_analysis,
        }
        verification_result = EvidenceVerifier.verify_incident(incident, agent_outputs)

        # Step 6: Assemble verified Evidence objects
        evidence_items = self._build_verified_evidence(
            incident=incident,
            investigator_analysis=investigator_analysis,
            threat_hunter_analysis=threat_hunter_analysis,
            context_analysis=context_analysis,
            skeptic_analysis=skeptic_analysis,
            verification_result=verification_result,
        )

        # Step 7: Map threat classification safely
        threat_classification = self._resolve_threat_category(
            investigator_analysis.suspected_attack_type,
            incident.primary_category,
        )

        # Step 8: Multi-Agent Explanation Synthesis
        explanation = self._synthesize_explanation(
            investigator=investigator_analysis,
            threat_hunter=threat_hunter_analysis,
            context=context_analysis,
            skeptic=skeptic_analysis,
            verification=verification_result,
        )

        # Step 9: Assemble final InvestigationResult
        result = InvestigationResult(
            incident_id=incident.incident_id,
            summary=investigator_analysis.summary,
            threat_classification=threat_classification,
            severity=incident.severity,
            evidence=evidence_items,
            explanation=explanation,
            mitre_techniques=timeline.attack_chain if timeline else [],
            attack_progression=[e.stage for e in timeline.entries] if timeline else [],
            agents_used=[
                "InvestigatorAgent",
                "ThreatHunterAgent",
                "ContextAgent",
                "SkepticAgent",
            ],
            timeline=timeline,
            attack_graph=graph,
        )

        logger.info(
            f"Multi-agent investigation completed for {incident.incident_id}: "
            f"{len(evidence_items)} verified evidence items, "
            f"threat_category={threat_classification.value}, "
            f"skeptic_verdict={skeptic_analysis.verdict}"
        )
        return result

    def _build_verified_evidence(
        self,
        incident: CorrelatedIncident,
        investigator_analysis: InvestigatorAnalysis,
        threat_hunter_analysis: ThreatHunterAnalysis,
        context_analysis: ContextAnalysis,
        skeptic_analysis: SkepticAnalysis,
        verification_result: VerificationResult,
    ) -> list[Evidence]:
        """Build verified Evidence instances strictly referencing valid incident event IDs."""
        verified_event_ids = set(verification_result.verified_event_ids)

        # Priority ordering of referenced event IDs
        ordered_ids: list[str] = []
        for eid in investigator_analysis.supporting_evidence_ids:
            if eid in verified_event_ids and eid not in ordered_ids:
                ordered_ids.append(eid)

        for eid in threat_hunter_analysis.discovered_evidence_ids:
            if eid in verified_event_ids and eid not in ordered_ids:
                ordered_ids.append(eid)

        for eid in context_analysis.supporting_evidence_ids:
            if eid in verified_event_ids and eid not in ordered_ids:
                ordered_ids.append(eid)

        for eid in skeptic_analysis.supporting_evidence_ids:
            if eid in verified_event_ids and eid not in ordered_ids:
                ordered_ids.append(eid)

        for eid in verified_event_ids:
            if eid not in ordered_ids:
                ordered_ids.append(eid)

        # Index events and detections for lookup
        events_by_id = {e.event_id: e for e in incident.normalized_events}
        detections_by_id = {d.event_id: d for d in incident.detections}

        evidence_items: list[Evidence] = []
        base_confidence = min(max(skeptic_analysis.revised_confidence, 0.1), 1.0)

        for idx, eid in enumerate(ordered_ids):
            event = events_by_id.get(eid)
            detection = detections_by_id.get(eid)

            source = event.source if event else "detection"
            description = (
                (event.attributes.get("description") or f"Observed {event.event_type} on {event.target or 'target'}")
                if event
                else (detection.description if detection else f"Event {eid}")
            )

            raw_snippet = ""
            if event:
                raw_snippet = event.attributes.get("raw_message") or event.attributes.get("description") or str(event.attributes)
            elif detection:
                raw_snippet = detection.description
            else:
                raw_snippet = f"Verified event {eid}"

            snippet = str(raw_snippet)[:500] if raw_snippet else description

            # Specific claim support explanation
            supports_claim = f"Supports hypothesis: {investigator_analysis.hypothesis[:80]}..."
            if threat_hunter_analysis and eid in threat_hunter_analysis.discovered_evidence_ids:
                supports_claim = f"Discovered clue: {threat_hunter_analysis.findings[:80]}..."

            evidence_items.append(
                Evidence(
                    evidence_id=f"ev-{idx+1:03d}",
                    event_id=eid,
                    source=source,
                    description=str(description)[:200],
                    snippet=snippet,
                    confidence=base_confidence,
                    supports=supports_claim,
                )
            )

        # Fallback if no specific agent claims were verified but incident events exist
        if not evidence_items and incident.normalized_events:
            first_event = incident.normalized_events[0]
            evidence_items.append(
                Evidence(
                    evidence_id="ev-001",
                    event_id=first_event.event_id,
                    source=first_event.source,
                    description=f"Incident baseline event: {first_event.event_type}",
                    snippet=str(first_event.attributes.get("raw_message", first_event.event_type))[:500],
                    confidence=0.2,
                    supports="Baseline observation; individual agent claims were unverified or inconclusive.",
                )
            )
        elif not evidence_items and incident.detections:
            first_det = incident.detections[0]
            evidence_items.append(
                Evidence(
                    evidence_id="ev-001",
                    event_id=first_det.event_id,
                    source="detection",
                    description=first_det.description,
                    snippet=first_det.description[:500],
                    confidence=first_det.confidence,
                    supports="Baseline detection record.",
                )
            )

        return evidence_items

    @staticmethod
    def _resolve_threat_category(
        suspected_type: str,
        fallback: ThreatCategory,
    ) -> ThreatCategory:
        """Map suspected attack string to ThreatCategory enum."""
        clean = suspected_type.lower().strip().replace(" ", "_").replace("-", "_")
        return _CATEGORY_MAP.get(clean, fallback)

    @staticmethod
    def _synthesize_explanation(
        investigator: InvestigatorAnalysis,
        threat_hunter: ThreatHunterAnalysis,
        context: ContextAnalysis,
        skeptic: SkepticAnalysis,
        verification: VerificationResult,
    ) -> str:
        """Synthesize findings from all four agents into a unified, coherent explanation."""
        sections = [
            f"### Primary Hypothesis (Investigator)\n{investigator.hypothesis}\n{investigator.reasoning}",
            f"### Proactive Threat Hunt (Threat Hunter)\n{threat_hunter.findings}\nSearch rationale: {threat_hunter.search_reason}",
            f"### Context & Baseline Assessment (Context Agent)\n{context.contextual_assessment}\n{context.explanation}",
            f"### Critical Evaluation (Skeptic Agent — Verdict: {skeptic.verdict})\n{skeptic.critique_summary}",
        ]

        if skeptic.alternative_explanations:
            alt_text = "\n".join(f"- {alt}" for alt in skeptic.alternative_explanations)
            sections.append(f"### Plausible Alternative Explanations\n{alt_text}")

        if skeptic.missing_information:
            missing_text = "\n".join(f"- {item}" for item in skeptic.missing_information)
            sections.append(f"### Missing Telemetry & Gaps\n{missing_text}")

        verification_note = (
            f"### Evidence Verification\n"
            f"Verified {verification.verified_count} evidence claims across agents. "
            f"Status: {verification.verification_status.value}."
        )
        if verification.invalid_event_ids:
            verification_note += f" Discarded unverified references: {', '.join(verification.invalid_event_ids)}."
        sections.append(verification_note)

        uncertainty_note = skeptic.uncertainty or investigator.uncertainty
        if uncertainty_note:
            sections.append(f"### Investigation Uncertainty\n{uncertainty_note}")

        return "\n\n".join(sections)
