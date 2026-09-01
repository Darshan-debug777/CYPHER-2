"""Skeptic Agent - Challenges and pressure-tests investigation hypotheses.

Evaluates evidence for and against hypotheses, generates alternative benign explanations,
identifies analytical weaknesses and missing information, and provides calibrated confidence.

Never automatically dismisses hypotheses; bases all critique strictly on evidence.
"""

import logging
import re
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from app.agents.context import ContextAnalysis
    from app.agents.investigator import InvestigatorAnalysis
    from app.agents.threat_hunter import ThreatHunterAnalysis
    from app.schemas.detection import CorrelatedIncident, DetectionResult
    from app.schemas.events import NormalizedEvent
    from app.services.llm_client import LLMClient

logger = logging.getLogger(__name__)


class SkepticAnalysis(BaseModel):
    """Structured output from Skeptic Agent evaluation.

    Challenges the primary hypothesis, assesses evidence strength, and suggests alternative explanations.
    """

    incident_id: str = Field(..., min_length=1)
    verdict: str = Field(
        ...,
        min_length=1,
        description="Verdict on hypothesis: STRENGTHEN, WEAKEN, or UNCHANGED",
    )
    critique_summary: str = Field(
        ...,
        min_length=1,
        description="Summary of skeptical critique and evaluation (2-3 sentences)",
    )
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs solidly supporting the hypothesis",
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs that weaken, contradict, or complicate the hypothesis",
    )
    alternative_explanations: list[str] = Field(
        default_factory=list,
        description="Plausible benign or operational explanations for observed events",
    )
    missing_information: list[str] = Field(
        default_factory=list,
        description="Critical missing telemetry or forensic artifacts needed to confirm conclusion",
    )
    investigation_weaknesses: list[str] = Field(
        default_factory=list,
        description="Analytical gaps, unsubstantiated assumptions, or logical leaps",
    )
    revised_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Skeptic's recalibrated confidence score (0.0-1.0)",
    )
    uncertainty: str = Field(
        ...,
        min_length=1,
        description="Explicit remaining ambiguities or unresolved doubts",
    )


class SkepticAgent:
    """Agent evaluating investigation hypotheses critically.

    Usage:
        agent = SkepticAgent(llm_client=your_llm_client)
        analysis = await agent.critique(
            incident=incident,
            investigator_analysis=investigator_analysis,
            threat_hunter_analysis=threat_hunter_analysis,
            context_analysis=context_analysis,
        )
    """

    def __init__(self, llm_client: "LLMClient", prompt_template: str | None = None):
        """Initialize skeptic agent.

        Args:
            llm_client: LLMClient instance for calling LLM
            prompt_template: Custom prompt template (uses default if None)
        """
        self.llm_client = llm_client
        self.prompt_template = prompt_template

        # Load default prompt if not provided
        if self.prompt_template is None:
            import os

            prompt_path = os.path.join(
                os.path.dirname(__file__),
                "..",
                "prompts",
                "skeptic_prompt.txt",
            )
            if os.path.exists(prompt_path):
                with open(prompt_path, "r") as f:
                    self.prompt_template = f.read()
            else:
                logger.warning(
                    f"Prompt template not found at {prompt_path}, using minimal template"
                )
                self.prompt_template = "Critique hypothesis for incident {incident_id}"

    async def critique(
        self,
        incident: "CorrelatedIncident",
        investigator_analysis: "InvestigatorAnalysis",
        threat_hunter_analysis: "ThreatHunterAnalysis | None" = None,
        context_analysis: "ContextAnalysis | None" = None,
    ) -> SkepticAnalysis:
        """Critique investigation findings and pressure-test conclusions.

        Args:
            incident: CorrelatedIncident with normalized events and detections
            investigator_analysis: Findings and hypothesis from InvestigatorAgent
            threat_hunter_analysis: Optional additional findings from ThreatHunterAgent
            context_analysis: Optional contextual findings from ContextAgent

        Returns:
            SkepticAnalysis with verdict, alternative explanations, and revised confidence

        Raises:
            LLMClientError: If LLM call fails or response cannot be parsed
        """
        prompt = self._format_prompt(
            incident=incident,
            investigator_analysis=investigator_analysis,
            threat_hunter_analysis=threat_hunter_analysis,
            context_analysis=context_analysis,
        )

        logger.info(
            f"Starting skeptical critique for {incident.incident_id}, "
            f"hypothesis: {investigator_analysis.hypothesis[:50]}..."
        )

        try:
            analysis = await self.llm_client.invoke(
                prompt=prompt,
                output_model=SkepticAnalysis,
                temperature=0.3,
                max_tokens=2500,
            )

            # Validate that referenced event IDs exist in incident
            self._validate_event_references(analysis, incident)

            logger.info(
                f"Skeptic critique complete for {incident.incident_id}, "
                f"verdict={analysis.verdict}, revised_confidence={analysis.revised_confidence}"
            )
            return analysis

        except Exception as e:
            logger.error(f"Skeptic critique failed for {incident.incident_id}: {e}")
            raise

    def _format_prompt(
        self,
        incident: "CorrelatedIncident",
        investigator_analysis: "InvestigatorAnalysis",
        threat_hunter_analysis: "ThreatHunterAnalysis | None" = None,
        context_analysis: "ContextAnalysis | None" = None,
    ) -> str:
        """Format incident, agent analyses, and evidence into prompt."""
        events_text = self._format_all_events(incident.normalized_events)
        detections_text = self._format_detections(incident.detections)
        investigator_text = self._format_investigator_findings(investigator_analysis)
        hunter_text = self._format_hunter_findings(threat_hunter_analysis)
        context_text = self._format_context_findings(context_analysis)

        prompt = self.prompt_template
        prompt = re.sub(r"{{INCIDENT_ID}}", incident.incident_id, prompt)
        prompt = re.sub(r"{{INCIDENT_TITLE}}", incident.title, prompt)
        prompt = re.sub(r"{{INCIDENT_SUMMARY}}", incident.summary, prompt)
        prompt = re.sub(r"{{INCIDENT_SEVERITY}}", incident.severity.value, prompt)
        prompt = re.sub(r"{{INCIDENT_CATEGORY}}", incident.primary_category.value, prompt)
        prompt = re.sub(r"{{INVESTIGATOR_FINDINGS}}", investigator_text, prompt)
        prompt = re.sub(r"{{THREAT_HUNTER_FINDINGS}}", hunter_text, prompt)
        prompt = re.sub(r"{{CONTEXT_FINDINGS}}", context_text, prompt)
        prompt = re.sub(r"{{ALL_EVENTS_TEXT}}", events_text, prompt)
        prompt = re.sub(r"{{ALL_DETECTIONS_TEXT}}", detections_text, prompt)

        return prompt

    @staticmethod
    def _format_all_events(events: list["NormalizedEvent"]) -> str:
        """Format normalized events."""
        if not events:
            return "No normalized events available."

        lines = []
        for event in events:
            attributes_str = ", ".join(f"{k}={v}" for k, v in event.attributes.items())
            lines.append(
                f"[{event.event_id}] {event.timestamp.isoformat()} "
                f"({event.event_type}) | Source: {event.source} | "
                f"Actor: {event.actor or 'N/A'} | Target: {event.target or 'N/A'} | "
                f"Attrs: {attributes_str}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_detections(detections: list["DetectionResult"]) -> str:
        """Format detections."""
        if not detections:
            return "No detections recorded."

        lines = []
        for detection in detections:
            lines.append(
                f"[{detection.detection_id}] Event {detection.event_id}: "
                f"{detection.threat_type} ({detection.category.value}) | "
                f"Severity: {detection.severity.value} | "
                f"Confidence: {detection.confidence:.2f}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_investigator_findings(analysis: "InvestigatorAnalysis") -> str:
        """Format InvestigatorAgent findings."""
        lines = [
            f"Hypothesis: {analysis.hypothesis}",
            f"Summary: {analysis.summary}",
            f"Reasoning: {analysis.reasoning}",
            f"Attack Type: {analysis.suspected_attack_type}",
            f"Supporting Evidence IDs: {', '.join(analysis.supporting_evidence_ids) or 'None'}",
            f"Observed Facts: {'; '.join(analysis.observed_facts) if analysis.observed_facts else 'None'}",
            f"Investigator Confidence: {analysis.confidence:.2%}",
            f"Investigator Uncertainty: {analysis.uncertainty}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_hunter_findings(analysis: "ThreatHunterAnalysis | None") -> str:
        """Format ThreatHunterAgent findings if provided."""
        if analysis is None:
            return "No threat hunter findings provided."

        lines = [
            f"Search Reason: {analysis.search_reason}",
            f"Findings: {analysis.findings}",
            f"Discovered Evidence IDs: {', '.join(analysis.discovered_evidence_ids) or 'None'}",
            f"Supporting Evidence IDs: {', '.join(analysis.supporting_evidence_ids) or 'None'}",
            f"Contradicting Evidence IDs: {', '.join(analysis.contradicting_evidence_ids) or 'None'}",
            f"Unexplored Areas: {'; '.join(analysis.unexplored_areas) if analysis.unexplored_areas else 'None'}",
            f"Hunter Confidence: {analysis.confidence:.2%}",
            f"Hunter Uncertainty: {analysis.uncertainty}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _format_context_findings(analysis: "ContextAnalysis | None") -> str:
        """Format ContextAgent findings if provided."""
        if analysis is None:
            return "No context agent findings provided."

        lines = [
            f"Contextual Assessment: {analysis.contextual_assessment}",
            f"Indicators: {'; '.join(analysis.indicators) if analysis.indicators else 'None'}",
            f"Relevant Factors: {'; '.join(analysis.relevant_factors) if analysis.relevant_factors else 'None'}",
            f"Supporting Evidence IDs: {', '.join(analysis.supporting_evidence_ids) or 'None'}",
            f"Contradicting Evidence IDs: {', '.join(analysis.contradicting_evidence_ids) or 'None'}",
            f"Explanation: {analysis.explanation}",
            f"Context Confidence: {analysis.confidence:.2%}",
            f"Context Uncertainty: {analysis.uncertainty}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _validate_event_references(
        analysis: SkepticAnalysis,
        incident: "CorrelatedIncident",
    ) -> None:
        """Validate referenced event IDs exist in incident events or detections."""
        valid_event_ids = {
            event.event_id for event in incident.normalized_events
        } | {detection.event_id for detection in incident.detections}

        # Validate supporting evidence IDs
        invalid_supporting = set(analysis.supporting_evidence_ids) - valid_event_ids
        if invalid_supporting:
            logger.warning(
                f"Skeptic referenced non-existent supporting events: {invalid_supporting}"
            )
            analysis.supporting_evidence_ids = [
                eid for eid in analysis.supporting_evidence_ids if eid in valid_event_ids
            ]

        # Validate contradicting evidence IDs
        invalid_contradicting = set(analysis.contradicting_evidence_ids) - valid_event_ids
        if invalid_contradicting:
            logger.warning(
                f"Skeptic referenced non-existent contradicting events: {invalid_contradicting}"
            )
            analysis.contradicting_evidence_ids = [
                eid for eid in analysis.contradicting_evidence_ids if eid in valid_event_ids
            ]
