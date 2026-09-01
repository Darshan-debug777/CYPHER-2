"""Threat Hunter Agent - Proactively searches for additional evidence.

Given the Investigator's hypothesis, searches provided event data for additional
clues that confirm, expand, or contradict the hypothesis.

The hunter never invents events - only references existing event IDs.
"""

import logging
import re
from datetime import datetime

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ThreatHunterAnalysis(BaseModel):
    """Structured output from threat hunter search.

    Results of proactive evidence search to expand investigator findings.
    """

    incident_id: str = Field(..., min_length=1)
    search_reason: str = Field(
        ...,
        min_length=1,
        description="Why this hypothesis led to this search (1-2 sentences)",
    )
    findings: str = Field(
        ...,
        min_length=1,
        description="Summary of what was discovered (2-3 sentences)",
    )
    discovered_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs found that weren't mentioned by investigator",
    )
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs that strengthen investigator's hypothesis",
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs that weaken or contradict investigator's hypothesis",
    )
    unexplored_areas: list[str] = Field(
        default_factory=list,
        description="Potential areas still needing investigation",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the hunt findings (0.0-1.0)",
    )
    uncertainty: str = Field(
        ...,
        min_length=1,
        description="What gaps remain, ambiguities, or data limitations",
    )


class ThreatHunterAgent:
    """Proactive hunter searching for additional evidence.

    Given an investigator's hypothesis, searches provided events for:
    - Additional supporting evidence (confirms hypothesis)
    - Contradicting evidence (challenges hypothesis)
    - New clues (expands understanding)

    Usage:
        agent = ThreatHunterAgent(llm_client=your_llm_client)
        findings = await agent.hunt(incident, investigator_analysis)
    """

    def __init__(self, llm_client: "LLMClient", prompt_template: str | None = None):  # noqa: F821
        """Initialize threat hunter agent.

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
                "threat_hunter_prompt.txt",
            )
            if os.path.exists(prompt_path):
                with open(prompt_path, "r") as f:
                    self.prompt_template = f.read()
            else:
                logger.warning(
                    f"Prompt template not found at {prompt_path}, using minimal template"
                )
                self.prompt_template = (
                    "Hunt for evidence supporting hypothesis: {hypothesis}"
                )

    async def hunt(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
        investigator_analysis: "InvestigatorAnalysis",  # noqa: F821
    ) -> ThreatHunterAnalysis:
        """Hunt for additional evidence supporting/contradicting hypothesis.

        Args:
            incident: CorrelatedIncident with all available events
            investigator_analysis: Investigator's analysis with hypothesis

        Returns:
            ThreatHunterAnalysis with discovered evidence

        Raises:
            LLMClientError: If LLM call fails or response cannot be parsed
        """
        # Validate inputs
        if not incident.normalized_events:
            logger.warning(f"No normalized events to hunt in {incident.incident_id}")
        if not incident.detections:
            logger.warning(f"No detections to hunt in {incident.incident_id}")

        # Format input data for prompt
        prompt = self._format_prompt(incident, investigator_analysis)

        logger.info(
            f"Starting threat hunt for {incident.incident_id}, "
            f"hypothesis: {investigator_analysis.hypothesis[:50]}..."
        )

        try:
            # Call LLM with structured output
            analysis = await self.llm_client.invoke(
                prompt=prompt,
                output_model=ThreatHunterAnalysis,
                temperature=0.4,  # Slightly higher for creative searching
                max_tokens=2500,
            )

            # Validate that referenced event IDs actually exist in input
            self._validate_event_references(analysis, incident)

            logger.info(
                f"Threat hunt complete for {incident.incident_id}, "
                f"discovered {len(analysis.discovered_evidence_ids)} new events"
            )
            return analysis

        except Exception as e:
            logger.error(f"Threat hunt failed for {incident.incident_id}: {e}")
            raise

    def _format_prompt(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
        investigator_analysis: "InvestigatorAnalysis",  # noqa: F821
    ) -> str:
        """Format incident and investigator data into prompt.

        Args:
            incident: The correlated incident with events
            investigator_analysis: Investigator's findings

        Returns:
            Formatted prompt string
        """
        # Format all events (including those not in investigator's list)
        events_text = self._format_all_events(incident.normalized_events)

        # Format detections (including those not mentioned)
        detections_text = self._format_detections(incident.detections)

        # Format investigator's findings
        investigator_text = self._format_investigator_findings(investigator_analysis)

        # Build prompt by replacing {{PLACEHOLDER}} markers
        prompt = self.prompt_template
        prompt = re.sub(r"{{INCIDENT_ID}}", incident.incident_id, prompt)
        prompt = re.sub(r"{{INCIDENT_TITLE}}", incident.title, prompt)
        prompt = re.sub(r"{{INCIDENT_SUMMARY}}", incident.summary, prompt)
        prompt = re.sub(r"{{INCIDENT_SEVERITY}}", incident.severity.value, prompt)
        prompt = re.sub(r"{{INCIDENT_CATEGORY}}", incident.primary_category.value, prompt)
        prompt = re.sub(r"{{ALL_EVENTS_TEXT}}", events_text, prompt)
        prompt = re.sub(r"{{ALL_DETECTIONS_TEXT}}", detections_text, prompt)
        prompt = re.sub(r"{{INVESTIGATOR_HYPOTHESIS}}", investigator_analysis.hypothesis, prompt)
        prompt = re.sub(r"{{INVESTIGATOR_FINDINGS}}", investigator_text, prompt)
        prompt = re.sub(
            r"{{INVESTIGATOR_EVIDENCE_IDS}}",
            ", ".join(investigator_analysis.supporting_evidence_ids),
            prompt,
        )

        return prompt

    @staticmethod
    def _format_all_events(events: list["NormalizedEvent"]) -> str:  # noqa: F821
        """Format all normalized events for hunting.

        Includes source, timestamp, type, and attributes to help hunter identify patterns.
        """
        if not events:
            return "No normalized events available."

        lines = []
        for event in events:
            # Include all available details for pattern matching
            attributes_str = ", ".join(
                f"{k}={v}" for k, v in event.attributes.items()
            )
            lines.append(
                f"[{event.event_id}] {event.timestamp.isoformat()} "
                f"({event.event_type}) | Source: {event.source} | "
                f"Actor: {event.actor or 'N/A'} | Target: {event.target or 'N/A'} | "
                f"Attrs: {attributes_str}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_detections(detections: list["DetectionResult"]) -> str:  # noqa: F821
        """Format all detections for hunting.

        Shows threat classifications and confidence levels.
        """
        if not detections:
            return "No detections recorded."

        lines = []
        for detection in detections:
            lines.append(
                f"[{detection.detection_id}] Event {detection.event_id}: "
                f"{detection.threat_type} ({detection.category.value}) | "
                f"Severity: {detection.severity.value} | "
                f"Confidence: {detection.confidence:.2f} | "
                f"Indicators: {', '.join(detection.indicators)}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_investigator_findings(
        analysis: "InvestigatorAnalysis",  # noqa: F821
    ) -> str:
        """Format investigator's findings for reference during hunt.

        Provides context about what investigator already concluded.
        """
        lines = [
            f"Hypothesis: {analysis.hypothesis}",
            f"Summary: {analysis.summary}",
            f"Attack Type: {analysis.suspected_attack_type}",
            f"Confidence: {analysis.confidence:.2%}",
            f"Reasoning: {analysis.reasoning}",
            f"Known Supporting Evidence: {', '.join(analysis.supporting_evidence_ids) or 'None'}",
            f"Known Facts: {'; '.join(analysis.observed_facts) if analysis.observed_facts else 'None'}",
            f"Investigator Uncertainties: {analysis.uncertainty}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _validate_event_references(
        analysis: ThreatHunterAnalysis,
        incident: "CorrelatedIncident",  # noqa: F821
    ) -> None:
        """Validate that all referenced event IDs exist in incident.

        Args:
            analysis: The hunter's analysis output
            incident: The input incident with valid events

        Raises:
            ValueError: If analysis references non-existent event IDs (logs warning instead)
        """
        valid_event_ids = {
            event.event_id for event in incident.normalized_events
        } | {detection.event_id for detection in incident.detections}

        # Check discovered evidence
        invalid_discovered = (
            set(analysis.discovered_evidence_ids) - valid_event_ids
        )
        if invalid_discovered:
            logger.warning(
                f"Hunter referenced non-existent discovered events: {invalid_discovered}"
            )
            analysis.discovered_evidence_ids = [
                eid
                for eid in analysis.discovered_evidence_ids
                if eid in valid_event_ids
            ]

        # Check supporting evidence
        invalid_supporting = (
            set(analysis.supporting_evidence_ids) - valid_event_ids
        )
        if invalid_supporting:
            logger.warning(
                f"Hunter referenced non-existent supporting events: {invalid_supporting}"
            )
            analysis.supporting_evidence_ids = [
                eid
                for eid in analysis.supporting_evidence_ids
                if eid in valid_event_ids
            ]

        # Check contradicting evidence
        invalid_contradicting = (
            set(analysis.contradicting_evidence_ids) - valid_event_ids
        )
        if invalid_contradicting:
            logger.warning(
                f"Hunter referenced non-existent contradicting events: {invalid_contradicting}"
            )
            analysis.contradicting_evidence_ids = [
                eid
                for eid in analysis.contradicting_evidence_ids
                if eid in valid_event_ids
            ]
