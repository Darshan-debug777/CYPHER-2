"""Context Agent - Analyzes security events within contextual baselines.

Evaluates user identity, device/host, source IP/location, time-of-day,
historical/baseline behavior, and administrative patterns to determine whether
activity is normal or unusual.

Never invents missing baseline information; reports uncertainty explicitly.
"""

import logging
import re

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class ContextAnalysis(BaseModel):
    """Structured output from Context Agent analysis.

    Captures whether observed activity aligns with normal baseline behavior or is anomalous.
    """

    incident_id: str = Field(..., min_length=1)
    contextual_assessment: str = Field(
        ...,
        min_length=1,
        description="Overall contextual assessment (normal, unusual, or mixed)",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Specific contextual indicators (e.g. off-hours, privileged user, unusual IP)",
    )
    relevant_factors: list[str] = Field(
        default_factory=list,
        description="Relevant environment and entity factors considered",
    )
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs indicating anomalous or suspicious context",
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs indicating normal, routine, or legitimate activity",
    )
    explanation: str = Field(
        ...,
        min_length=1,
        description="Detailed contextual reasoning and analysis",
    )
    uncertainty: str = Field(
        ...,
        min_length=1,
        description="Explicit gaps in baseline data, user history, or environment context",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in contextual assessment (0.0-1.0)",
    )


class ContextAgent:
    """Agent analyzing contextual factors surrounding security incidents.

    Usage:
        agent = ContextAgent(llm_client=your_llm_client)
        analysis = await agent.analyze(incident)
    """

    def __init__(self, llm_client: "LLMClient", prompt_template: str | None = None):  # noqa: F821
        """Initialize context agent.

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
                "context_prompt.txt",
            )
            if os.path.exists(prompt_path):
                with open(prompt_path, "r") as f:
                    self.prompt_template = f.read()
            else:
                logger.warning(
                    f"Prompt template not found at {prompt_path}, using minimal template"
                )
                self.prompt_template = "Analyze context for incident {incident_id}"

    async def analyze(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
    ) -> ContextAnalysis:
        """Analyze security incident context and produce structured assessment.

        Args:
            incident: CorrelatedIncident with normalized events and detections

        Returns:
            ContextAnalysis with indicators, factors, and baseline evaluation

        Raises:
            LLMClientError: If LLM call fails or response cannot be parsed
        """
        if not incident.normalized_events:
            logger.warning(f"No normalized events for context analysis in {incident.incident_id}")

        prompt = self._format_prompt(incident)

        logger.info(f"Starting contextual analysis for {incident.incident_id}")

        try:
            analysis = await self.llm_client.invoke(
                prompt=prompt,
                output_model=ContextAnalysis,
                temperature=0.3,
                max_tokens=2000,
            )

            # Validate that referenced event IDs exist in incident
            self._validate_event_references(analysis, incident)

            logger.info(
                f"Context analysis complete for {incident.incident_id}, "
                f"assessment='{analysis.contextual_assessment[:40]}...', "
                f"confidence={analysis.confidence}"
            )
            return analysis

        except Exception as e:
            logger.error(f"Context analysis failed for {incident.incident_id}: {e}")
            raise

    def _format_prompt(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
    ) -> str:
        """Format incident data into context prompt.

        Args:
            incident: The correlated incident

        Returns:
            Formatted prompt string
        """
        events_text = self._format_all_events(incident.normalized_events)
        detections_text = self._format_detections(incident.detections)

        prompt = self.prompt_template
        prompt = re.sub(r"{{INCIDENT_ID}}", incident.incident_id, prompt)
        prompt = re.sub(r"{{INCIDENT_TITLE}}", incident.title, prompt)
        prompt = re.sub(r"{{INCIDENT_SUMMARY}}", incident.summary, prompt)
        prompt = re.sub(r"{{INCIDENT_SEVERITY}}", incident.severity.value, prompt)
        prompt = re.sub(r"{{INCIDENT_CATEGORY}}", incident.primary_category.value, prompt)
        prompt = re.sub(r"{{ALL_EVENTS_TEXT}}", events_text, prompt)
        prompt = re.sub(r"{{ALL_DETECTIONS_TEXT}}", detections_text, prompt)

        return prompt

    @staticmethod
    def _format_all_events(events: list["NormalizedEvent"]) -> str:  # noqa: F821
        """Format normalized events for contextual analysis."""
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
    def _format_detections(detections: list["DetectionResult"]) -> str:  # noqa: F821
        """Format detections for contextual analysis."""
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
    def _validate_event_references(
        analysis: ContextAnalysis,
        incident: "CorrelatedIncident",  # noqa: F821
    ) -> None:
        """Validate that all referenced event IDs exist in incident.

        Args:
            analysis: The context analysis output
            incident: The input incident with valid events
        """
        valid_event_ids = {
            event.event_id for event in incident.normalized_events
        } | {detection.event_id for detection in incident.detections}

        # Check supporting evidence
        invalid_supporting = set(analysis.supporting_evidence_ids) - valid_event_ids
        if invalid_supporting:
            logger.warning(
                f"Context agent referenced non-existent supporting events: {invalid_supporting}"
            )
            analysis.supporting_evidence_ids = [
                eid for eid in analysis.supporting_evidence_ids if eid in valid_event_ids
            ]

        # Check contradicting evidence
        invalid_contradicting = set(analysis.contradicting_evidence_ids) - valid_event_ids
        if invalid_contradicting:
            logger.warning(
                f"Context agent referenced non-existent contradicting events: {invalid_contradicting}"
            )
            analysis.contradicting_evidence_ids = [
                eid for eid in analysis.contradicting_evidence_ids if eid in valid_event_ids
            ]
