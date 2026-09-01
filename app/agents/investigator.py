"""Investigator Agent - Analyzes cybersecurity incidents to determine what happened.

The investigator examines detections, events, and attack graphs to form
evidence-backed hypotheses about attack type, progression, and threat level.

Every claim references specific event IDs. Uncertainty is explicit.
"""

import logging
import re
from datetime import datetime

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class InvestigatorAnalysis(BaseModel):
    """Intermediate output from investigator before conversion to InvestigationResult.

    This is the LLM's structured response about what happened.
    """

    incident_id: str = Field(..., min_length=1)
    hypothesis: str = Field(
        ...,
        min_length=1,
        description="Primary conclusion about what happened (1-2 sentences)",
    )
    summary: str = Field(
        ..., min_length=1, description="Attack narrative (2-3 sentences)"
    )
    reasoning: str = Field(
        ...,
        min_length=1,
        description="Detailed step-by-step analysis referencing evidence",
    )
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="Event IDs from input that support the hypothesis",
    )
    observed_facts: list[str] = Field(
        default_factory=list,
        description="Specific facts observed in events, referencing event_ids",
    )
    suspected_attack_type: str = Field(
        ...,
        min_length=1,
        description="Attack type: CREDENTIAL_ACCESS, LATERAL_MOVEMENT, EXECUTION, etc.",
    )
    uncertainty: str = Field(
        ...,
        min_length=1,
        description="What you're uncertain about, ambiguities, or missing information",
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in primary hypothesis (0.0-1.0)",
    )


class InvestigatorAgent:
    """Independent detective analyzing security incidents.

    Receives correlated incident evidence (events, detections, graphs) and
    produces structured analysis explaining what happened.

    Usage:
        agent = InvestigatorAgent(llm_client=your_llm_client)
        analysis = await agent.investigate(incident, graph, timeline)
    """

    def __init__(self, llm_client: "LLMClient", prompt_template: str | None = None):  # noqa: F821
        """Initialize investigator agent.

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
                "investigator_prompt.txt",
            )
            if os.path.exists(prompt_path):
                with open(prompt_path, "r") as f:
                    self.prompt_template = f.read()
            else:
                logger.warning(
                    f"Prompt template not found at {prompt_path}, using minimal template"
                )
                self.prompt_template = "Analyze incident {incident_id}: {incident_summary}"

    async def investigate(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
        graph: "AttackGraph",  # noqa: F821
        timeline: "IncidentTimeline",  # noqa: F821
    ) -> InvestigatorAnalysis:
        """Investigate incident and produce analysis.

        Args:
            incident: CorrelatedIncident with detections and events
            graph: AttackGraph showing attack progression
            timeline: IncidentTimeline showing event sequence

        Returns:
            InvestigatorAnalysis with hypothesis, reasoning, and supporting evidence

        Raises:
            LLMClientError: If LLM call fails or response cannot be parsed
        """
        # Validate inputs
        if not incident.normalized_events:
            logger.warning(f"No normalized events for {incident.incident_id}")
        if not graph.nodes:
            raise ValueError(f"Empty graph for {incident.incident_id}")
        if not timeline.entries:
            raise ValueError(f"Empty timeline for {incident.incident_id}")

        # Format input data for prompt
        prompt = self._format_prompt(incident, graph, timeline)

        logger.info(f"Starting investigation for {incident.incident_id}")

        try:
            # Call LLM with structured output
            analysis = await self.llm_client.invoke(
                prompt=prompt,
                output_model=InvestigatorAnalysis,
                temperature=0.3,  # Low temperature for consistent analysis
                max_tokens=2000,
            )

            # Validate that referenced event IDs actually exist in input
            self._validate_event_references(analysis, incident)

            logger.info(
                f"Investigation complete for {incident.incident_id}, "
                f"confidence={analysis.confidence}"
            )
            return analysis

        except Exception as e:
            logger.error(f"Investigation failed for {incident.incident_id}: {e}")
            raise

    def _format_prompt(
        self,
        incident: "CorrelatedIncident",  # noqa: F821
        graph: "AttackGraph",  # noqa: F821
        timeline: "IncidentTimeline",  # noqa: F821
    ) -> str:
        """Format incident data into prompt.

        Args:
            incident: The correlated incident
            graph: Attack graph showing node relationships
            timeline: Timeline of events

        Returns:
            Formatted prompt string
        """
        # Format normalized events
        events_text = self._format_events(incident.normalized_events)

        # Format detections
        detections_text = self._format_detections(incident.detections)

        # Format graph nodes
        graph_nodes_text = self._format_graph_nodes(graph.nodes)

        # Format graph edges
        graph_edges_text = self._format_graph_edges(graph.edges)

        # Format timeline
        timeline_text = self._format_timeline(timeline.entries)

        # Build prompt by replacing {{PLACEHOLDER}} markers
        prompt = self.prompt_template
        prompt = re.sub(r"{{INCIDENT_ID}}", incident.incident_id, prompt)
        prompt = re.sub(r"{{INCIDENT_TITLE}}", incident.title, prompt)
        prompt = re.sub(r"{{INCIDENT_SUMMARY}}", incident.summary, prompt)
        prompt = re.sub(r"{{INCIDENT_SEVERITY}}", incident.severity.value, prompt)
        prompt = re.sub(r"{{INCIDENT_CATEGORY}}", incident.primary_category.value, prompt)
        prompt = re.sub(r"{{NORMALIZED_EVENTS_TEXT}}", events_text, prompt)
        prompt = re.sub(r"{{DETECTIONS_TEXT}}", detections_text, prompt)
        prompt = re.sub(r"{{GRAPH_ENTRY_POINT}}", graph.entry_point, prompt)
        prompt = re.sub(r"{{GRAPH_NODES_TEXT}}", graph_nodes_text, prompt)
        prompt = re.sub(r"{{GRAPH_EDGES_TEXT}}", graph_edges_text, prompt)
        prompt = re.sub(r"{{TIMELINE_TEXT}}", timeline_text, prompt)

        return prompt

    @staticmethod
    def _format_events(events: list["NormalizedEvent"]) -> str:  # noqa: F821
        """Format normalized events for inclusion in prompt."""
        if not events:
            return "No raw events recorded."

        lines = []
        for event in events[:20]:  # Limit to 20 most recent
            lines.append(
                f"- [{event.event_id}] {event.timestamp.isoformat()} "
                f"({event.event_type}): {event.attributes.get('description', 'N/A')} "
                f"[actor={event.actor}, target={event.target}]"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_detections(detections: list["DetectionResult"]) -> str:  # noqa: F821
        """Format detections for inclusion in prompt."""
        if not detections:
            return "No detections recorded."

        lines = []
        for detection in detections:
            lines.append(
                f"- [{detection.detection_id}] Event {detection.event_id}: "
                f"{detection.threat_type} (confidence={detection.confidence:.2f}) "
                f"[{detection.category.value}] Severity: {detection.severity.value}"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_graph_nodes(nodes: list["GraphNode"]) -> str:  # noqa: F821
        """Format attack graph nodes."""
        if not nodes:
            return "No graph nodes."

        lines = []
        for node in nodes:
            attrs = ", ".join(f"{k}={v}" for k, v in node.attributes.items())
            lines.append(f"- {node.node_id}: {node.label} ({node.node_type}) [{attrs}]")
        return "\n".join(lines)

    @staticmethod
    def _format_graph_edges(edges: list["GraphEdge"]) -> str:  # noqa: F821
        """Format attack graph edges (relationships between nodes)."""
        if not edges:
            return "No graph edges."

        lines = []
        for edge in edges:
            timestamp = edge.timestamp.isoformat() if edge.timestamp else "unknown"
            lines.append(
                f"- {edge.source_id} --[{edge.relationship}]-> {edge.target_id} "
                f"(event={edge.event_id}, time={timestamp})"
            )
        return "\n".join(lines)

    @staticmethod
    def _format_timeline(entries: list["TimelineEntry"]) -> str:  # noqa: F821
        """Format incident timeline."""
        if not entries:
            return "No timeline entries."

        lines = []
        for entry in entries:
            lines.append(
                f"- {entry.timestamp.isoformat()}: [{entry.stage}] {entry.description} "
                f"(event={entry.event_id}, severity={entry.severity.value}, "
                f"mitre={entry.mitre_technique or 'N/A'})"
            )
        return "\n".join(lines)

    @staticmethod
    def _validate_event_references(
        analysis: InvestigatorAnalysis,
        incident: "CorrelatedIncident",  # noqa: F821
    ) -> None:
        """Validate that all referenced event IDs exist in incident.

        Args:
            analysis: The investigator's analysis output
            incident: The input incident with valid events

        Raises:
            ValueError: If analysis references non-existent event IDs
        """
        valid_event_ids = {
            event.event_id for event in incident.normalized_events
        } | {detection.event_id for detection in incident.detections}

        invalid_ids = set(analysis.supporting_evidence_ids) - valid_event_ids

        if invalid_ids:
            logger.warning(
                f"Analysis references non-existent event IDs: {invalid_ids}. "
                f"Valid IDs are: {valid_event_ids}"
            )
            # Don't raise error - instead remove invalid IDs
            analysis.supporting_evidence_ids = [
                eid
                for eid in analysis.supporting_evidence_ids
                if eid in valid_event_ids
            ]

        # Also check observed_facts for event ID references
        # These should be in the text, but we won't strictly validate them
        for fact in analysis.observed_facts:
            # Just log if we can't find referenced event ID in fact text
            found_any = any(eid in fact for eid in valid_event_ids)
            if not found_any and valid_event_ids:
                logger.debug(f"Fact may not reference valid event ID: {fact}")
