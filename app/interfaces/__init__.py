"""Module interface protocols for dependency inversion."""

from typing import Protocol

from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.events import NormalizedEvent, SecurityEvent
from app.schemas.graph import AttackGraph, IncidentTimeline
from app.schemas.investigation import InvestigationResult, RiskAssessment
from app.schemas.response import (
    AnalystDecision,
    IncidentReport,
    ResponseRecommendation,
    ResponseSimulation,
)


class IngestionService(Protocol):
    """
    KV-owned: log collection, parsing, normalization.

    INPUT:  list[SecurityEvent] or raw log dicts
    OUTPUT: list[NormalizedEvent]
    ERRORS: ValidationError (malformed logs), EmptyResultError
    """

    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]: ...


class DetectionService(Protocol):
    """
    MRUN-owned: threat/anomaly detection.

    INPUT:  list[NormalizedEvent]
    OUTPUT: list[DetectionResult]
    ERRORS: EmptyResultError, InvalidModuleOutputError
    """

    async def detect(self, events: list[NormalizedEvent]) -> list[DetectionResult]: ...


class CorrelationService(Protocol):
    """
    MRUN-owned: event correlation into incidents.

    INPUT:  list[NormalizedEvent], list[DetectionResult]
    OUTPUT: CorrelatedIncident
    ERRORS: EmptyResultError, InvalidModuleOutputError
    """

    async def correlate(
        self,
        events: list[NormalizedEvent],
        detections: list[DetectionResult],
    ) -> CorrelatedIncident: ...


class AttackGraphService(Protocol):
    """
    ROHIT-owned: attack graph and timeline construction.

    INPUT:  CorrelatedIncident
    OUTPUT: tuple[AttackGraph, IncidentTimeline]
    ERRORS: EmptyResultError, InvalidModuleOutputError
    """

    async def build(self, incident: CorrelatedIncident) -> tuple[AttackGraph, IncidentTimeline]: ...


class InvestigationService(Protocol):
    """
    AI investigation agents (Log Analysis + Threat Investigation).

    INPUT:  CorrelatedIncident, AttackGraph, IncidentTimeline
    OUTPUT: InvestigationResult
    ERRORS: ModuleError, InvalidModuleOutputError
    """

    async def investigate(
        self,
        incident: CorrelatedIncident,
        graph: AttackGraph,
        timeline: IncidentTimeline,
    ) -> InvestigationResult: ...


class RiskService(Protocol):
    """
    Risk scoring module.

    INPUT:  InvestigationResult
    OUTPUT: RiskAssessment
    ERRORS: InvalidModuleOutputError
    """

    async def assess(self, investigation: InvestigationResult) -> RiskAssessment: ...


class ResponseService(Protocol):
    """
    Response recommendation and simulation.

    INPUT:  InvestigationResult, RiskAssessment
    OUTPUT: ResponseRecommendation or ResponseSimulation
    ERRORS: InvalidModuleOutputError
    """

    async def recommend(
        self,
        investigation: InvestigationResult,
        risk: RiskAssessment,
    ) -> ResponseRecommendation: ...

    async def simulate(
        self,
        incident_id: str,
        recommendation: ResponseRecommendation,
        action_ids: list[str] | None = None,
    ) -> ResponseSimulation: ...


class ReportService(Protocol):
    """
    Incident report generation.

    INPUT:  InvestigationResult, RiskAssessment, ResponseRecommendation
    OUTPUT: IncidentReport
    ERRORS: InvalidModuleOutputError
    """

    async def generate(
        self,
        investigation: InvestigationResult,
        risk: RiskAssessment,
        response: ResponseRecommendation,
    ) -> IncidentReport: ...


class ReconstructionService(Protocol):
    """
    ROHIT-owned (optional): incident reconstruction beyond graph.

    INPUT:  CorrelatedIncident, AttackGraph
    OUTPUT: dict enrichment (placeholder for future use)
    """

    async def reconstruct(
        self,
        incident: CorrelatedIncident,
        graph: AttackGraph,
    ) -> dict: ...
