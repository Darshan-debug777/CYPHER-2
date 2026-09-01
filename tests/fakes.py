"""Test doubles for error-path testing."""

from datetime import datetime, timezone

from app.core.errors import EmptyResultError, ModuleError
from app.factory import ServiceContainer
from app.mocks import (
    MockAttackGraphService,
    MockCorrelationService,
    MockDetectionService,
    MockIngestionService,
    MockInvestigationService,
    MockReportService,
    MockResponseService,
    MockRiskService,
)
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.events import NormalizedEvent
from app.schemas.graph import AttackGraph, IncidentTimeline


class FailingIngestionService(MockIngestionService):
    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]:
        raise ModuleError("ingestion", "Simulated ingestion failure")


class EmptyDetectionService(MockDetectionService):
    async def detect(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        return []


class InvalidDetectionService(MockDetectionService):
    async def detect(self, events: list[NormalizedEvent]) -> list:
        return [{"bad": "data"}]


class FailingCorrelationService(MockCorrelationService):
    async def correlate(
        self,
        events: list[NormalizedEvent],
        detections: list[DetectionResult],
    ) -> CorrelatedIncident:
        raise ModuleError("correlation", "Simulated correlation failure")


class InvalidGraphService(MockAttackGraphService):
    async def build(self, incident: CorrelatedIncident) -> tuple[AttackGraph, IncidentTimeline]:
        graph = AttackGraph(
            incident_id=incident.incident_id,
            nodes=[],
            edges=[],
            entry_point="missing",
        )
        timeline = IncidentTimeline(incident_id=incident.incident_id, entries=[])
        return graph, timeline


def build_failing_container(**overrides) -> ServiceContainer:
    defaults = {
        "ingestion": MockIngestionService(),
        "detection": MockDetectionService(),
        "correlation": MockCorrelationService(),
        "attack_graph": MockAttackGraphService(),
        "investigation": MockInvestigationService(),
        "risk": MockRiskService(),
        "response": MockResponseService(),
        "report": MockReportService(),
    }
    defaults.update(overrides)
    return ServiceContainer(**defaults)
