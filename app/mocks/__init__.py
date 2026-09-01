"""Mock module factory."""

from app.mocks.attack_graph import MockAttackGraphService
from app.mocks.correlation import MockCorrelationService
from app.mocks.detection import MockDetectionService
from app.mocks.ingestion import MockIngestionService
from app.mocks.investigation import MockInvestigationService
from app.mocks.report import MockReportService
from app.mocks.response import MockResponseService
from app.mocks.risk import MockRiskService

__all__ = [
    "MockAttackGraphService",
    "MockCorrelationService",
    "MockDetectionService",
    "MockIngestionService",
    "MockInvestigationService",
    "MockReportService",
    "MockResponseService",
    "MockRiskService",
]
