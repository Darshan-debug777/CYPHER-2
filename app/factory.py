"""Service factory — swap mock implementations for real teammate modules here."""

from app.config import settings
from app.interfaces import (
    AttackGraphService,
    CorrelationService,
    DetectionService,
    IngestionService,
    InvestigationService,
    ReportService,
    ResponseService,
    RiskService,
)
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
from app.services.llm_investigation import LLMInvestigationService


class ServiceContainer:
    """Holds module implementations. Replace mocks via factory methods."""

    def __init__(
        self,
        ingestion: IngestionService | None = None,
        detection: DetectionService | None = None,
        correlation: CorrelationService | None = None,
        attack_graph: AttackGraphService | None = None,
        investigation: InvestigationService | None = None,
        risk: RiskService | None = None,
        response: ResponseService | None = None,
        report: ReportService | None = None,
    ):
        self.ingestion = ingestion or MockIngestionService()
        self.detection = detection or MockDetectionService()
        self.correlation = correlation or MockCorrelationService()
        self.attack_graph = attack_graph or MockAttackGraphService()
        self.investigation = investigation or MockInvestigationService()
        self.risk = risk or MockRiskService()
        self.response = response or MockResponseService()
        self.report = report or MockReportService()


def build_services(use_llm_investigation: bool = False) -> ServiceContainer:
    """Build service container.

    Defaults to mock services for fast, deterministic unit testing.
    If use_llm_investigation is True or settings.use_mock_modules is False,
    instantiates the real multi-agent LLMInvestigationService.
    """
    if not settings.use_mock_modules or use_llm_investigation:
        return ServiceContainer(
            investigation=LLMInvestigationService(),
        )
    return ServiceContainer()
