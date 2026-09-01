"""FastAPI dependencies."""

from functools import lru_cache

from app.orchestrator.pipeline import InvestigationOrchestrator
from app.services.incident_store import IncidentStore, incident_store


@lru_cache
def get_orchestrator() -> InvestigationOrchestrator:
    return InvestigationOrchestrator()


def get_incident_store() -> IncidentStore:
    return incident_store
