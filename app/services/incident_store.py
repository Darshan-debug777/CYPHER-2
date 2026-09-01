"""In-memory incident store for prototype."""

import logging
from threading import Lock

from app.core.errors import NotFoundError
from app.schemas.enums import IncidentStatus
from app.schemas.response import FinalIncident, ResponseRecommendation, ResponseSimulation

logger = logging.getLogger(__name__)


class IncidentStore:
    def __init__(self) -> None:
        self._incidents: dict[str, FinalIncident] = {}
        self._simulations: dict[str, list[ResponseSimulation]] = {}
        self._lock = Lock()

    def save(self, incident: FinalIncident) -> None:
        with self._lock:
            self._incidents[incident.incident_id] = incident
            logger.debug("Stored incident %s", incident.incident_id)

    def get(self, incident_id: str) -> FinalIncident:
        with self._lock:
            incident = self._incidents.get(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found")
        return incident

    def update(self, incident: FinalIncident) -> None:
        with self._lock:
            if incident.incident_id not in self._incidents:
                raise NotFoundError(f"Incident '{incident.incident_id}' not found")
            self._incidents[incident.incident_id] = incident

    def get_response_recommendation(self, incident_id: str) -> ResponseRecommendation:
        incident = self.get(incident_id)
        return incident.response

    def save_simulation(self, simulation: ResponseSimulation) -> None:
        with self._lock:
            self._simulations.setdefault(simulation.incident_id, []).append(simulation)

    def list_simulations(self, incident_id: str) -> list[ResponseSimulation]:
        with self._lock:
            return list(self._simulations.get(incident_id, []))


# Singleton for prototype
incident_store = IncidentStore()
