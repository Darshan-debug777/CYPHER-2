"""Shared test fixtures."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.incident_store import IncidentStore, incident_store


@pytest.fixture(autouse=True)
def clear_incident_store():
    incident_store._incidents.clear()
    incident_store._simulations.clear()
    yield
    incident_store._incidents.clear()
    incident_store._simulations.clear()


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
