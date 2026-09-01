"""Error handling and failure-path tests."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.orchestrator.pipeline import InvestigationOrchestrator
from app.schemas.api import InvestigateRequest
from app.core.errors import EmptyResultError, InvalidModuleOutputError, ModuleError
from tests.fakes import (
    EmptyDetectionService,
    FailingCorrelationService,
    FailingIngestionService,
    InvalidDetectionService,
    InvalidGraphService,
    build_failing_container,
)


@pytest.mark.asyncio
async def test_module_failure_returns_error():
    orchestrator = InvestigationOrchestrator(
        services=build_failing_container(ingestion=FailingIngestionService())
    )
    with pytest.raises(ModuleError) as exc_info:
        await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))
    assert exc_info.value.details["module"] == "ingestion"


@pytest.mark.asyncio
async def test_empty_detection_result_raises():
    orchestrator = InvestigationOrchestrator(
        services=build_failing_container(detection=EmptyDetectionService())
    )
    with pytest.raises(EmptyResultError) as exc_info:
        await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))
    assert exc_info.value.details["module"] == "detection"


@pytest.mark.asyncio
async def test_invalid_detection_output_raises():
    orchestrator = InvestigationOrchestrator(
        services=build_failing_container(detection=InvalidDetectionService())
    )
    with pytest.raises(InvalidModuleOutputError) as exc_info:
        await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))
    assert exc_info.value.details["module"] == "detection"


@pytest.mark.asyncio
async def test_invalid_graph_empty_nodes_raises():
    orchestrator = InvestigationOrchestrator(
        services=build_failing_container(attack_graph=InvalidGraphService())
    )
    # Pydantic validation catches empty nodes first, so ModuleError is raised
    with pytest.raises(ModuleError) as exc_info:
        await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))
    assert exc_info.value.details["module"] == "attack_graph"


@pytest.mark.asyncio
async def test_correlation_failure_propagates():
    orchestrator = InvestigationOrchestrator(
        services=build_failing_container(correlation=FailingCorrelationService())
    )
    with pytest.raises(ModuleError):
        await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))


@pytest.mark.asyncio
async def test_api_module_failure_returns_502():
    from app.api import dependencies

    dependencies.get_orchestrator.cache_clear()
    failing = InvestigationOrchestrator(
        services=build_failing_container(ingestion=FailingIngestionService())
    )

    app.dependency_overrides[dependencies.get_orchestrator] = lambda: failing
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post("/api/v1/investigate", json={"use_sample_logs": True})
        assert response.status_code == 502
        body = response.json()
        assert body["code"] == "module_error"
        assert body["details"]["module"] == "ingestion"
    finally:
        app.dependency_overrides.clear()
        dependencies.get_orchestrator.cache_clear()


@pytest.mark.asyncio
async def test_api_malformed_raw_logs_returns_400():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/investigate",
            json={
                "use_sample_logs": False,
                "raw_logs": [{"event_id": "x", "source": "auth"}],
            },
        )
    assert response.status_code == 400
    body = response.json()
    assert body["code"] == "validation_error"


@pytest.mark.asyncio
async def test_api_invalid_decision_body_returns_422():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        inv = await client.post("/api/v1/investigate", json={})
        incident_id = inv.json()["incident"]["incident_id"]
        response = await client.post(
            f"/api/v1/incidents/{incident_id}/decision",
            json={"analyst_id": "", "action": "approve"},
        )
    assert response.status_code == 422
