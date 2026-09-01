"""API integration tests."""

import pytest


@pytest.mark.asyncio
async def test_health(client):
    response = await client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["modules"] == "mock"


@pytest.mark.asyncio
async def test_investigate_returns_final_incident(client):
    response = await client.post("/api/v1/investigate", json={"use_sample_logs": True})
    assert response.status_code == 200
    data = response.json()
    incident = data["incident"]

    assert incident["incident_id"].startswith("INC-")
    assert incident["investigation"]["explanation"]
    assert incident["risk"]["risk_score"] > 0
    assert len(incident["response"]["actions"]) >= 3
    assert incident["report"]["markdown_content"]


@pytest.mark.asyncio
async def test_get_incident_and_subresources(client):
    inv = await client.post("/api/v1/investigate", json={})
    incident_id = inv.json()["incident"]["incident_id"]

    get_resp = await client.get(f"/api/v1/incidents/{incident_id}")
    assert get_resp.status_code == 200

    timeline_resp = await client.get(f"/api/v1/incidents/{incident_id}/timeline")
    assert timeline_resp.status_code == 200
    assert len(timeline_resp.json()["entries"]) >= 5

    graph_resp = await client.get(f"/api/v1/incidents/{incident_id}/graph")
    assert graph_resp.status_code == 200
    assert len(graph_resp.json()["nodes"]) >= 5


@pytest.mark.asyncio
async def test_simulate_response(client):
    inv = await client.post("/api/v1/investigate", json={})
    incident_id = inv.json()["incident"]["incident_id"]

    sim_resp = await client.post(
        f"/api/v1/incidents/{incident_id}/simulate-response",
        json={"action_ids": ["act-001", "act-003"]},
    )
    assert sim_resp.status_code == 200
    sim = sim_resp.json()["simulation"]
    assert len(sim["outcomes"]) == 2
    assert sim["overall_risk_reduction"] > 0


@pytest.mark.asyncio
async def test_analyst_decision(client):
    inv = await client.post("/api/v1/investigate", json={})
    incident_id = inv.json()["incident"]["incident_id"]

    decision_resp = await client.post(
        f"/api/v1/incidents/{incident_id}/decision",
        json={"analyst_id": "analyst-01", "action": "approve", "comment": "Proceed with containment"},
    )
    assert decision_resp.status_code == 200
    assert decision_resp.json()["status"] == "resolved"


@pytest.mark.asyncio
async def test_download_report(client):
    inv = await client.post("/api/v1/investigate", json={})
    incident_id = inv.json()["incident"]["incident_id"]

    report_resp = await client.get(f"/api/v1/incidents/{incident_id}/report")
    assert report_resp.status_code == 200
    assert "Incident Report" in report_resp.text
    assert "attachment" in report_resp.headers.get("content-disposition", "")


@pytest.mark.asyncio
async def test_not_found_incident(client):
    response = await client.get("/api/v1/incidents/INC-NOTEXIST")
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_investigate_requires_raw_logs_when_sample_disabled(client):
    response = await client.post("/api/v1/investigate", json={"use_sample_logs": False, "raw_logs": []})
    assert response.status_code == 422
