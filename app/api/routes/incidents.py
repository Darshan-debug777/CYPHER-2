"""Incident investigation and management routes."""

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse

from app.api.dependencies import get_incident_store, get_orchestrator
from app.core.errors import NotFoundError
from app.core.validation import validate_module_output
from app.orchestrator.pipeline import InvestigationOrchestrator
from app.schemas.api import (
    DecisionRequest,
    DecisionResponse,
    SimulateResponseRequest,
    SimulateResponseResponse,
)
from app.schemas.enums import IncidentStatus
from app.schemas.graph import AttackGraph, IncidentTimeline
from app.schemas.response import AuditEvent, FinalIncident, ResponseSimulation
from app.services.incident_store import IncidentStore

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/{incident_id}", response_model=FinalIncident)
async def get_incident(
    incident_id: str,
    store: IncidentStore = Depends(get_incident_store),
) -> FinalIncident:
    return store.get(incident_id)


@router.get("/{incident_id}/timeline", response_model=IncidentTimeline)
async def get_timeline(
    incident_id: str,
    store: IncidentStore = Depends(get_incident_store),
) -> IncidentTimeline:
    incident = store.get(incident_id)
    if not incident.investigation.timeline:
        raise NotFoundError(f"Timeline not available for incident '{incident_id}'")
    return incident.investigation.timeline


@router.get("/{incident_id}/graph", response_model=AttackGraph)
async def get_graph(
    incident_id: str,
    store: IncidentStore = Depends(get_incident_store),
) -> AttackGraph:
    incident = store.get(incident_id)
    if not incident.investigation.attack_graph:
        raise NotFoundError(f"Attack graph not available for incident '{incident_id}'")
    return incident.investigation.attack_graph


@router.post("/{incident_id}/simulate-response", response_model=SimulateResponseResponse)
async def simulate_response(
    incident_id: str,
    request: SimulateResponseRequest,
    store: IncidentStore = Depends(get_incident_store),
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
) -> SimulateResponseResponse:
    incident = store.get(incident_id)
    simulation = validate_module_output(
        "response",
        ResponseSimulation,
        await orchestrator.services.response.simulate(
            incident_id,
            incident.response,
            request.action_ids,
        ),
    )
    store.save_simulation(simulation)
    return SimulateResponseResponse(simulation=simulation)


@router.post("/{incident_id}/decision", response_model=DecisionResponse)
async def record_decision(
    incident_id: str,
    request: DecisionRequest,
    store: IncidentStore = Depends(get_incident_store),
) -> DecisionResponse:
    incident = store.get(incident_id)
    audit_event = AuditEvent(
        audit_id=f"aud-{uuid.uuid4().hex[:8]}",
        incident_id=incident_id,
        event_type="analyst_decision",
        actor=request.analyst_id,
        message=f"Decision: {request.action.value} — {request.comment or 'No comment'}",
        timestamp=datetime.now(timezone.utc),
        metadata={"approved_actions": ",".join(request.approved_actions)},
    )

    new_status = IncidentStatus.RESOLVED if request.action.value == "approve" else incident.status
    if request.action.value == "escalate":
        new_status = IncidentStatus.INVESTIGATING

    updated = incident.model_copy(
        update={
            "status": new_status,
            "updated_at": datetime.now(timezone.utc),
            "audit_trail": [*incident.audit_trail, audit_event],
        }
    )
    store.update(updated)

    return DecisionResponse(
        incident_id=incident_id,
        status=new_status.value,
        message=f"Analyst decision recorded: {request.action.value}",
        audit_event_id=audit_event.audit_id,
    )


@router.get("/{incident_id}/report")
async def get_report(
    incident_id: str,
    store: IncidentStore = Depends(get_incident_store),
) -> PlainTextResponse:
    incident = store.get(incident_id)
    return PlainTextResponse(
        content=incident.report.markdown_content,
        media_type="text/markdown",
        headers={
            "Content-Disposition": f'attachment; filename="incident-{incident_id}.md"',
        },
    )
