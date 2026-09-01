"""Investigation trigger route."""

from fastapi import APIRouter, Depends

from app.api.dependencies import get_orchestrator
from app.orchestrator.pipeline import InvestigationOrchestrator
from app.schemas.api import InvestigateRequest, InvestigateResponse

router = APIRouter(tags=["investigation"])


@router.post("/investigate", response_model=InvestigateResponse)
async def investigate(
    request: InvestigateRequest,
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
) -> InvestigateResponse:
    incident = await orchestrator.investigate(request)
    return InvestigateResponse(incident=incident)
