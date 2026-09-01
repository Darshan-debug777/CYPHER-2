"""Health check routes."""

from fastapi import APIRouter

from app.config import settings
from app.schemas.api import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        version=settings.app_version,
        modules="mock" if settings.use_mock_modules else "custom",
    )
