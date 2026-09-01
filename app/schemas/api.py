"""API request/response models."""

from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.schemas.enums import DecisionAction
from app.schemas.response import FinalIncident, ResponseSimulation


class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    modules: str


class InvestigateRequest(BaseModel):
    """Trigger full investigation pipeline."""

    use_sample_logs: bool = Field(
        default=True,
        description="When true, use built-in sample logs instead of raw_logs",
    )
    raw_logs: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Optional raw log payloads for KV ingestion module",
    )
    scenario: str | None = Field(
        default=None,
        description="Optional scenario name for deterministic mock behavior",
    )

    @field_validator("raw_logs")
    @classmethod
    def validate_raw_logs_when_not_sample(cls, value: list[dict[str, Any]], info) -> list[dict[str, Any]]:
        use_sample = info.data.get("use_sample_logs", True)
        if not use_sample and not value:
            raise ValueError("raw_logs required when use_sample_logs is false")
        return value


class InvestigateResponse(BaseModel):
    incident: FinalIncident


class SimulateResponseRequest(BaseModel):
    action_ids: list[str] | None = Field(
        default=None,
        description="Subset of response actions to simulate; defaults to all recommended",
    )


class SimulateResponseResponse(BaseModel):
    simulation: ResponseSimulation


class DecisionRequest(BaseModel):
    analyst_id: str = Field(..., min_length=1)
    action: DecisionAction
    comment: str = ""
    approved_actions: list[str] = Field(default_factory=list)


class DecisionResponse(BaseModel):
    incident_id: str
    status: str
    message: str
    audit_event_id: str


class ErrorResponse(BaseModel):
    error: str
    code: str
    details: dict[str, Any] = Field(default_factory=dict)
