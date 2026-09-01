"""Response, audit, and report schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import DecisionAction, IncidentStatus, RiskLevel, Severity, ThreatCategory
from app.schemas.investigation import Evidence, InvestigationResult, RiskAssessment


class ResponseAction(BaseModel):
    action_id: str = Field(..., min_length=1)
    priority: int = Field(..., ge=1, le=10)
    action_type: str = Field(..., min_length=1, description="e.g. isolate_host, reset_password")
    description: str = Field(..., min_length=1)
    target: str = Field(..., min_length=1)
    automated: bool = False


class ResponseRecommendation(BaseModel):
    incident_id: str = Field(..., min_length=1)
    actions: list[ResponseAction] = Field(..., min_length=1)
    rationale: str = Field(..., min_length=1)
    requires_human_approval: bool = True


class SimulationOutcome(BaseModel):
    action_id: str
    success: bool
    impact_summary: str
    side_effects: list[str] = Field(default_factory=list)


class ResponseSimulation(BaseModel):
    incident_id: str = Field(..., min_length=1)
    simulated_at: datetime
    outcomes: list[SimulationOutcome] = Field(..., min_length=1)
    overall_risk_reduction: float = Field(..., ge=0.0, le=100.0)
    notes: str = ""


class AnalystDecision(BaseModel):
    incident_id: str = Field(..., min_length=1)
    analyst_id: str = Field(..., min_length=1)
    action: DecisionAction
    comment: str = ""
    decided_at: datetime
    approved_actions: list[str] = Field(default_factory=list)


class AuditEvent(BaseModel):
    audit_id: str = Field(..., min_length=1)
    incident_id: str = Field(..., min_length=1)
    event_type: str = Field(..., min_length=1)
    actor: str = Field(..., min_length=1)
    message: str = Field(..., min_length=1)
    timestamp: datetime
    metadata: dict[str, str] = Field(default_factory=dict)


class IncidentReport(BaseModel):
    incident_id: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    generated_at: datetime
    executive_summary: str = Field(..., min_length=1)
    threat_classification: ThreatCategory
    severity: Severity
    risk_level: RiskLevel
    risk_score: float = Field(..., ge=0.0, le=100.0)
    evidence: list[Evidence] = Field(default_factory=list)
    explanation: str = Field(..., min_length=1)
    recommended_actions: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    timeline_summary: list[str] = Field(default_factory=list)
    markdown_content: str = Field(..., min_length=1)


class FinalIncident(BaseModel):
    """Complete pipeline output returned to API consumers."""

    incident_id: str = Field(..., min_length=1)
    status: IncidentStatus
    title: str = Field(..., min_length=1)
    investigation: InvestigationResult
    risk: RiskAssessment
    response: ResponseRecommendation
    report: IncidentReport
    audit_trail: list[AuditEvent] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime
