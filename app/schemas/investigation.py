"""Investigation, evidence, and risk schemas."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import RiskLevel, Severity, ThreatCategory
from app.schemas.graph import AttackGraph, IncidentTimeline


class Evidence(BaseModel):
    """Evidence item supporting an investigation conclusion."""

    evidence_id: str = Field(..., min_length=1)
    event_id: str = Field(..., min_length=1)
    source: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    snippet: str = Field(..., min_length=1)
    confidence: float = Field(..., ge=0.0, le=1.0)
    supports: str = Field(..., min_length=1, description="What claim this evidence supports")


class InvestigationResult(BaseModel):
    """Output of specialized AI investigation agents."""

    incident_id: str = Field(..., min_length=1)
    summary: str = Field(..., min_length=1)
    threat_classification: ThreatCategory
    severity: Severity
    evidence: list[Evidence] = Field(..., min_length=1)
    explanation: str = Field(..., min_length=1, description="Evidence-backed reasoning")
    mitre_techniques: list[str] = Field(default_factory=list)
    attack_progression: list[str] = Field(default_factory=list)
    agents_used: list[str] = Field(default_factory=list)
    timeline: IncidentTimeline | None = None
    attack_graph: AttackGraph | None = None


class RiskAssessment(BaseModel):
    """Risk and confidence scoring for an incident."""

    incident_id: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: RiskLevel
    confidence: float = Field(..., ge=0.0, le=1.0)
    factors: list[str] = Field(default_factory=list)
    business_impact: str = Field(..., min_length=1)
    assessed_at: datetime
