"""Attack graph and timeline schemas (ROHIT-owned pipeline stages)."""

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.enums import Severity, ThreatCategory


class GraphNode(BaseModel):
    node_id: str = Field(..., min_length=1)
    label: str = Field(..., min_length=1)
    node_type: str = Field(..., min_length=1, description="host, user, process, file, ip")
    attributes: dict[str, str] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    edge_id: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    target_id: str = Field(..., min_length=1)
    relationship: str = Field(..., min_length=1, description="e.g. authenticated_to, executed")
    event_id: str | None = None
    timestamp: datetime | None = None


class AttackGraph(BaseModel):
    """Structured attack progression graph."""

    incident_id: str = Field(..., min_length=1)
    nodes: list[GraphNode] = Field(..., min_length=1)
    edges: list[GraphEdge] = Field(default_factory=list)
    entry_point: str = Field(..., min_length=1)
    objective: str | None = None


class TimelineEntry(BaseModel):
    entry_id: str = Field(..., min_length=1)
    timestamp: datetime
    event_id: str
    stage: str = Field(..., min_length=1, description="e.g. initial_access, execution")
    description: str = Field(..., min_length=1)
    severity: Severity
    mitre_technique: str | None = None


class IncidentTimeline(BaseModel):
    incident_id: str = Field(..., min_length=1)
    entries: list[TimelineEntry] = Field(..., min_length=1)
    attack_chain: list[str] = Field(default_factory=list, description="Ordered MITRE technique IDs")
