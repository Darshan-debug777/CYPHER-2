# Data Schema Reference

All schemas live in `app/schemas/`. Each is a Pydantic v2 model used as an inter-module contract.

## SecurityEvent (raw log)

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| event_id | str | yes | Unique raw event ID |
| source | str | yes | Log source (auth, edr, etc.) |
| timestamp | datetime | yes | Event time (ISO 8601) |
| raw_message | str | yes | Unparsed log line |
| metadata | dict | no | Source-specific fields |

```json
{
  "event_id": "raw-001",
  "source": "auth",
  "timestamp": "2026-03-15T02:00:00+00:00",
  "raw_message": "Failed login for user admin from 203.0.113.45",
  "metadata": {"user": "admin", "src_ip": "203.0.113.45"}
}
```

## NormalizedEvent

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| event_id | str | yes | Normalized event ID |
| source | str | yes | Log source |
| timestamp | datetime | yes | Event time |
| event_type | str | yes | Standardized type (failed_login, etc.) |
| actor | str | no | User/IP/host |
| target | str | no | Affected resource |
| severity_hint | Severity | no | Pre-detection severity hint |
| attributes | dict | no | Extra normalized fields |
| raw_event_id | str | yes | Link to SecurityEvent |

## DetectionResult

| Field | Type | Required | Validation | Purpose |
|-------|------|----------|------------|---------|
| detection_id | str | yes | min_length=1 | Unique detection ID |
| event_id | str | yes | | Linked normalized event |
| threat_type | str | yes | | Human-readable threat name |
| category | ThreatCategory | yes | enum | Threat category |
| severity | Severity | yes | enum | low/medium/high/critical |
| confidence | float | yes | 0.0–1.0 | Detection confidence |
| indicators | list[str] | no | | MITRE IDs, IOCs |
| description | str | yes | | Detection summary |

## CorrelatedIncident

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Unique incident ID (INC-XXXXXXXX) |
| title | str | yes | Incident title |
| summary | str | yes | Brief description |
| related_event_ids | list[str] | yes | All linked event IDs |
| detections | list[DetectionResult] | yes | All detections |
| normalized_events | list[NormalizedEvent] | no | Full event context |
| first_seen | datetime | yes | Earliest event |
| last_seen | datetime | yes | Latest event |
| primary_category | ThreatCategory | no | Dominant threat type |
| severity | Severity | yes | Overall severity |

## AttackGraph

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Parent incident |
| nodes | list[GraphNode] | yes | Entities (host, user, ip, file) |
| edges | list[GraphEdge] | no | Relationships between nodes |
| entry_point | str | yes | Initial compromise node ID |
| objective | str | no | Target node ID |

## IncidentTimeline

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Parent incident |
| entries | list[TimelineEntry] | yes | Ordered attack stages |
| attack_chain | list[str] | no | MITRE technique sequence |

## InvestigationResult

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Parent incident |
| summary | str | yes | Investigation summary |
| threat_classification | ThreatCategory | yes | Final classification |
| severity | Severity | yes | Assessed severity |
| evidence | list[Evidence] | yes | Supporting evidence items |
| explanation | str | yes | Evidence-backed reasoning |
| mitre_techniques | list[str] | no | Mapped techniques |
| attack_progression | list[str] | no | Stage names in order |
| agents_used | list[str] | no | Which AI agents contributed |
| timeline | IncidentTimeline | no | Embedded timeline |
| attack_graph | AttackGraph | no | Embedded graph |

## Evidence

| Field | Type | Required | Validation | Purpose |
|-------|------|----------|------------|---------|
| evidence_id | str | yes | | Unique evidence ID |
| event_id | str | yes | | Source event |
| source | str | yes | | Log source |
| description | str | yes | | What was observed |
| snippet | str | yes | | Raw log excerpt |
| confidence | float | yes | 0.0–1.0 | Evidence strength |
| supports | str | yes | | Claim this supports |

## RiskAssessment

| Field | Type | Required | Validation | Purpose |
|-------|------|----------|------------|---------|
| incident_id | str | yes | | Parent incident |
| risk_score | float | yes | 0–100 | Numeric risk |
| risk_level | RiskLevel | yes | enum | low/medium/high/critical |
| confidence | float | yes | 0.0–1.0 | Assessment confidence |
| factors | list[str] | no | | Risk contributing factors |
| business_impact | str | yes | | Impact description |
| assessed_at | datetime | yes | | Assessment timestamp |

## ResponseRecommendation

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Parent incident |
| actions | list[ResponseAction] | yes | Recommended actions |
| rationale | str | yes | Why these actions |
| requires_human_approval | bool | yes | Needs analyst sign-off |

## FinalIncident

Top-level API response object combining all pipeline outputs.

| Field | Type | Required | Purpose |
|-------|------|----------|---------|
| incident_id | str | yes | Unique ID |
| status | IncidentStatus | yes | Workflow status |
| title | str | yes | Display title |
| investigation | InvestigationResult | yes | Full investigation |
| risk | RiskAssessment | yes | Risk scoring |
| response | ResponseRecommendation | yes | Recommended actions |
| report | IncidentReport | yes | Generated report |
| audit_trail | list[AuditEvent] | no | Pipeline audit log |
| created_at | datetime | yes | Creation time |
| updated_at | datetime | yes | Last update |

See `app/schemas/` for full definitions and validation rules.
