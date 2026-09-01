# Developer Integration Guide

## Team Ownership

| Teammate | Responsibility | Interface to Implement | Mock to Replace |
|----------|---------------|------------------------|-----------------|
| **DARSHAN** | Architecture, API, orchestration, schemas, mocks | All interfaces (defines contracts) | N/A |
| **KV** | Log ingestion, parsing, normalization | `IngestionService` | `MockIngestionService` |
| **MRUN** | Context engine, threat detection, correlation | `DetectionService`, `CorrelationService` | `MockDetectionService`, `MockCorrelationService` |
| **ROHIT** | Attack graph, incident reconstruction, E2E integration | `AttackGraphService`, optional `ReconstructionService` | `MockAttackGraphService` |
| **NIHARIKA** | Investigation dashboard, evidence viz, timeline UI | Consumes REST API only | N/A |
| **SANSAAR** | Risk display, response UI, approval, audit UI | Consumes REST API only | N/A |

## How to Replace a Mock Module

### Step 1: Implement the interface

Create your module in a team folder, e.g. `app/modules/kv/ingestion.py`:

```python
from app.schemas.events import NormalizedEvent

class KVIngestionService:
    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]:
        # Your real parsing logic here
        ...
```

Your class must match the Protocol in `app/interfaces/__init__.py`:
- Same method name
- Same input types
- Same return type (Pydantic model)
- Raise `AppError` subclasses on failure (see `app/core/errors.py`)

### Step 2: Register in factory

Edit `app/factory.py`:

```python
from app.modules.kv.ingestion import KVIngestionService

def build_services() -> ServiceContainer:
    return ServiceContainer(
        ingestion=KVIngestionService(),  # replaces MockIngestionService
        # detection=MRUNDetectionService(),  # when MRUN is ready
        # ...
    )
```

**No changes needed** to the orchestrator or API routes.

### Step 3: Test independently

```python
from app.modules.kv.ingestion import KVIngestionService
from app.mocks.sample_logs import SAMPLE_RAW_LOGS

async def test_kv_ingestion():
    svc = KVIngestionService()
    events = await svc.normalize(SAMPLE_RAW_LOGS)
    assert len(events) > 0
    assert all(e.event_id for e in events)
```

## API Endpoints for Frontend

Base URL: `http://localhost:8000`

| Method | Path | Purpose | Consumer |
|--------|------|---------|----------|
| GET | `/health` | Health check | All |
| POST | `/api/v1/investigate` | Run full pipeline | Dashboard trigger |
| GET | `/api/v1/incidents/{id}` | Full incident | Niharika, Sanskaar |
| GET | `/api/v1/incidents/{id}/timeline` | Attack timeline | Niharika |
| GET | `/api/v1/incidents/{id}/graph` | Attack graph nodes/edges | Niharika |
| POST | `/api/v1/incidents/{id}/simulate-response` | Response simulation | Sanskaar |
| POST | `/api/v1/incidents/{id}/decision` | Human approval | Sanskaar |
| GET | `/api/v1/incidents/{id}/report` | Downloadable markdown report | Both |

### Example: Trigger investigation

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Content-Type: application/json" \
  -d '{"use_sample_logs": true}'
```

### Example response shape (abbreviated)

```json
{
  "incident": {
    "incident_id": "INC-A1B2C3D4",
    "status": "awaiting_approval",
    "investigation": {
      "threat_classification": "lateral_movement",
      "severity": "critical",
      "evidence": [...],
      "explanation": "..."
    },
    "risk": {
      "risk_score": 96.0,
      "risk_level": "critical"
    },
    "response": {
      "actions": [...]
    },
    "report": {
      "markdown_content": "# Incident Report..."
    }
  }
}
```

## Error Contract

All API errors return:

```json
{
  "error": "Human-readable message",
  "code": "validation_error | not_found | module_error | ...",
  "details": {}
}
```

HTTP status codes:
- `400` — validation / module errors
- `404` — incident not found
- `422` — request body validation
- `500` — unhandled (details hidden unless `SIH_DEBUG=true`)

## Running the Backend

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Run tests:

```bash
pytest -v
```

## Integration Checklist (ROHIT)

- [ ] KV module returns valid `NormalizedEvent` list
- [ ] MRUN detection returns valid `DetectionResult` list
- [ ] MRUN correlation returns valid `CorrelatedIncident`
- [ ] ROHIT graph returns valid `AttackGraph` + `IncidentTimeline`
- [ ] All modules registered in `factory.py`
- [ ] `POST /api/v1/investigate` returns `FinalIncident`
- [ ] Frontend can fetch timeline, graph, report
- [ ] E2E test passes with real modules

## Mock Scenario

The built-in mock simulates:

1. 3× failed login (brute force)
2. Successful login from unknown IP
3. VPN remote access
4. PowerShell execution
5. SMB lateral movement
6. Sensitive finance file access

This produces realistic evidence, MITRE mappings, risk score ~96, and 4 recommended response actions.
