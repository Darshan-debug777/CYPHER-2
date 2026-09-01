# SIH26 Cybersecurity Assistant — Backend

**Project ID:** SIH26S01  
**Owner:** DARSHAN — System Architecture, FastAPI Backend, Orchestration

A fully working, deterministic mock-based investigation pipeline backend. Teammates independently plug in real modules via `app/factory.py` without changing the API, orchestrator, or schemas.

---

## Quick Start

### Prerequisites
- Python 3.11+
- Virtual environment

### Installation & Running

```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows: venv\Scripts\activate.bat
pip install -r requirements.txt

# Start server
uvicorn app.main:app --reload --port 8000
```

- **Interactive API docs:** http://localhost:8000/docs
- **Health check:** http://localhost:8000/health

### Testing

```bash
pytest -v                       # All tests
pytest tests/test_api.py -v     # API only
pytest tests/test_orchestrator.py -v   # Orchestration
pytest --co                     # List all tests
```

All 23 tests pass ✓

---

## Directory Structure

```
backend/
├── app/
│   ├── main.py                 # FastAPI app, exception handlers
│   ├── config.py               # Settings (from .env or defaults)
│   ├── factory.py              # Service factory — swap mocks here
│   ├── api/
│   │   ├── routes/
│   │   │   ├── health.py       # GET /health
│   │   │   ├── investigation.py    # POST /api/v1/investigate
│   │   │   └── incidents.py    # GET/POST /api/v1/incidents/*
│   │   └── dependencies.py     # FastAPI dependency injection
│   ├── schemas/                # Pydantic models (team contracts)
│   │   ├── api.py              # Request/response DTOs
│   │   ├── enums.py            # Severity, ThreatCategory, etc.
│   │   ├── events.py           # SecurityEvent, NormalizedEvent
│   │   ├── detection.py        # DetectionResult, CorrelatedIncident
│   │   ├── investigation.py    # Evidence, InvestigationResult, RiskAssessment
│   │   ├── graph.py            # AttackGraph, IncidentTimeline
│   │   └── response.py         # ResponseRecommendation, IncidentReport, FinalIncident
│   ├── interfaces/
│   │   └── __init__.py         # Protocol definitions for all modules
│   ├── orchestrator/
│   │   └── pipeline.py         # InvestigationOrchestrator (no business logic)
│   ├── mocks/                  # Reference implementations (DARSHAN)
│   │   ├── ingestion.py        # KV placeholder
│   │   ├── detection.py        # MRUN placeholder
│   │   ├── correlation.py      # MRUN placeholder
│   │   ├── attack_graph.py     # ROHIT placeholder
│   │   ├── investigation.py    # AI agents placeholder
│   │   ├── risk.py             # Risk assessment placeholder
│   │   ├── response.py         # Response recommendation placeholder
│   │   ├── report.py           # Report generation placeholder
│   │   └── sample_logs.py      # Hardcoded test data
│   ├── services/
│   │   └── incident_store.py   # In-memory incident storage
│   └── core/
│       ├── errors.py           # AppError, ValidationError, ModuleError, etc.
│       ├── validation.py       # validate_module_output, validate_non_empty_list
│       └── logging.py          # Logger setup
├── tests/
│   ├── conftest.py             # pytest fixtures (FastAPI test client)
│   ├── fakes.py                # Test doubles for error paths
│   ├── test_api.py             # API endpoint tests (8 tests)
│   ├── test_orchestrator.py    # Pipeline orchestration (2 tests)
│   ├── test_errors.py          # Error handling (8 tests)
│   └── test_schemas.py         # Schema validation (5 tests)
├── docs/
│   ├── ARCHITECTURE.md         # Detailed architecture & ownership
│   ├── SCHEMAS.md              # Complete schema reference
│   └── INTEGRATION.md          # How teammates integrate
├── requirements.txt
├── pytest.ini
└── README.md
```

---

## Architecture Overview

### Pipeline Flow (Orchestrator)

The `InvestigationOrchestrator` executes this sequence with full validation and error handling:

```
1. INGESTION (KV)
   Input:  raw_logs: list[dict] | None
   Output: list[NormalizedEvent]
   
2. DETECTION (MRUN)
   Input:  list[NormalizedEvent]
   Output: list[DetectionResult]
   
3. CORRELATION (MRUN)
   Input:  list[NormalizedEvent], list[DetectionResult]
   Output: CorrelatedIncident
   
4. ATTACK GRAPH (ROHIT)
   Input:  CorrelatedIncident
   Output: tuple[AttackGraph, IncidentTimeline]
   
5. INVESTIGATION (AI Agents)
   Input:  CorrelatedIncident, AttackGraph, IncidentTimeline
   Output: InvestigationResult (with evidence, explanation)
   
6. RISK ASSESSMENT
   Input:  InvestigationResult
   Output: RiskAssessment (risk_score, risk_level, confidence)
   
7. RESPONSE RECOMMENDATION
   Input:  InvestigationResult, RiskAssessment
   Output: ResponseRecommendation (actions with priorities)
   
8. REPORT GENERATION
   Input:  InvestigationResult, RiskAssessment, ResponseRecommendation
   Output: IncidentReport (markdown_content)
   
9. FINAL INCIDENT
   Combines all results + audit_trail → FinalIncident
```

### Data Contracts (Schemas)

All inter-module communication uses **Pydantic v2 models** defined in `app/schemas/`:

- **SecurityEvent** → raw log entry
- **NormalizedEvent** → standardized after ingestion
- **DetectionResult** → single threat detection
- **CorrelatedIncident** → grouped detections into one incident
- **AttackGraph** + **IncidentTimeline** → attack progression
- **Evidence** → supporting proof items
- **InvestigationResult** → AI analysis + reasoning
- **RiskAssessment** → quantified risk
- **ResponseRecommendation** → recommended actions
- **IncidentReport** → final markdown summary
- **FinalIncident** → complete response to API

See [docs/SCHEMAS.md](docs/SCHEMAS.md) for detailed field documentation.

### API Endpoints

All endpoints respect the same error contract (`ErrorResponse`).

#### Core Endpoints

| Method | Path | Purpose | Consumes | Produces |
|--------|------|---------|----------|----------|
| GET | `/health` | Health check | — | `{"status": "ok", "version": "...", "modules": "mock"}` |
| POST | `/api/v1/investigate` | Run full pipeline | `InvestigateRequest` | `{"incident": FinalIncident}` |

#### Incident Management

| Method | Path | Purpose | Consumes | Produces |
|--------|------|---------|----------|----------|
| GET | `/api/v1/incidents/{id}` | Retrieve full incident | — | `FinalIncident` |
| GET | `/api/v1/incidents/{id}/timeline` | Attack timeline | — | `IncidentTimeline` |
| GET | `/api/v1/incidents/{id}/graph` | Attack graph | — | `AttackGraph` |
| POST | `/api/v1/incidents/{id}/simulate-response` | Simulate actions | `SimulateResponseRequest` | `{"simulation": ResponseSimulation}` |
| POST | `/api/v1/incidents/{id}/decision` | Record analyst decision | `DecisionRequest` | `{"status": "...", "message": "...", ...}` |
| GET | `/api/v1/incidents/{id}/report` | Download markdown | — | `text/markdown` |

### Orchestration & Validation

**File:** `app/orchestrator/pipeline.py`

```python
class InvestigationOrchestrator:
    async def investigate(self, request: InvestigateRequest) -> FinalIncident:
        # 1. Calls each module in sequence
        # 2. Validates output using Pydantic models
        # 3. Catches exceptions and converts to AppError subclasses
        # 4. Tracks audit events (who, when, what)
        # 5. Stores result in IncidentStore
        # 6. Returns FinalIncident
```

**Error Handling:**
- Module timeout → `ModuleTimeoutError` (HTTP 502)
- Module returns None/wrong type → `InvalidModuleOutputError` (HTTP 502)
- Module returns empty list → `EmptyResultError` (HTTP 502)
- Orchestrator raises AppError → HTTP 400/404/502 with `ErrorResponse`
- Request validation fails → HTTP 422 with Pydantic errors

---

## Data Contracts & Team Integration

### Schemas as Contracts

Each module has an input type and output type, both Pydantic models:

```python
class IngestionService(Protocol):
    async def normalize(
        self, 
        raw_logs: list[dict] | None = None
    ) -> list[NormalizedEvent]:
        """
        INPUT:  list[dict] with SecurityEvent structure
        OUTPUT: list[NormalizedEvent] — must not be empty
        ERROR:  Raise ValidationError or EmptyResultError
        """
```

**Critical constraints:**
- All outputs must be **non-empty lists** where required
- All fields in schemas must be **populated with valid data**
- Confidence scores must be **0.0–1.0**
- Risk scores must be **0.0–100.0**
- Enums must use **exact values** (e.g., `Severity.CRITICAL`)

### Module Interfaces

**File:** `app/interfaces/__init__.py`

Protocols for all team modules:

- `IngestionService.normalize()` → KV
- `DetectionService.detect()` → MRUN
- `CorrelationService.correlate()` → MRUN
- `AttackGraphService.build()` → ROHIT
- `InvestigationService.investigate()` → AI agents
- `RiskService.assess()` → DARSHAN (stub, replaceable)
- `ResponseService.recommend() / simulate()` → DARSHAN (stub, replaceable)
- `ReportService.generate()` → DARSHAN (stub, replaceable)

---

## How Mocks Work

### Reference Implementations

**File:** `app/mocks/`

Each mock implements the corresponding Protocol and produces **deterministic, realistic output**:

- **MockIngestionService:** Normalizes sample logs using keyword rules
- **MockDetectionService:** Detects threats based on event type
- **MockCorrelationService:** Groups events into a single incident
- **MockAttackGraphService:** Builds a 6-node graph with SMB lateral movement attack
- **MockInvestigationService:** Returns hardcoded evidence-backed explanation
- **MockRiskService:** Scores based on severity and evidence count
- **MockResponseService:** Recommends 4 actions (isolate, reset creds, block IP, quarantine)
- **MockReportService:** Generates markdown report with all evidence

**Design principle:** Mocks are **complete, working, and independent**. The pipeline runs end-to-end with mocks alone.

### Sample Logs

**File:** `app/mocks/sample_logs.py`

Hardcoded list of 8 `SecurityEvent` objects covering a realistic attack chain:
- 3 failed logins
- 1 successful login
- 1 VPN session
- 1 PowerShell execution
- 1 SMB connection
- 1 sensitive file access

Used when `InvestigateRequest(use_sample_logs=True)`.

---

## How to Replace a Mock with Your Real Module

### Prerequisites

- Implement a class matching the Protocol signature
- Handle errors correctly (raise `AppError` subclasses)
- Test independently before integrating

### Step-by-Step Integration

#### 1. Create Your Module

Example (KV ingestion):

```python
# app/modules/kv/ingestion.py
from app.schemas.events import NormalizedEvent, SecurityEvent
from app.core.errors import ValidationError, EmptyResultError

class KVIngestionService:
    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]:
        if not raw_logs:
            raw_logs = []  # or load defaults
        
        normalized = []
        for entry in raw_logs:
            try:
                raw = SecurityEvent.model_validate(entry)
            except Exception as e:
                raise ValidationError(f"Malformed log: {entry}", details={"error": str(e)})
            
            # Your parsing logic here
            normalized.append(NormalizedEvent(...))
        
        if not normalized:
            raise EmptyResultError("ingestion", "No events after parsing")
        
        return normalized
```

#### 2. Register in Factory

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

#### 3. No Other Changes Needed

- API routes: **unchanged**
- Orchestrator: **unchanged**
- Tests: **rerun to verify**

#### 4. Test Your Module

```python
import pytest
from app.modules.kv.ingestion import KVIngestionService
from app.schemas.events import SecurityEvent

@pytest.mark.asyncio
async def test_kv_ingestion_parses_logs():
    svc = KVIngestionService()
    raw = [
        {
            "event_id": "raw-001",
            "source": "auth",
            "timestamp": "2026-03-15T02:00:00Z",
            "raw_message": "Failed login for admin",
            "metadata": {}
        }
    ]
    events = await svc.normalize(raw)
    assert len(events) == 1
    assert events[0].event_type in ["failed_login", "unknown"]
```

---

## Error Handling

### Exception Hierarchy

```
AppError (base class)
├── ValidationError          → HTTP 400
├── NotFoundError           → HTTP 404
├── ModuleError             → HTTP 502
│   ├── ModuleTimeoutError
│   ├── EmptyResultError
│   └── InvalidModuleOutputError
```

### Example: Module Timeout

```python
# In orchestrator._run_stage()
try:
    return await asyncio.wait_for(coro, timeout=30.0)
except asyncio.TimeoutError:
    raise ModuleTimeoutError("ingestion", 30.0)  # → HTTP 502
```

### Example: Validation Failure

```python
# In orchestrator.investigate()
normalized = validate_model_list(
    "ingestion",
    NormalizedEvent,
    await self._run_stage("ingestion", self.services.ingestion.normalize(...))
)
# If any item fails Pydantic validation → InvalidModuleOutputError (HTTP 502)
```

---

## Testing

### Test Coverage

- **test_api.py** (8 tests): Full API flow, incident retrieval, simulation, decision, report
- **test_orchestrator.py** (2 tests): Mock pipeline execution, graph/timeline production
- **test_schemas.py** (5 tests): Schema validation, constraints (bounds, lengths)
- **test_errors.py** (8 tests): Module failures, empty results, invalid output, API error codes

### Running Tests

```bash
# All tests
pytest -v

# Specific file
pytest tests/test_api.py -v

# Specific test
pytest tests/test_api.py::test_investigate_returns_final_incident -v

# Stop on first failure
pytest -x

# Show print statements
pytest -s
```

### Test Client

**File:** `tests/conftest.py`

FastAPI `TestClient` with ASGI transport, bypasses HTTP overhead.

```python
@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c
```

---

## Development Notes

### Configuration

**File:** `app/config.py`

Settings from environment variables (prefix `SIH_`):

```python
app_name = "SIH26 Cybersecurity Assistant API"
app_version = "0.1.0"
debug = False
api_prefix = "/api/v1"
module_timeout_seconds = 30.0
use_mock_modules = True
log_level = "INFO"
```

Override via `.env`:
```
SIH_DEBUG=true
SIH_LOG_LEVEL=DEBUG
```

### Logging

**File:** `app/core/logging.py`

Structured logging with timestamps, levels, and module names.

```python
logger = logging.getLogger(__name__)
logger.info("Pipeline completed for incident %s", incident_id)
```

### Incident Store

**File:** `app/services/incident_store.py`

In-memory singleton (thread-safe) for prototype. In production, replace with database.

```python
incident_store = IncidentStore()
incident_store.save(final_incident)
incident_store.get("INC-12345")
```

---

## API Examples
│  INTERFACES         app/interfaces/   (Protocols)       │
└───────────────────────────┬─────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   KV (ingestion)     MRUN (detect/correlate)  ROHIT (graph)
   app/mocks/*        replace in factory.py    replace in factory.py
```

### Pipeline order (orchestrator)

```
ingestion/normalization → detection → correlation → attack graph
  → investigation → risk → response → report → FinalIncident
```

---

## Directory Structure

```
backend/
├── app/
│   ├── main.py                 # FastAPI app + error handlers
│   ├── config.py               # Settings (SIH_ env prefix)
│   ├── factory.py              # ★ Swap mocks for real modules here
│   ├── api/
│   │   ├── dependencies.py
│   │   └── routes/
│   │       ├── health.py
│   │       ├── investigation.py   # POST /investigate
│   │       └── incidents.py       # GET incident, timeline, graph, etc.
│   ├── schemas/                # Data contracts (Pydantic)
│   │   ├── events.py           # SecurityEvent, NormalizedEvent
│   │   ├── detection.py        # DetectionResult, CorrelatedIncident
│   │   ├── graph.py            # AttackGraph, IncidentTimeline
│   │   ├── investigation.py    # Evidence, InvestigationResult, RiskAssessment
│   │   ├── response.py         # Response*, AuditEvent, IncidentReport, FinalIncident
│   │   └── api.py              # Request/response DTOs
│   ├── interfaces/__init__.py  # Protocol definitions per module
│   ├── orchestrator/pipeline.py
│   ├── mocks/                  # Deterministic placeholder implementations
│   ├── services/incident_store.py   # In-memory incident storage
│   └── core/
│       ├── errors.py
│       ├── validation.py       # Module output validation
│       └── logging.py
├── tests/
├── docs/                       # Extended reference docs
└── requirements.txt
```

---

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/investigate` | Run full investigation pipeline |
| GET | `/api/v1/incidents/{id}` | Get `FinalIncident` |
| GET | `/api/v1/incidents/{id}/timeline` | Attack timeline |
| GET | `/api/v1/incidents/{id}/graph` | Attack graph |
| POST | `/api/v1/incidents/{id}/simulate-response` | Simulate response actions |
| POST | `/api/v1/incidents/{id}/decision` | Record analyst decision |
| GET | `/api/v1/incidents/{id}/report` | Download markdown report |

### POST /api/v1/investigate

**Request:**
```json
{ "use_sample_logs": true }
```

**Response:** `{ "incident": { ...FinalIncident } }`

### Error format (all endpoints)

```json
{
  "error": "Human-readable message",
  "code": "validation_error | not_found | module_error | internal_error",
  "details": {}
}
```

| HTTP | When |
|------|------|
| 400 | Invalid input / malformed logs |
| 404 | Incident not found |
| 422 | Request body schema validation |
| 502 | Pipeline module failure, empty result, invalid module output |
| 500 | Unexpected server error |

---

## Data Contracts

| Schema | File | Used by |
|--------|------|---------|
| `SecurityEvent` | events.py | KV ingestion input |
| `NormalizedEvent` | events.py | Pipeline after normalization |
| `DetectionResult` | detection.py | MRUN detection output |
| `CorrelatedIncident` | detection.py | MRUN correlation output |
| `AttackGraph` | graph.py | ROHIT graph output |
| `IncidentTimeline` | graph.py | ROHIT timeline output |
| `InvestigationResult` | investigation.py | Investigation agents |
| `Evidence` | investigation.py | Embedded in investigation/report |
| `RiskAssessment` | investigation.py | Risk scoring |
| `ResponseRecommendation` | response.py | Response module |
| `ResponseSimulation` | response.py | Simulate endpoint |
| `AnalystDecision` | response.py | Decision contract (API uses `DecisionRequest`) |
| `AuditEvent` | response.py | Audit trail entries |
| `IncidentReport` | response.py | Report generation |
| `FinalIncident` | response.py | Top-level API response |

Each module **must** return instances matching these schemas. The orchestrator validates every stage output via `app/core/validation.py`.

---

## How Mocks Work

Built-in scenario in `app/mocks/sample_logs.py`:

1. Failed logins (brute force)  
2. Successful login from external IP  
3. VPN from unknown geo  
4. PowerShell execution  
5. SMB lateral movement  
6. Sensitive finance file access  

Mock modules in `app/mocks/` produce deterministic structured data: evidence, MITRE techniques, risk score ~98, 4 response actions, downloadable markdown report.

Run with defaults — no teammate code required:

```bash
curl -X POST http://localhost:8000/api/v1/investigate \
  -H "Content-Type: application/json" \
  -d "{\"use_sample_logs\": true}"
```

---

## Replace a Mock with Real Implementation

### 1. Implement the interface

Example for KV (`app/interfaces/__init__.py` → `IngestionService`):

```python
# app/modules/kv/ingestion.py
from app.schemas.events import NormalizedEvent

class KVIngestionService:
    async def normalize(self, raw_logs: list[dict] | None = None) -> list[NormalizedEvent]:
        ...
```

Must match: method name, input types, return type, raise `AppError` subclasses on failure.

### 2. Register in factory

```python
# app/factory.py
from app.modules.kv.ingestion import KVIngestionService

def build_services() -> ServiceContainer:
    return ServiceContainer(
        ingestion=KVIngestionService(),
        # detection=MRUNDetectionService(),
        # correlation=MRUNCorrelationService(),
        # attack_graph=RohitAttackGraphService(),
    )
```

**Do not modify** `app/orchestrator/pipeline.py` or API routes.

### 3. Test independently

```python
from app.modules.kv.ingestion import KVIngestionService
from app.mocks.sample_logs import SAMPLE_RAW_LOGS

async def test_kv():
    events = await KVIngestionService().normalize(SAMPLE_RAW_LOGS)
    assert len(events) > 0
```

---

## Team Ownership

| Person | Owns | Interface |
|--------|------|-----------|
| DARSHAN | API, schemas, orchestrator, mocks, factory | All contracts |
| KV | Log ingestion/normalization | `IngestionService` |
| MRUN | Detection, correlation | `DetectionService`, `CorrelationService` |
| ROHIT | Attack graph, E2E integration | `AttackGraphService` |
| NIHARIKA | Dashboard UI | Consumes API only |
| SANSAAR | Risk/response/approval UI | Consumes API only |

See also: `docs/ARCHITECTURE.md`, `docs/SCHEMAS.md`, `docs/INTEGRATION.md`
