# SIH26 Backend Architecture

**Owner:** DARSHAN — System Architecture, Backend API, Orchestration

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FRONTEND (NIHARIKA + SANSAAR)                        │
│              Dashboard │ Timeline │ Graph │ Risk │ Response UI               │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ REST API
┌───────────────────────────────────▼─────────────────────────────────────────┐
│                        DARSHAN — API LAYER (FastAPI)                       │
│  GET /health                                                                │
│  POST /api/v1/investigate                                                   │
│  GET  /api/v1/incidents/{id}                                                │
│  GET  /api/v1/incidents/{id}/timeline                                       │
│  GET  /api/v1/incidents/{id}/graph                                          │
│  POST /api/v1/incidents/{id}/simulate-response                              │
│  POST /api/v1/incidents/{id}/decision                                       │
│  GET  /api/v1/incidents/{id}/report                                         │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼─────────────────────────────────────────┐
│                   DARSHAN — ORCHESTRATION LAYER                             │
│                   InvestigationOrchestrator.investigate()                   │
│   (wires modules, validates I/O, handles errors — NO business logic)        │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        │                           │                           │
        ▼                           ▼                           ▼
┌───────────────┐         ┌─────────────────┐         ┌─────────────────┐
│ KV            │         │ MRUN            │         │ ROHIT           │
│ Ingestion     │         │ Detection       │         │ Attack Graph    │
│ Normalization │         │ Correlation     │         │ Timeline        │
└───────┬───────┘         └────────┬────────┘         └────────┬────────┘
        │                          │                           │
        └──────────────────────────┼───────────────────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ Investigation Agents (mock)   │
                    │ Log Analysis + Threat Invest. │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ Risk Assessment (mock)        │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ Response + Simulation (mock)  │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ Report Generation (mock)      │
                    └──────────────┬───────────────┘
                                   ▼
                    ┌──────────────────────────────┐
                    │ FinalIncident + IncidentStore│
                    └──────────────────────────────┘
```

## Data Flow

```
RAW LOGS (SecurityEvent)
    ↓  [KV: IngestionService.normalize]
NORMALIZED EVENTS (NormalizedEvent)
    ↓  [MRUN: DetectionService.detect]
DETECTION RESULTS (DetectionResult)
    ↓  [MRUN: CorrelationService.correlate]
CORRELATED INCIDENT (CorrelatedIncident)
    ↓  [ROHIT: AttackGraphService.build]
ATTACK GRAPH + TIMELINE (AttackGraph, IncidentTimeline)
    ↓  [InvestigationService.investigate]
INVESTIGATION RESULT (InvestigationResult + Evidence)
    ↓  [RiskService.assess]
RISK ASSESSMENT (RiskAssessment)
    ↓  [ResponseService.recommend]
RESPONSE RECOMMENDATION (ResponseRecommendation)
    ↓  [ReportService.generate]
INCIDENT REPORT (IncidentReport)
    ↓
FINAL INCIDENT (FinalIncident)
```

## Component Ownership

| Component | Owner | Location |
|-----------|-------|----------|
| API routes, error handling | DARSHAN | `app/api/`, `app/main.py` |
| Schemas / contracts | DARSHAN | `app/schemas/` |
| Orchestrator | DARSHAN | `app/orchestrator/` |
| Module interfaces | DARSHAN | `app/interfaces/` |
| Mock implementations | DARSHAN (placeholders) | `app/mocks/` |
| Service factory | DARSHAN | `app/factory.py` |
| Ingestion / normalization | KV | Replace `MockIngestionService` |
| Detection / correlation | MRUN | Replace `MockDetectionService`, `MockCorrelationService` |
| Attack graph / timeline | ROHIT | Replace `MockAttackGraphService` |
| Frontend dashboard | NIHARIKA | External — consumes API |
| Risk / response UI | SANSAAR | External — consumes API |
| Final E2E integration | ROHIT | Wires real modules via factory |

## Project Structure

```
backend/
├── app/
│   ├── main.py              # FastAPI app
│   ├── config.py            # Settings
│   ├── factory.py           # Module wiring (swap mocks here)
│   ├── api/                 # DARSHAN — REST endpoints
│   ├── schemas/             # DARSHAN — data contracts
│   ├── interfaces/          # DARSHAN — Protocol definitions
│   ├── orchestrator/        # DARSHAN — pipeline wiring
│   ├── mocks/               # DARSHAN — deterministic placeholders
│   ├── services/            # DARSHAN — incident store
│   └── core/                # DARSHAN — errors, logging
├── tests/
├── docs/
└── requirements.txt
```

## Design Principles

1. **Dependency inversion** — Orchestrator depends on Protocol interfaces, not concrete implementations.
2. **Stable contracts** — Pydantic schemas are the integration boundary; teammates implement interfaces returning these types.
3. **No logic in orchestrator** — Only sequencing, timeout handling, and audit trail.
4. **Replaceable mocks** — Change one line in `factory.py` to plug in a real module.
