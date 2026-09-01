# DARSHAN IMPLEMENTATION PLAN

**Objective:** Enhance the SIH26S01 backend with LLM-driven intelligence while preserving existing architecture, protocols, schemas, and tests.

**Constraint:** No modifications to frozen backend components (orchestrator, interfaces, factories, existing mocks, tests, APIs).

**Approach:** Create new intelligent implementations of existing Protocols that use LLM prompts + structured outputs to replace deterministic mocks.

---

## ANALYSIS: CURRENT ARCHITECTURE

### Existing Frozen Components (DO NOT MODIFY)
- ✅ `app/main.py` — FastAPI app and exception handlers
- ✅ `app/orchestrator/pipeline.py` — 8-stage orchestrator logic
- ✅ `app/interfaces/__init__.py` — All service Protocols
- ✅ `app/schemas/` — All Pydantic models
- ✅ `app/factory.py` — ServiceContainer and build_services()
- ✅ `app/mocks/` — All mock implementations
- ✅ `app/api/` — All route handlers
- ✅ `tests/` — All existing tests
- ✅ `app/core/` — Validation and error handling
- ✅ `app/config.py` — Configuration

### Existing Protocols That Will Be Implemented

| Protocol | File | Stage | Current Mock | New Implementation |
|----------|------|-------|-------|---|
| `InvestigationService` | `app/interfaces/__init__.py` line 68 | Stage 5 | `MockInvestigationService` | **`LLMInvestigationService`** (NEW) |
| `RiskService` | `app/interfaces/__init__.py` line 82 | Stage 6 | `MockRiskService` | **`LLMRiskService`** (NEW) |
| `ResponseService` | `app/interfaces/__init__.py` line 94 | Stage 7 | `MockResponseService` | **`LLMResponseService`** (NEW) |
| `ReportService` | `app/interfaces/__init__.py` line 113 | Stage 8 | `MockReportService` | Keep mock (no LLM needed) |

### Existing Schemas That Will Be Used

#### Investigation Stage Input
```
CorrelatedIncident:
  - incident_id: str
  - title: str
  - summary: str
  - detections: list[DetectionResult]
  - normalized_events: list[NormalizedEvent]
  
AttackGraph:
  - nodes: list[GraphNode]
  - edges: list[GraphEdge]
  - entry_point: str
  
IncidentTimeline:
  - entries: list[TimelineEntry]
  - attack_chain: list[str]  # MITRE technique IDs
```

#### Investigation Stage Output
```
InvestigationResult:
  - incident_id: str
  - summary: str
  - threat_classification: ThreatCategory  # AUTHENTICATION|LATERAL_MOVEMENT|EXECUTION|...
  - severity: Severity  # LOW|MEDIUM|HIGH|CRITICAL
  - evidence: list[Evidence]  # MIN LENGTH: 1
    - evidence_id: str
    - description: str
    - snippet: str
    - confidence: float  # 0.0-1.0
    - supports: str
  - explanation: str  # Evidence-backed reasoning
  - mitre_techniques: list[str]
  - attack_progression: list[str]
  - agents_used: list[str]  # EXISTING FIELD — will populate with agent names
  - timeline: IncidentTimeline | None
  - attack_graph: AttackGraph | None
```

#### Risk Stage Input
```
InvestigationResult:
  (all fields from above)
```

#### Risk Stage Output
```
RiskAssessment:
  - incident_id: str
  - risk_score: float  # 0.0-100.0
  - risk_level: RiskLevel  # LOW|MEDIUM|HIGH|CRITICAL
  - confidence: float  # 0.0-1.0
  - factors: list[str]  # Risk drivers
  - business_impact: str
  - assessed_at: datetime
```

#### Response Stage Input
```
InvestigationResult, RiskAssessment
(from above)
```

#### Response Stage Output
```
ResponseRecommendation:
  - incident_id: str
  - actions: list[ResponseAction]  # MIN LENGTH: 1
    - action_id: str
    - priority: int  # 1-10
    - action_type: str
    - description: str
    - target: str
    - automated: bool
  - rationale: str
  - requires_human_approval: bool
```

---

## FEATURE MAPPING TO EXISTING INFRASTRUCTURE

### Feature 7: Investigator Agent
**Purpose:** Primary agent analyzing raw events and detections to identify threat patterns.

| Aspect | Specification |
|--------|---|
| **Input** | `CorrelatedIncident`, `AttackGraph`, `IncidentTimeline` |
| **Output** | Contributes to `InvestigationResult.evidence` list |
| **Existing Interface** | `InvestigationService.investigate()` → `InvestigationResult` |
| **Implementation** | Part of `LLMInvestigationService` class |
| **LLM Task** | Analyze events + graph + timeline → generate evidence items with confidence scores |
| **Structured Output** | List of `Evidence` objects (Pydantic serializable) |
| **Independence** | Testable via unit tests that mock orchestrator calls |
| **Files to Create** | `app/agents/investigator.py` |
| **Files to Modify** | `app/services/llm_investigation.py` (NEW service wrapper) |

**Schema Constraints:**
- Evidence.confidence must be 0.0-1.0
- Evidence.snippet max ~500 chars (from detection.description)
- Evidence.supports must explain claim it backs
- evidence list must have ≥1 item

**Prompt Strategy:**
```
ROLE: Security investigator analyzing threat evidence
INPUT: Raw events (normalized), detections (threats identified), graph (attack path), timeline (sequence)
TASK: 
  1. Extract key facts from events
  2. Map facts to detections
  3. Identify confidence level for each fact
  4. Generate evidence_id, description, snippet, confidence, supports
OUTPUT: JSON array of Evidence objects
```

---

### Feature 8: Threat Hunter Agent
**Purpose:** Secondary agent focusing on attack pattern recognition and MITRE ATT&CK mapping.

| Aspect | Specification |
|--------|---|
| **Input** | Same as Investigator: `CorrelatedIncident`, `AttackGraph`, `IncidentTimeline` |
| **Output** | Contributes to `InvestigationResult.mitre_techniques` + `attack_progression` |
| **Existing Interface** | `InvestigationService.investigate()` → `InvestigationResult` |
| **Implementation** | Part of `LLMInvestigationService` class |
| **LLM Task** | Analyze graph/timeline → identify MITRE technique sequence → estimate attack stages |
| **Structured Output** | List of MITRE technique IDs (strings like "T1078", "T1570", etc.) |
| **Independence** | Testable via unit tests with mock incident data |
| **Files to Create** | `app/agents/threat_hunter.py` |
| **Files to Modify** | `app/services/llm_investigation.py` |

**Schema Constraints:**
- mitre_techniques: list[str] (IDs only, no duplicates)
- attack_progression: list[str] (stage names like "initial_access", "execution", etc.)

**Prompt Strategy:**
```
ROLE: Threat hunter mapping attack to MITRE ATT&CK framework
INPUT: Attack graph nodes/edges, timeline entries with stages
TASK:
  1. Identify technique for each attack stage
  2. Validate technique against timeline actions
  3. Order techniques chronologically
  4. Map to attack_progression stages
OUTPUT: 
  {
    "mitre_techniques": ["T1078", "T1078.002", "T1021.002", "T1005"],
    "attack_progression": ["initial_access", "execution", "lateral_movement", "collection"]
  }
```

---

### Feature 9: Context Agent
**Purpose:** Enriches investigation with external context (threat intel, asset info, business context).

| Aspect | Specification |
|--------|---|
| **Input** | `CorrelatedIncident`, `AttackGraph` (for target asset names) |
| **Output** | Enriched data added to `Evidence.metadata` or additional factors |
| **Existing Interface** | `InvestigationService.investigate()` → `InvestigationResult` |
| **Implementation** | Part of `LLMInvestigationService` class |
| **LLM Task** | Given asset names + threat types → synthesize business context |
| **Structured Output** | Context strings added to Evidence.supports or Risk.factors |
| **Independence** | Testable with mock asset database lookup |
| **Files to Create** | `app/agents/context_agent.py` + `app/context/asset_db.py` (mock asset lookup) |
| **Files to Modify** | `app/services/llm_investigation.py` |

**Schema Integration:**
- Context data stored in `Evidence` (via supports field) or `RiskAssessment.factors`
- Example: `"Target FILE-SERVER-01 contains financial records and has high business impact"`

**Prompt Strategy:**
```
ROLE: Context enricher providing business/asset intelligence
INPUT: Target assets (from graph nodes), threat type, severity
TASK:
  1. Lookup asset classification (public mock data)
  2. Determine business impact
  3. Assess asset criticality
  4. Generate context statement
OUTPUT: String explaining business relevance and impact
```

---

### Feature 10: Skeptic Agent
**Purpose:** Challenges evidence and confidence scores, provides alternative hypotheses.

| Aspect | Specification |
|--------|---|
| **Input** | `InvestigationResult` (with all evidence) |
| **Output** | Adjusts `Evidence.confidence` or adds skeptic notes to `Evidence.supports` |
| **Existing Interface** | Post-processing within `LLMInvestigationService` |
| **Implementation** | Part of `LLMInvestigationService` class, called AFTER other agents |
| **LLM Task** | Review evidence → identify weak confidence → suggest alternatives |
| **Structured Output** | Updated Evidence objects with modified confidence or alternative_explanation field |
| **Independence** | Testable via unit tests on evidence validation |
| **Files to Create** | `app/agents/skeptic.py` |
| **Files to Modify** | `app/services/llm_investigation.py` (to call skeptic as final step) |

**Schema Constraints:**
- Evidence.confidence may be reduced (0.0-1.0 bounds preserved)
- Alternative hypothesis stored in Evidence.supports or new field if added

**Prompt Strategy:**
```
ROLE: Skeptical security analyst challenging conclusions
INPUT: All evidence items with confidence scores
TASK:
  1. Identify weak evidence (confidence < 0.7)
  2. Challenge each evidence item
  3. Suggest alternative explanations
  4. Reduce confidence if alternatives plausible
  5. Return revised evidence
OUTPUT: JSON array of Evidence with adjusted confidence
```

---

### Feature 11: Evidence Verification
**Purpose:** Formal verification process ensuring evidence quality and chain-of-custody.

| Aspect | Specification |
|--------|---|
| **Input** | `Evidence` list from Investigation agents |
| **Output** | `Evidence` with new fields: `verified: bool`, `verification_timestamp: datetime`, `verification_notes: str` |
| **Existing Interface** | Add fields to `Evidence` schema (REQUIRED SCHEMA CHANGE) |
| **Implementation** | Validation function in `app/core/verification.py` |
| **LLM Task** | NOT LLM-driven; deterministic validation rules |
| **Structured Output** | Updated Evidence objects |
| **Independence** | Testable via unit tests on validation rules |
| **Files to Create** | `app/core/verification.py` |
| **Files to Modify** | `app/schemas/investigation.py` (add verified, verification_timestamp, verification_notes to Evidence) |

**Schema Changes:**
```python
class Evidence(BaseModel):
    evidence_id: str
    event_id: str
    source: str
    description: str
    snippet: str
    confidence: float  # 0.0-1.0 (EXISTING)
    supports: str  # (EXISTING)
    # NEW FIELDS:
    verified: bool = False
    verification_timestamp: datetime | None = None
    verification_notes: str = ""
```

**Verification Rules:**
- Confidence ≥ 0.7 → verified = True
- snippet must be ≤500 chars
- event_id must match incident events
- source must be non-empty

---

### Feature 12: Risk (Enhanced)
**Purpose:** LLM-driven risk scoring with nuanced factors and business impact assessment.

| Aspect | Specification |
|--------|---|
| **Input** | `InvestigationResult` (with investigation agents' output) |
| **Output** | `RiskAssessment` with:
  - risk_score: 0-100
  - risk_level: RiskLevel enum
  - confidence: 0.0-1.0
  - factors: list[str] (LLM-generated explanations)
  - business_impact: str (LLM-generated)
|
| **Existing Interface** | `RiskService.assess()` → `RiskAssessment` |
| **Implementation** | `LLMRiskService` class |
| **LLM Task** | Analyze investigation + severity + threat classification → generate risk score + factors |
| **Structured Output** | Pydantic `RiskAssessment` object |
| **Independence** | Testable via unit tests with mock investigations |
| **Files to Create** | `app/agents/risk_scorer.py` + `app/services/llm_risk.py` |
| **Files to Modify** | `app/factory.py` (to register LLMRiskService) |

**Schema Constraints:**
- risk_score: 0.0-100.0 (float)
- risk_level: RiskLevel (LOW|MEDIUM|HIGH|CRITICAL)
- confidence: 0.0-1.0
- factors: list[str] (3-5 items explaining score)
- business_impact: non-empty string

**Prompt Strategy:**
```
ROLE: Risk assessment specialist
INPUT: 
  - threat_classification (AUTHENTICATION|LATERAL_MOVEMENT|...)
  - severity (LOW|MEDIUM|HIGH|CRITICAL)
  - evidence count + average confidence
  - MITRE techniques (indicates sophistication)
  - attack progression (indicates dwell time)
TASK:
  1. Baseline risk from severity
  2. Adjust for attack sophistication (# MITRE techniques)
  3. Adjust for evidence confidence (low confidence → lower risk)
  4. Generate risk_score (0-100)
  5. Determine risk_level
  6. Generate 3-5 risk factors
  7. Assess business impact
OUTPUT: 
  {
    "risk_score": 78.5,
    "risk_level": "HIGH",
    "confidence": 0.85,
    "factors": [
      "MITRE technique T1078 (credential access) indicates account compromise",
      "Lateral movement (T1021.002) to sensitive asset FILE-SERVER-01",
      "Evidence confidence 0.82 indicates high-confidence findings"
    ],
    "business_impact": "..."
  }
```

---

### Feature 13: Confidence (Explicit Scoring)
**Purpose:** Structured confidence scoring across all evidence and assessments.

| Aspect | Specification |
|--------|---|
| **Input** | Evidence items, risk factors, response actions |
| **Output** | Confidence scores on:
  - Evidence.confidence (EXISTING, 0.0-1.0)
  - RiskAssessment.confidence (EXISTING, 0.0-1.0)
  - ResponseAction.confidence (NEW FIELD)
|
| **Existing Interface** | Used by Investigation, Risk, Response agents |
| **Implementation** | Confidence scoring logic in each agent |
| **LLM Task** | For each evidence/action, generate confidence based on:
  - Source reliability
  - Evidence quality
  - Attack pattern uniqueness
  - Historical accuracy
|
| **Structured Output** | Float 0.0-1.0 for each item |
| **Independence** | Testable via unit tests |
| **Files to Create** | `app/agents/confidence_scorer.py` |
| **Files to Modify** | `app/schemas/response.py` (add confidence to ResponseAction) |

**Schema Changes:**
```python
class ResponseAction(BaseModel):
    action_id: str
    priority: int  # 1-10 (EXISTING)
    action_type: str  # (EXISTING)
    description: str  # (EXISTING)
    target: str  # (EXISTING)
    automated: bool  # (EXISTING)
    # NEW FIELD:
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in action effectiveness")
```

**Confidence Factors:**
- Log source reliability (auth logs > DNS logs)
- Detection algorithm accuracy
- MITRE technique confidence (well-documented vs. novel)
- Attack pattern uniqueness (unique = lower confidence, common = higher)
- Temporal correlation (tightly correlated events = higher)

---

### Feature 16: Response Recommendation (Enhanced)
**Purpose:** LLM-driven response action recommendation with risk/impact trade-offs.

| Aspect | Specification |
|--------|---|
| **Input** | `InvestigationResult`, `RiskAssessment` |
| **Output** | `ResponseRecommendation` with:
  - actions: list[ResponseAction] (≥1)
  - rationale: str (LLM-generated explanation)
  - requires_human_approval: bool
|
| **Existing Interface** | `ResponseService.recommend()` → `ResponseRecommendation` |
| **Implementation** | `LLMResponseService.recommend()` |
| **LLM Task** | Given risk level + threat type → generate 3-5 prioritized response actions |
| **Structured Output** | Pydantic `ResponseRecommendation` |
| **Independence** | Testable via unit tests |
| **Files to Create** | `app/agents/response_recommender.py` + `app/services/llm_response.py` |
| **Files to Modify** | `app/factory.py` (to register LLMResponseService) |

**Schema Constraints:**
- actions list: 1-10 items
- ResponseAction.priority: 1-10 int
- ResponseAction.automated: bool (some actions unsafe to auto-execute)
- rationale: non-empty string

**Prompt Strategy:**
```
ROLE: Incident response coordinator
INPUT:
  - risk_score (0-100)
  - threat_classification
  - target assets (from graph)
  - evidence (what we know)
  - business impact
TASK:
  1. Determine response strategy (containment|remediation|investigation)
  2. Generate 3-5 specific actions
  3. Assign priority (1=immediate, 5=within 24h)
  4. Mark automated-safe actions
  5. Generate rationale
OUTPUT:
  {
    "actions": [
      {
        "action_id": "act-001",
        "priority": 1,
        "action_type": "isolate_host",
        "description": "Isolate compromised workstation from network",
        "target": "WORKSTATION-07",
        "automated": true,
        "confidence": 0.95
      },
      ...
    ],
    "rationale": "..."
  }
```

---

### Feature 17: Response Prioritization (Dynamic)
**Purpose:** Prioritize response actions based on risk + business context + feasibility.

| Aspect | Specification |
|--------|---|
| **Input** | `ResponseRecommendation`, `RiskAssessment` |
| **Output** | Updated `ResponseRecommendation` with re-prioritized actions |
| **Existing Interface** | Post-processing within `LLMResponseService.recommend()` |
| **Implementation** | Prioritization logic in `app/agents/response_prioritizer.py` |
| **LLM Task** | Re-score action priority based on:
  - Risk level (higher risk → higher priority)
  - Automation feasibility
  - Business continuity impact
  - Dependency order (some actions prerequisite to others)
|
| **Structured Output** | ResponseAction.priority updated (1-10) |
| **Independence** | Testable via unit tests on priority logic |
| **Files to Create** | `app/agents/response_prioritizer.py` |
| **Files to Modify** | `app/services/llm_response.py` (to call prioritizer) |

**Priority Factors:**
- Risk level: CRITICAL → 1-3, HIGH → 2-5, MEDIUM → 4-7, LOW → 6-10
- Business impact: HIGH → increase priority
- Automation: Automatable actions may be higher priority (less delay)
- Dependencies: Prerequisite actions raised in priority

---

## LLM INFRASTRUCTURE (TO CREATE)

### New Files Required

#### 1. Configuration for LLM
**File:** `app/config.py` (MODIFY)
```
- Add LLM provider (openai|anthropic|local)
- Add LLM model name
- Add LLM API key (from env)
- Add LLM temperature
- Add prompt template directory
```

#### 2. LLM Client Wrapper
**File:** `app/services/llm_client.py` (NEW)
```
Purpose: Centralized LLM interface
- Abstraction over LLM provider
- Structured output enforcement (Pydantic)
- Error handling
- Retry logic
```

#### 3. Prompt Templates
**Directory:** `app/prompts/` (NEW)
```
- investigator_prompt.txt
- threat_hunter_prompt.txt
- context_agent_prompt.txt
- skeptic_prompt.txt
- risk_scorer_prompt.txt
- response_recommender_prompt.txt
- response_prioritizer_prompt.txt
```

#### 4. Individual Agent Implementations
**Files:** `app/agents/` (NEW DIRECTORY)
```
- investigator.py          → Evidence generation
- threat_hunter.py         → MITRE technique mapping
- context_agent.py         → Business context enrichment
- skeptic.py               → Confidence challenge
- risk_scorer.py           → Risk scoring
- response_recommender.py  → Action recommendation
- response_prioritizer.py  → Priority assignment
```

#### 5. Service Wrappers (Implement Existing Protocols)
**Files:** `app/services/` (NEW)
```
- llm_investigation.py  → Implements InvestigationService protocol
- llm_risk.py          → Implements RiskService protocol
- llm_response.py      → Implements ResponseService protocol
```

#### 6. Context Enrichment
**File:** `app/context/asset_db.py` (NEW)
```
Purpose: Mock asset database for context agent
- Asset classification
- Business impact assessment
```

#### 7. Confidence Scoring
**File:** `app/agents/confidence_scorer.py` (NEW)
```
Purpose: Shared confidence scoring logic
- Evidence confidence rules
- Action confidence rules
- Risk confidence rules
```

#### 8. Evidence Verification
**File:** `app/core/verification.py` (NEW)
```
Purpose: Evidence validation and chain-of-custody
- Verify evidence quality
- Check confidence bounds
- Validate event links
```

---

## SCHEMA MODIFICATIONS (MINIMAL)

### 1. Evidence Schema Enhancement
**File:** `app/schemas/investigation.py`
**Add to Evidence class:**
```python
verified: bool = False
verification_timestamp: datetime | None = None
verification_notes: str = ""
```

### 2. ResponseAction Confidence
**File:** `app/schemas/response.py`
**Add to ResponseAction class:**
```python
confidence: float = Field(..., ge=0.0, le=1.0, 
                          description="Confidence in action effectiveness")
```

### 3. Configuration
**File:** `app/config.py`
**Add Settings fields:**
```python
llm_provider: str = "openai"  # or anthropic, local
llm_model: str = "gpt-4-turbo"
llm_temperature: float = 0.3  # Lower = more deterministic
llm_max_tokens: int = 2000
llm_api_key: str = ""  # From env SIH_LLM_API_KEY
prompt_templates_dir: str = "app/prompts"
```

---

## FACTORY PATTERN (HOW TO INTEGRATE)

### Current Factory (app/factory.py)
```python
class ServiceContainer:
    def __init__(
        self,
        investigation: InvestigationService | None = None,
        risk: RiskService | None = None,
        response: ResponseService | None = None,
        ...
    ):
        self.investigation = investigation or MockInvestigationService()
        self.risk = risk or MockRiskService()
        self.response = response or MockResponseService()
```

### How to Activate LLM Implementations
**Without modifying factory, do this in calling code:**

```python
# In dependency injection or tests:
from app.services.llm_investigation import LLMInvestigationService
from app.services.llm_risk import LLMRiskService
from app.services.llm_response import LLMResponseService

# Use LLM services:
orchestrator = InvestigationOrchestrator(
    services=ServiceContainer(
        investigation=LLMInvestigationService(),  # Instead of Mock
        risk=LLMRiskService(),                    # Instead of Mock
        response=LLMResponseService(),             # Instead of Mock
    )
)
```

**Or via environment variable:**
```python
# Modify app/factory.py build_services() to check:
if settings.use_mock_modules:
    return ServiceContainer()  # All mocks
else:
    return ServiceContainer(
        investigation=LLMInvestigationService(),
        risk=LLMRiskService(),
        response=LLMResponseService(),
    )
```

---

## ORCHESTRATION INTEGRATION

### No Changes to Orchestrator
The existing `app/orchestrator/pipeline.py` requires **ZERO changes**.

Proof:
```python
# Stage 5: Investigation (EXISTING LINE 91-100)
investigation = validate_module_output(
    "investigation",
    InvestigationResult,
    await self._run_stage(
        "investigation",
        self.services.investigation.investigate(correlated, graph, timeline),
    ),
)
```

This works identically with:
- `MockInvestigationService` (current)
- `LLMInvestigationService` (new)

Both satisfy `InvestigationService` Protocol.

Same for RiskService (line 101-105) and ResponseService (line 106-113).

---

## API INTEGRATION

### No Changes to API Routes
The existing `app/api/routes/investigation.py` requires **ZERO changes**.

```python
@router.post("/investigate")
async def investigate(
    request: InvestigateRequest,
    orchestrator: InvestigationOrchestrator = Depends(get_orchestrator),
) -> InvestigateResponse:
    incident = await orchestrator.investigate(request)
    return InvestigateResponse(incident=incident)
```

Works identically with mock or LLM implementations.

---

## TESTING STRATEGY

### Unit Tests (INDEPENDENT FROM ORCHESTRATOR)

Each agent testable in isolation:

```python
# tests/agents/test_investigator.py
async def test_investigator_generates_evidence():
    agent = InvestigatorAgent()
    evidence = await agent.analyze(
        detections=[...],
        events=[...],
        mock_llm=MockLLMClient()
    )
    assert len(evidence) >= 1
    assert all(0.0 <= e.confidence <= 1.0 for e in evidence)

# tests/services/test_llm_investigation.py
async def test_llm_investigation_service():
    service = LLMInvestigationService(mock_llm=MockLLMClient())
    result = await service.investigate(
        incident=...,
        graph=...,
        timeline=...
    )
    assert isinstance(result, InvestigationResult)
    assert result.incident_id == incident.incident_id
```

### Integration Tests (WITH ORCHESTRATOR)

Test full pipeline with LLM:

```python
# tests/test_llm_pipeline.py
async def test_full_pipeline_with_llm():
    orchestrator = InvestigationOrchestrator(
        services=ServiceContainer(
            investigation=LLMInvestigationService(mock_llm=MockLLMClient()),
            risk=LLMRiskService(mock_llm=MockLLMClient()),
            response=LLMResponseService(mock_llm=MockLLMClient()),
        )
    )
    final = await orchestrator.investigate(InvestigateRequest(use_sample_logs=True))
    assert final.incident_id.startswith("INC-")
    assert len(final.investigation.evidence) >= 1
```

### Mock LLM Client for Testing
```python
# tests/mocks/mock_llm_client.py
class MockLLMClient:
    async def invoke(self, prompt: str, output_model: type[T]) -> T:
        # Return deterministic Pydantic object
        # No actual LLM calls in tests
```

---

## FILE STRUCTURE (FINAL)

```
backend/
├── app/
│   ├── agents/                    # NEW DIRECTORY
│   │   ├── __init__.py
│   │   ├── investigator.py        # Investigator Agent
│   │   ├── threat_hunter.py       # Threat Hunter Agent
│   │   ├── context_agent.py       # Context Agent
│   │   ├── skeptic.py             # Skeptic Agent
│   │   ├── confidence_scorer.py   # Confidence scoring
│   │   ├── risk_scorer.py         # Risk assessment logic
│   │   ├── response_recommender.py # Response generation
│   │   └── response_prioritizer.py # Priority assignment
│   ├── context/                   # NEW DIRECTORY
│   │   ├── __init__.py
│   │   └── asset_db.py            # Mock asset database
│   ├── core/
│   │   ├── errors.py              # EXISTING
│   │   ├── validation.py          # EXISTING
│   │   ├── logging.py             # EXISTING
│   │   └── verification.py        # NEW — Evidence verification
│   ├── prompts/                   # NEW DIRECTORY
│   │   ├── investigator_prompt.txt
│   │   ├── threat_hunter_prompt.txt
│   │   ├── context_agent_prompt.txt
│   │   ├── skeptic_prompt.txt
│   │   ├── risk_scorer_prompt.txt
│   │   ├── response_recommender_prompt.txt
│   │   └── response_prioritizer_prompt.txt
│   ├── services/
│   │   ├── incident_store.py      # EXISTING
│   │   ├── llm_client.py          # NEW — LLM wrapper
│   │   ├── llm_investigation.py   # NEW — Implements InvestigationService
│   │   ├── llm_risk.py            # NEW — Implements RiskService
│   │   └── llm_response.py        # NEW — Implements ResponseService
│   ├── config.py                  # MODIFY — Add LLM config
│   ├── factory.py                 # OPTIONALLY MODIFY — To support LLM flag
│   ├── main.py                    # EXISTING
│   ├── orchestrator/
│   │   └── pipeline.py            # EXISTING (NO CHANGES)
│   ├── interfaces/
│   │   └── __init__.py            # EXISTING (NO CHANGES)
│   ├── schemas/
│   │   ├── investigation.py       # MODIFY — Add verification fields to Evidence
│   │   ├── response.py            # MODIFY — Add confidence to ResponseAction
│   │   └── *.py                   # EXISTING (NO CHANGES)
│   ├── mocks/                     # EXISTING (NO CHANGES)
│   ├── api/                       # EXISTING (NO CHANGES)
│   └── ...
├── tests/
│   ├── agents/                    # NEW DIRECTORY
│   │   ├── test_investigator.py
│   │   ├── test_threat_hunter.py
│   │   ├── test_context_agent.py
│   │   ├── test_skeptic.py
│   │   ├── test_risk_scorer.py
│   │   └── test_response_recommender.py
│   ├── services/                  # NEW DIRECTORY
│   │   ├── test_llm_client.py
│   │   ├── test_llm_investigation.py
│   │   ├── test_llm_risk.py
│   │   └── test_llm_response.py
│   ├── mocks/                     # NEW SUBDIRECTORY
│   │   └── mock_llm_client.py
│   ├── conftest.py                # EXISTING (NO CHANGES)
│   ├── test_api.py                # EXISTING (NO CHANGES)
│   ├── test_orchestrator.py       # EXISTING (NO CHANGES)
│   └── ...
├── requirements.txt               # MODIFY — Add LLM dependencies
└── DARSHAN_IMPLEMENTATION_PLAN.md
```

---

## DEPENDENCIES TO ADD

### requirements.txt
```
# Existing
fastapi>=0.115.0
uvicorn[standard]>=0.32.0
pydantic>=2.9.0
pydantic-settings>=2.6.0
httpx>=0.27.0
pytest>=8.3.0
pytest-asyncio>=0.24.0

# NEW — LLM
openai>=1.0.0          # For OpenAI GPT models
anthropic>=0.7.0       # For Claude models (optional)
python-dotenv>=1.0.0   # For .env file loading
```

---

## IMPLEMENTATION SEQUENCE

**Phase 1: LLM Infrastructure**
1. Create `app/services/llm_client.py` — LLM abstraction
2. Update `app/config.py` — Add LLM settings
3. Create prompt templates in `app/prompts/`
4. Add dependencies to requirements.txt

**Phase 2: Agents (Independent)**
5. Create `app/agents/investigator.py` — Evidence generation
6. Create `app/agents/threat_hunter.py` — MITRE mapping
7. Create `app/agents/context_agent.py` — Business context
8. Create `app/agents/skeptic.py` — Confidence challenge
9. Create `app/agents/confidence_scorer.py` — Shared confidence logic
10. Create `app/agents/risk_scorer.py` — Risk scoring
11. Create `app/agents/response_recommender.py` — Response generation
12. Create `app/agents/response_prioritizer.py` — Priority assignment

**Phase 3: Service Implementations**
13. Create `app/services/llm_investigation.py` — Orchestrates agents 5-8
14. Create `app/services/llm_risk.py` — Uses agent 10
15. Create `app/services/llm_response.py` — Uses agents 11-12

**Phase 4: Schema Updates (MINIMAL)**
16. Update `app/schemas/investigation.py` — Add verification fields to Evidence
17. Update `app/schemas/response.py` — Add confidence to ResponseAction
18. Create `app/core/verification.py` — Evidence verification logic

**Phase 5: Supporting Infrastructure**
19. Create `app/context/asset_db.py` — Mock asset database for agent 7

**Phase 6: Integration & Testing**
20. Update `app/factory.py` (optional) — Support LLM flag
21. Update `app/config.py` (final) — Finalize LLM settings
22. Create unit tests in `tests/agents/`
23. Create service tests in `tests/services/`
24. Create mock LLM client in `tests/mocks/`

**Phase 7: Validation**
25. Run existing tests (should all pass — no changes to frozen code)
26. Run new agent tests
27. Run integration tests with LLM services
28. Test with mock LLM client (deterministic)

---

## CONSTRAINTS MAINTAINED

✅ **Frozen Backend Components:**
- Orchestrator logic unchanged
- Protocols unchanged
- Existing mocks unchanged
- API routes unchanged
- Tests unchanged (all should still pass)
- Exception handling unchanged
- Validation logic unchanged

✅ **Backward Compatibility:**
- MockInvestigationService still works
- MockRiskService still works
- MockResponseService still works
- Can switch between mock and LLM via factory
- No hard-coded threat conclusions in frozen code

✅ **Testability:**
- Each agent independently testable
- Mock LLM client for deterministic tests
- No actual LLM calls in CI/CD
- Unit tests + integration tests

---

## SUMMARY

| Feature | Input | Output | Protocol | Files to Create | Schema Changes |
|---------|-------|--------|----------|---|---|
| **7. Investigator Agent** | CorrelatedIncident, AttackGraph, IncidentTimeline | Evidence list | InvestigationService | `agents/investigator.py`, `services/llm_investigation.py` | None |
| **8. Threat Hunter Agent** | CorrelatedIncident, AttackGraph, IncidentTimeline | MITRE techniques + progression | InvestigationService | `agents/threat_hunter.py`, `services/llm_investigation.py` | None |
| **9. Context Agent** | CorrelatedIncident, AttackGraph | Context enrichment | InvestigationService | `agents/context_agent.py`, `context/asset_db.py`, `services/llm_investigation.py` | None |
| **10. Skeptic Agent** | InvestigationResult | Confidence adjustments | InvestigationService | `agents/skeptic.py`, `services/llm_investigation.py` | None |
| **11. Evidence Verification** | Evidence list | Verified evidence | Core validation | `core/verification.py` | Add to Evidence: verified, verification_timestamp, verification_notes |
| **12. Risk (LLM)** | InvestigationResult | RiskAssessment | RiskService | `agents/risk_scorer.py`, `services/llm_risk.py` | None |
| **13. Confidence** | Evidence + actions | Confidence scores | Shared across agents | `agents/confidence_scorer.py` | Add to ResponseAction: confidence |
| **16. Response Recommendation** | InvestigationResult, RiskAssessment | ResponseRecommendation | ResponseService | `agents/response_recommender.py`, `services/llm_response.py` | None |
| **17. Response Prioritization** | ResponseRecommendation | Updated priorities | ResponseService | `agents/response_prioritizer.py`, `services/llm_response.py` | None |

---

## NEXT STEP

Awaiting approval to proceed with Phase 1 implementation (LLM infrastructure setup).

**No code will be written until you confirm this plan.**

---

**END OF DARSHAN_IMPLEMENTATION_PLAN.md**
