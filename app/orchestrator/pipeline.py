"""Investigation pipeline orchestrator."""

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from app.config import settings
from app.core.errors import AppError, ModuleError
from app.core.validation import validate_model_list, validate_module_output, validate_non_empty_list
from app.factory import ServiceContainer, build_services
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.events import NormalizedEvent
from app.schemas.graph import AttackGraph, IncidentTimeline
from app.schemas.investigation import InvestigationResult, RiskAssessment
from app.schemas.response import IncidentReport, ResponseRecommendation
from app.schemas.api import InvestigateRequest
from app.schemas.enums import IncidentStatus
from app.schemas.response import AuditEvent, FinalIncident
from app.services.incident_store import incident_store

logger = logging.getLogger(__name__)


class InvestigationOrchestrator:
    """
    Coordinates pipeline stages through module interfaces.
    Contains NO detection, correlation, or AI logic — only wiring and validation.
    """

    def __init__(self, services: ServiceContainer | None = None):
        self.services = services or build_services()

    async def _run_stage(self, module_name: str, coro):
        try:
            return await asyncio.wait_for(coro, timeout=settings.module_timeout_seconds)
        except asyncio.TimeoutError as exc:
            from app.core.errors import ModuleTimeoutError

            raise ModuleTimeoutError(module_name, settings.module_timeout_seconds) from exc
        except AppError:
            raise
        except Exception as exc:
            raise ModuleError(module_name, str(exc)) from exc

    async def investigate(self, request: InvestigateRequest) -> FinalIncident:
        audit: list[AuditEvent] = []
        now = datetime.now(timezone.utc)
        state: dict[str, str] = {"incident_id": "pending"}

        def _audit(event_type: str, message: str) -> None:
            audit.append(
                AuditEvent(
                    audit_id=f"aud-{uuid.uuid4().hex[:8]}",
                    incident_id=state["incident_id"],
                    event_type=event_type,
                    actor="orchestrator",
                    message=message,
                    timestamp=datetime.now(timezone.utc),
                )
            )

        raw_logs = None if request.use_sample_logs else request.raw_logs
        _audit("pipeline_start", "Investigation pipeline started")

        # Stage 1: Ingestion / Normalization (KV)
        normalized = validate_model_list(
            "ingestion",
            NormalizedEvent,
            await self._run_stage("ingestion", self.services.ingestion.normalize(raw_logs)),
        )
        _audit("normalization_complete", f"Normalized {len(normalized)} events")

        # Stage 2: Detection (MRUN)
        detections = validate_model_list(
            "detection",
            DetectionResult,
            await self._run_stage("detection", self.services.detection.detect(normalized)),
        )
        _audit("detection_complete", f"Detected {len(detections)} threats")

        # Stage 3: Correlation (MRUN)
        correlated = validate_module_output(
            "correlation",
            CorrelatedIncident,
            await self._run_stage(
                "correlation",
                self.services.correlation.correlate(normalized, detections),
            ),
        )
        incident_id = correlated.incident_id
        state["incident_id"] = incident_id
        _audit("correlation_complete", f"Correlated incident {incident_id}")

        # Stage 4: Attack Graph + Timeline (ROHIT)
        graph, timeline = await self._run_stage(
            "attack_graph",
            self.services.attack_graph.build(correlated),
        )
        graph = validate_module_output("attack_graph", AttackGraph, graph)
        timeline = validate_module_output("attack_graph", IncidentTimeline, timeline)
        validate_non_empty_list("attack_graph", graph.nodes, "graph nodes")
        validate_non_empty_list("attack_graph", timeline.entries, "timeline entries")
        _audit("attack_graph_complete", f"Built graph with {len(graph.nodes)} nodes")

        # Stage 5: Investigation (AI agents)
        investigation = validate_module_output(
            "investigation",
            InvestigationResult,
            await self._run_stage(
                "investigation",
                self.services.investigation.investigate(correlated, graph, timeline),
            ),
        )
        validate_non_empty_list("investigation", investigation.evidence, "evidence items")
        _audit("investigation_complete", "Investigation agents completed analysis")

        # Stage 6: Risk Assessment
        risk = validate_module_output(
            "risk",
            RiskAssessment,
            await self._run_stage("risk", self.services.risk.assess(investigation)),
        )
        _audit("risk_assessment_complete", f"Risk score: {risk.risk_score}")

        # Stage 7: Response Recommendation
        response = validate_module_output(
            "response",
            ResponseRecommendation,
            await self._run_stage(
                "response",
                self.services.response.recommend(investigation, risk),
            ),
        )
        validate_non_empty_list("response", response.actions, "response actions")
        _audit("response_recommendation_complete", f"Recommended {len(response.actions)} actions")

        # Stage 8: Report Generation
        report = validate_module_output(
            "report",
            IncidentReport,
            await self._run_stage(
                "report",
                self.services.report.generate(investigation, risk, response),
            ),
        )
        _audit("report_generated", "Incident report generated")

        final = FinalIncident(
            incident_id=incident_id,
            status=IncidentStatus.AWAITING_APPROVAL,
            title=correlated.title,
            investigation=investigation,
            risk=risk,
            response=response,
            report=report,
            audit_trail=audit,
            created_at=now,
            updated_at=datetime.now(timezone.utc),
        )

        incident_store.save(final)
        logger.info("Pipeline completed for incident %s", incident_id)
        return final
