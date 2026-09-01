"""Mock response recommendation and simulation."""

import logging
from datetime import datetime, timezone

from app.core.errors import NotFoundError
from app.schemas.investigation import InvestigationResult, RiskAssessment
from app.schemas.response import (
    ResponseAction,
    ResponseRecommendation,
    ResponseSimulation,
    SimulationOutcome,
)

logger = logging.getLogger(__name__)


class MockResponseService:
    async def recommend(
        self,
        investigation: InvestigationResult,
        risk: RiskAssessment,
    ) -> ResponseRecommendation:
        actions = [
            ResponseAction(
                action_id="act-001",
                priority=1,
                action_type="isolate_host",
                description="Isolate WORKSTATION-07 from network",
                target="WORKSTATION-07",
                automated=True,
            ),
            ResponseAction(
                action_id="act-002",
                priority=2,
                action_type="reset_credentials",
                description="Force password reset and revoke sessions for admin account",
                target="admin",
                automated=False,
            ),
            ResponseAction(
                action_id="act-003",
                priority=3,
                action_type="block_ip",
                description="Block external IP 203.0.113.45 at perimeter firewall",
                target="203.0.113.45",
                automated=True,
            ),
            ResponseAction(
                action_id="act-004",
                priority=4,
                action_type="quarantine_file",
                description="Snapshot and quarantine accessed file Q1_reports.xlsx for forensic review",
                target="/finance/Q1_reports.xlsx",
                automated=False,
            ),
        ]

        recommendation = ResponseRecommendation(
            incident_id=investigation.incident_id,
            actions=actions,
            rationale=(
                f"Risk level {risk.risk_level.value} ({risk.risk_score}/100) warrants immediate containment "
                "of compromised workstation, credential revocation, and perimeter blocking of attacker IP."
            ),
            requires_human_approval=True,
        )

        logger.info("Mock response recommendation generated for %s", investigation.incident_id)
        return recommendation

    async def simulate(
        self,
        incident_id: str,
        recommendation: ResponseRecommendation,
        action_ids: list[str] | None = None,
    ) -> ResponseSimulation:
        selected = recommendation.actions
        if action_ids:
            selected = [a for a in recommendation.actions if a.action_id in action_ids]
            if not selected:
                raise NotFoundError(
                    "None of the requested action_ids match recommended actions",
                    details={"action_ids": action_ids},
                )

        outcomes: list[SimulationOutcome] = []
        risk_reduction = 0.0
        for action in selected:
            if action.action_type == "isolate_host":
                outcomes.append(
                    SimulationOutcome(
                        action_id=action.action_id,
                        success=True,
                        impact_summary="Lateral movement from WORKSTATION-07 halted",
                        side_effects=["User admin loses active RDP session"],
                    )
                )
                risk_reduction += 25.0
            elif action.action_type == "reset_credentials":
                outcomes.append(
                    SimulationOutcome(
                        action_id=action.action_id,
                        success=True,
                        impact_summary="Attacker session tokens invalidated",
                        side_effects=["Legitimate admin must re-authenticate"],
                    )
                )
                risk_reduction += 30.0
            elif action.action_type == "block_ip":
                outcomes.append(
                    SimulationOutcome(
                        action_id=action.action_id,
                        success=True,
                        impact_summary="External attacker IP blocked at firewall",
                        side_effects=[],
                    )
                )
                risk_reduction += 20.0
            else:
                outcomes.append(
                    SimulationOutcome(
                        action_id=action.action_id,
                        success=True,
                        impact_summary=f"Simulated {action.action_type} on {action.target}",
                        side_effects=["Brief service interruption during quarantine"],
                    )
                )
                risk_reduction += 10.0

        simulation = ResponseSimulation(
            incident_id=incident_id,
            simulated_at=datetime.now(timezone.utc),
            outcomes=outcomes,
            overall_risk_reduction=min(risk_reduction, 85.0),
            notes="Mock simulation — replace with real response engine for production impact modeling.",
        )

        logger.info("Mock simulation completed for %s", incident_id)
        return simulation
