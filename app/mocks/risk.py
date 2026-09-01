"""Mock risk assessment."""

import logging
from datetime import datetime, timezone

from app.schemas.enums import RiskLevel, Severity
from app.schemas.investigation import InvestigationResult, RiskAssessment

logger = logging.getLogger(__name__)


class MockRiskService:
    async def assess(self, investigation: InvestigationResult) -> RiskAssessment:
        base_score = 65.0
        if investigation.severity == Severity.CRITICAL:
            base_score = 88.0
        elif investigation.severity == Severity.HIGH:
            base_score = 75.0

        evidence_boost = min(len(investigation.evidence) * 2.0, 10.0)
        risk_score = min(base_score + evidence_boost, 100.0)

        if risk_score >= 85:
            level = RiskLevel.CRITICAL
        elif risk_score >= 70:
            level = RiskLevel.HIGH
        elif risk_score >= 45:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        assessment = RiskAssessment(
            incident_id=investigation.incident_id,
            risk_score=round(risk_score, 1),
            risk_level=level,
            confidence=0.87,
            factors=[
                "Multiple MITRE techniques observed in sequence",
                "Access to sensitive financial data confirmed",
                "External IP with unknown geolocation",
                "PowerShell execution post-authentication",
            ],
            business_impact="Potential exposure of confidential financial reports; lateral movement risk to additional hosts.",
            assessed_at=datetime.now(timezone.utc),
        )

        logger.info("Mock risk assessment: score=%.1f level=%s", assessment.risk_score, assessment.risk_level)
        return assessment
