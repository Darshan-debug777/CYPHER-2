"""Evidence Verification module for CYPHER.

Provides deterministic validation of AI agent evidence claims against provided
incident events without using an LLM.
"""

from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any

from pydantic import BaseModel, Field

from app.schemas.detection import CorrelatedIncident
from app.schemas.events import NormalizedEvent
from app.schemas.investigation import Evidence

logger = logging.getLogger(__name__)


class VerificationStatus(str, Enum):
    """Status of evidence verification."""

    PASSED = "PASSED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    NO_EVIDENCE = "NO_EVIDENCE"


class EvidenceClaim(BaseModel):
    """An individual evidence claim made by an AI agent."""

    agent_name: str = Field(..., min_length=1, description="Name of the agent making the claim")
    event_id: str = Field(..., min_length=1, description="Event ID referenced by the claim")
    claim_type: str = Field(
        default="supporting",
        description="Type of claim (e.g., supporting, discovered, contradicting, fact, evidence)",
    )
    description: str = Field(default="", description="Description or context of the claim")
    evidence_id: str | None = Field(default=None, description="Optional associated evidence ID")
    confidence: float | None = Field(default=None, ge=0.0, le=1.0, description="Optional confidence score")
    supports: str | None = Field(default=None, description="What hypothesis/conclusion this claim supports")


class VerifiedClaimRecord(BaseModel):
    """Result of verifying a single evidence claim."""

    claim: EvidenceClaim
    is_verified: bool
    reason: str


class VerificationResult(BaseModel):
    """Structured result of evidence verification across all agent claims."""

    incident_id: str | None = None
    total_claims: int = 0
    verified_claims: list[VerifiedClaimRecord] = Field(default_factory=list)
    unverified_claims: list[VerifiedClaimRecord] = Field(default_factory=list)
    verification_status: VerificationStatus = VerificationStatus.NO_EVIDENCE
    verified_event_ids: list[str] = Field(default_factory=list)
    invalid_event_ids: list[str] = Field(default_factory=list)
    agent_breakdown: dict[str, dict[str, Any]] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def verified_count(self) -> int:
        """Return number of verified claims."""
        return len(self.verified_claims)

    @property
    def unverified_count(self) -> int:
        """Return number of unverified claims."""
        return len(self.unverified_claims)

    @property
    def is_fully_verified(self) -> bool:
        """Return True if all claims are verified and there is at least one claim."""
        return self.verification_status == VerificationStatus.PASSED


class EvidenceVerifier:
    """Deterministic verifier for AI agent evidence claims."""

    @classmethod
    def extract_claims(
        cls,
        agent_name: str,
        agent_output: Any,
    ) -> list[EvidenceClaim]:
        """Extract EvidenceClaim instances from an agent's output.

        Supports InvestigatorAnalysis, ThreatHunterAnalysis, Evidence instances/lists,
        dictionaries, strings, or generic objects with event reference attributes.
        """
        claims: list[EvidenceClaim] = []

        if agent_output is None:
            return claims

        # If it's already an EvidenceClaim
        if isinstance(agent_output, EvidenceClaim):
            claims.append(agent_output)
            return claims

        # If it's a raw string event ID
        if isinstance(agent_output, str):
            if agent_output.strip():
                claims.append(
                    EvidenceClaim(
                        agent_name=agent_name,
                        event_id=agent_output.strip(),
                        claim_type="referenced_event",
                    )
                )
            return claims

        # If it's a single Evidence schema object
        if isinstance(agent_output, Evidence):
            claims.append(
                EvidenceClaim(
                    agent_name=agent_name,
                    event_id=agent_output.event_id,
                    evidence_id=agent_output.evidence_id,
                    description=agent_output.description,
                    confidence=agent_output.confidence,
                    supports=agent_output.supports,
                    claim_type="evidence",
                )
            )
            return claims

        # If it's a list of items
        if isinstance(agent_output, list):
            for item in agent_output:
                if isinstance(item, str):
                    if item.strip():
                        claims.append(
                            EvidenceClaim(
                                agent_name=agent_name,
                                event_id=item.strip(),
                                claim_type="referenced_event",
                            )
                        )
                elif isinstance(item, Evidence):
                    claims.append(
                        EvidenceClaim(
                            agent_name=agent_name,
                            event_id=item.event_id,
                            evidence_id=item.evidence_id,
                            description=item.description,
                            confidence=item.confidence,
                            supports=item.supports,
                            claim_type="evidence",
                        )
                    )
                elif isinstance(item, EvidenceClaim):
                    claims.append(item)
                elif isinstance(item, dict):
                    eid = item.get("event_id") or item.get("evidence_id")
                    if eid:
                        claims.append(
                            EvidenceClaim(
                                agent_name=agent_name,
                                event_id=eid,
                                claim_type=item.get("claim_type", "supporting"),
                                description=item.get("description", ""),
                                evidence_id=item.get("evidence_id"),
                                confidence=item.get("confidence"),
                                supports=item.get("supports"),
                            )
                        )
            return claims

        # If it's a dictionary
        if isinstance(agent_output, dict):
            # Check for specific claim lists
            if "supporting_evidence_ids" in agent_output:
                for eid in agent_output.get("supporting_evidence_ids", []):
                    claims.append(
                        EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="supporting")
                    )
            if "discovered_evidence_ids" in agent_output:
                for eid in agent_output.get("discovered_evidence_ids", []):
                    claims.append(
                        EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="discovered")
                    )
            if "contradicting_evidence_ids" in agent_output:
                for eid in agent_output.get("contradicting_evidence_ids", []):
                    claims.append(
                        EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="contradicting")
                    )
            if "evidence" in agent_output and isinstance(agent_output["evidence"], list):
                for item in agent_output["evidence"]:
                    if isinstance(item, Evidence):
                        claims.append(
                            EvidenceClaim(
                                agent_name=agent_name,
                                event_id=item.event_id,
                                evidence_id=item.evidence_id,
                                description=item.description,
                                confidence=item.confidence,
                                supports=item.supports,
                                claim_type="evidence",
                            )
                        )
                    elif isinstance(item, dict) and "event_id" in item:
                        claims.append(
                            EvidenceClaim(
                                agent_name=agent_name,
                                event_id=item["event_id"],
                                evidence_id=item.get("evidence_id"),
                                description=item.get("description", ""),
                                confidence=item.get("confidence"),
                                supports=item.get("supports"),
                                claim_type="evidence",
                            )
                        )
            if "evidence_ids" in agent_output:
                for eid in agent_output.get("evidence_ids", []):
                    claims.append(
                        EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="supporting")
                    )
            if "event_ids" in agent_output:
                for eid in agent_output.get("event_ids", []):
                    claims.append(
                        EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="supporting")
                    )
            return claims

        # If it's a Pydantic model or object with attributes
        # ThreatHunterAnalysis / InvestigatorAnalysis / Generic output
        if hasattr(agent_output, "supporting_evidence_ids") and isinstance(
            agent_output.supporting_evidence_ids, list
        ):
            for eid in agent_output.supporting_evidence_ids:
                claims.append(
                    EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="supporting")
                )

        if hasattr(agent_output, "discovered_evidence_ids") and isinstance(
            agent_output.discovered_evidence_ids, list
        ):
            for eid in agent_output.discovered_evidence_ids:
                claims.append(
                    EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="discovered")
                )

        if hasattr(agent_output, "contradicting_evidence_ids") and isinstance(
            agent_output.contradicting_evidence_ids, list
        ):
            for eid in agent_output.contradicting_evidence_ids:
                claims.append(
                    EvidenceClaim(agent_name=agent_name, event_id=eid, claim_type="contradicting")
                )

        if hasattr(agent_output, "evidence") and isinstance(agent_output.evidence, list):
            for item in agent_output.evidence:
                if isinstance(item, Evidence):
                    claims.append(
                        EvidenceClaim(
                            agent_name=agent_name,
                            event_id=item.event_id,
                            evidence_id=item.evidence_id,
                            description=item.description,
                            confidence=item.confidence,
                            supports=item.supports,
                            claim_type="evidence",
                        )
                    )

        return claims

    @classmethod
    def verify(
        cls,
        events: CorrelatedIncident | list[NormalizedEvent] | set[str] | list[str],
        agent_outputs: Any | dict[str, Any] | list[Any],
        incident_id: str | None = None,
    ) -> VerificationResult:
        """Verify agent evidence claims against provided incident events.

        Args:
            events: CorrelatedIncident, list of NormalizedEvent, or collection of valid event IDs.
            agent_outputs: Single agent output, dict of {agent_name: output}, or list of outputs/claims.
            incident_id: Optional incident ID to associate with result.

        Returns:
            Structured VerificationResult.
        """
        # 1. Resolve valid event IDs
        valid_event_ids: set[str] = set()
        resolved_incident_id = incident_id

        if isinstance(events, CorrelatedIncident):
            resolved_incident_id = resolved_incident_id or events.incident_id
            valid_event_ids = (
                {e.event_id for e in events.normalized_events}
                | {d.event_id for d in events.detections}
                | set(events.related_event_ids)
            )
        elif isinstance(events, (list, set, tuple)):
            for item in events:
                if isinstance(item, NormalizedEvent):
                    valid_event_ids.add(item.event_id)
                elif isinstance(item, str):
                    valid_event_ids.add(item)
                elif hasattr(item, "event_id"):
                    valid_event_ids.add(getattr(item, "event_id"))

        # 2. Collect all claims from agent outputs & pre-register known agent names
        all_claims: list[EvidenceClaim] = []
        agent_stats: dict[str, dict[str, Any]] = {}

        if isinstance(agent_outputs, dict):
            for agent_name, output in agent_outputs.items():
                agent_stats[agent_name] = {
                    "total": 0,
                    "verified": 0,
                    "unverified": 0,
                    "verified_event_ids": [],
                    "invalid_event_ids": [],
                }
                all_claims.extend(cls.extract_claims(agent_name, output))
        elif isinstance(agent_outputs, list):
            for item in agent_outputs:
                if isinstance(item, EvidenceClaim):
                    all_claims.append(item)
                elif isinstance(item, tuple) and len(item) == 2:
                    agent_name, output = item
                    agent_stats[str(agent_name)] = {
                        "total": 0,
                        "verified": 0,
                        "unverified": 0,
                        "verified_event_ids": [],
                        "invalid_event_ids": [],
                    }
                    all_claims.extend(cls.extract_claims(str(agent_name), output))
                elif isinstance(item, str):
                    all_claims.append(EvidenceClaim(agent_name="Agent", event_id=item))
                else:
                    agent_name = getattr(item, "__class__", type(item)).__name__
                    all_claims.extend(cls.extract_claims(agent_name, item))
        elif isinstance(agent_outputs, str):
            all_claims.append(EvidenceClaim(agent_name="Agent", event_id=agent_outputs))
        else:
            agent_name = getattr(agent_outputs, "__class__", type(agent_outputs)).__name__
            all_claims.extend(cls.extract_claims(agent_name, agent_outputs))

        # 3. Perform deterministic verification
        verified_claims: list[VerifiedClaimRecord] = []
        unverified_claims: list[VerifiedClaimRecord] = []
        verified_event_ids_set: set[str] = set()
        invalid_event_ids_set: set[str] = set()

        for claim in all_claims:
            agent_name = claim.agent_name
            if agent_name not in agent_stats:
                agent_stats[agent_name] = {
                    "total": 0,
                    "verified": 0,
                    "unverified": 0,
                    "verified_event_ids": [],
                    "invalid_event_ids": [],
                }

            agent_stats[agent_name]["total"] += 1

            if claim.event_id in valid_event_ids:
                record = VerifiedClaimRecord(
                    claim=claim,
                    is_verified=True,
                    reason=f"Event ID '{claim.event_id}' verified against incident events.",
                )
                verified_claims.append(record)
                verified_event_ids_set.add(claim.event_id)
                agent_stats[agent_name]["verified"] += 1
                if claim.event_id not in agent_stats[agent_name]["verified_event_ids"]:
                    agent_stats[agent_name]["verified_event_ids"].append(claim.event_id)
            else:
                record = VerifiedClaimRecord(
                    claim=claim,
                    is_verified=False,
                    reason=f"Event ID '{claim.event_id}' not found in incident event data.",
                )
                unverified_claims.append(record)
                invalid_event_ids_set.add(claim.event_id)
                agent_stats[agent_name]["unverified"] += 1
                if claim.event_id not in agent_stats[agent_name]["invalid_event_ids"]:
                    agent_stats[agent_name]["invalid_event_ids"].append(claim.event_id)

        # 4. Finalize per-agent status
        for agent_name, stats in agent_stats.items():
            if stats["total"] == 0:
                stats["status"] = VerificationStatus.NO_EVIDENCE.value
            elif stats["unverified"] == 0:
                stats["status"] = VerificationStatus.PASSED.value
            elif stats["verified"] == 0:
                stats["status"] = VerificationStatus.FAILED.value
            else:
                stats["status"] = VerificationStatus.PARTIAL.value

        # 5. Determine overall verification status
        total = len(all_claims)
        if total == 0:
            status = VerificationStatus.NO_EVIDENCE
        elif len(unverified_claims) == 0:
            status = VerificationStatus.PASSED
        elif len(verified_claims) == 0:
            status = VerificationStatus.FAILED
        else:
            status = VerificationStatus.PARTIAL

        return VerificationResult(
            incident_id=resolved_incident_id,
            total_claims=total,
            verified_claims=verified_claims,
            unverified_claims=unverified_claims,
            verification_status=status,
            verified_event_ids=sorted(list(verified_event_ids_set)),
            invalid_event_ids=sorted(list(invalid_event_ids_set)),
            agent_breakdown=agent_stats,
        )

    @classmethod
    def verify_incident(
        cls,
        incident: CorrelatedIncident,
        agent_outputs: dict[str, Any] | list[Any] | Any,
    ) -> VerificationResult:
        """Convenience method to verify agent outputs against a CorrelatedIncident."""
        return cls.verify(
            events=incident,
            agent_outputs=agent_outputs,
            incident_id=incident.incident_id,
        )


def verify_evidence(
    events: CorrelatedIncident | list[NormalizedEvent] | set[str] | list[str],
    agent_outputs: Any | dict[str, Any] | list[Any],
    incident_id: str | None = None,
) -> VerificationResult:
    """Helper function to run evidence verification."""
    return EvidenceVerifier.verify(
        events=events,
        agent_outputs=agent_outputs,
        incident_id=incident_id,
    )
