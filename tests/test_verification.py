"""Unit tests for Evidence Verification module.

Tests cover all required verification scenarios:
1. All evidence valid
2. One invalid evidence ID
3. Multiple invalid IDs
4. Agent with no evidence
5. Empty event set
6. Mixed valid/invalid evidence
7. Complete system compatibility
"""

from datetime import datetime, timezone
import pytest

from app.agents.investigator import InvestigatorAnalysis
from app.agents.threat_hunter import ThreatHunterAnalysis
from app.core.verification import (
    EvidenceClaim,
    EvidenceVerifier,
    VerificationResult,
    VerificationStatus,
    VerifiedClaimRecord,
    verify_evidence,
)
from app.schemas.detection import CorrelatedIncident, DetectionResult
from app.schemas.enums import Severity, ThreatCategory
from app.schemas.events import NormalizedEvent
from app.schemas.investigation import Evidence


@pytest.fixture
def sample_incident():
    """Create a sample correlated incident with realistic normalized events."""
    now = datetime(2024, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(
            event_id="EVT-001",
            source="auth_log",
            timestamp=now,
            event_type="failed_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"description": "Failed login attempt"},
            raw_event_id="raw-001",
        ),
        NormalizedEvent(
            event_id="EVT-002",
            source="auth_log",
            timestamp=now,
            event_type="successful_login",
            actor="admin",
            target="server-01",
            severity_hint=Severity.MEDIUM,
            attributes={"description": "Successful login from unusual IP"},
            raw_event_id="raw-002",
        ),
        NormalizedEvent(
            event_id="EVT-003",
            source="process_log",
            timestamp=now,
            event_type="process_start",
            actor="admin",
            target="server-01",
            severity_hint=Severity.HIGH,
            attributes={"description": "Suspicious process started"},
            raw_event_id="raw-003",
        ),
        NormalizedEvent(
            event_id="EVT-004",
            source="network_log",
            timestamp=now,
            event_type="data_transfer",
            actor="server-01",
            target="192.168.1.100",
            severity_hint=Severity.CRITICAL,
            attributes={"description": "Data transfer to external IP"},
            raw_event_id="raw-004",
        ),
    ]

    detections = [
        DetectionResult(
            detection_id="DET-001",
            event_id="EVT-001",
            threat_type="credential_attack",
            category=ThreatCategory.AUTHENTICATION,
            severity=Severity.MEDIUM,
            confidence=0.8,
            indicators=["multiple_failed_attempts"],
            description="Brute force login",
        ),
        DetectionResult(
            detection_id="DET-002",
            event_id="EVT-002",
            threat_type="account_compromise",
            category=ThreatCategory.LATERAL_MOVEMENT,
            severity=Severity.HIGH,
            confidence=0.85,
            indicators=["unusual_ip"],
            description="Compromised login",
        ),
    ]

    return CorrelatedIncident(
        incident_id="INC-2024-001",
        title="Credential Compromise and Data Exfiltration",
        summary="Admin account compromised and data transferred",
        related_event_ids=["EVT-001", "EVT-002", "EVT-003", "EVT-004"],
        detections=detections,
        normalized_events=events,
        first_seen=now,
        last_seen=now,
        primary_category=ThreatCategory.AUTHENTICATION,
        severity=Severity.CRITICAL,
    )


@pytest.fixture
def investigator_output_valid():
    """Valid Investigator analysis with existing events."""
    return InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="Admin account was compromised through credential brute force.",
        summary="Failed logins followed by successful login and command execution.",
        reasoning="EVT-001 shows failed logins, EVT-002 shows successful login.",
        supporting_evidence_ids=["EVT-001", "EVT-002"],
        observed_facts=["Failed login (EVT-001)", "Successful login (EVT-002)"],
        suspected_attack_type="AUTHENTICATION",
        uncertainty="No network logs available.",
        confidence=0.9,
    )


@pytest.fixture
def threat_hunter_output_valid():
    """Valid Threat Hunter analysis with existing events."""
    return ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="Looked for process execution and exfiltration following login.",
        findings="Discovered process start EVT-003 and data transfer EVT-004.",
        discovered_evidence_ids=["EVT-003", "EVT-004"],
        supporting_evidence_ids=["EVT-002"],
        contradicting_evidence_ids=[],
        unexplored_areas=["Check persistence"],
        confidence=0.85,
        uncertainty="Need deeper packet inspection.",
    )


# ============================================================================
# Test 1: All Evidence Valid
# ============================================================================


def test_verification_all_evidence_valid(
    sample_incident,
    investigator_output_valid,
    threat_hunter_output_valid,
):
    """Test 1: All evidence claims reference real events present in the incident."""
    agent_outputs = {
        "Investigator": investigator_output_valid,
        "ThreatHunter": threat_hunter_output_valid,
    }

    result = EvidenceVerifier.verify_incident(sample_incident, agent_outputs)

    assert isinstance(result, VerificationResult)
    assert result.incident_id == "INC-2024-001"
    assert result.verification_status == VerificationStatus.PASSED
    assert result.is_fully_verified is True
    assert result.total_claims == 5  # 2 from investigator, 3 from threat hunter
    assert result.verified_count == 5
    assert result.unverified_count == 0
    assert len(result.invalid_event_ids) == 0
    assert set(result.verified_event_ids) == {"EVT-001", "EVT-002", "EVT-003", "EVT-004"}

    # Verify per-agent breakdown
    assert result.agent_breakdown["Investigator"]["status"] == "PASSED"
    assert result.agent_breakdown["Investigator"]["verified"] == 2
    assert result.agent_breakdown["Investigator"]["unverified"] == 0

    assert result.agent_breakdown["ThreatHunter"]["status"] == "PASSED"
    assert result.agent_breakdown["ThreatHunter"]["verified"] == 3
    assert result.agent_breakdown["ThreatHunter"]["unverified"] == 0


# ============================================================================
# Test 2: One Invalid Evidence ID
# ============================================================================


def test_verification_one_invalid_evidence_id(sample_incident, investigator_output_valid):
    """Test 2: Exactly one invalid/hallucinated evidence ID is detected."""
    # Add one hallucinated claim to investigator output
    investigator_invalid = investigator_output_valid.model_copy(
        update={"supporting_evidence_ids": ["EVT-001", "EVT-002", "EVT-FAKE-999"]}
    )

    result = EvidenceVerifier.verify(
        events=sample_incident,
        agent_outputs={"Investigator": investigator_invalid},
    )

    assert result.verification_status == VerificationStatus.PARTIAL
    assert result.total_claims == 3
    assert result.verified_count == 2
    assert result.unverified_count == 1
    assert result.invalid_event_ids == ["EVT-FAKE-999"]
    assert result.unverified_claims[0].claim.event_id == "EVT-FAKE-999"
    assert result.unverified_claims[0].claim.agent_name == "Investigator"
    assert result.unverified_claims[0].is_verified is False
    assert "not found" in result.unverified_claims[0].reason

    # Single claim that is invalid results in FAILED
    single_invalid = EvidenceClaim(agent_name="Skeptic", event_id="EVT-GHOST-1")
    single_res = EvidenceVerifier.verify(events=sample_incident, agent_outputs=single_invalid)
    assert single_res.verification_status == VerificationStatus.FAILED
    assert single_res.unverified_count == 1


# ============================================================================
# Test 3: Multiple Invalid IDs
# ============================================================================


def test_verification_multiple_invalid_ids(sample_incident):
    """Test 3: Multiple invalid IDs across multiple agents are identified and traced."""
    claims = [
        EvidenceClaim(agent_name="Investigator", event_id="EVT-001"),
        EvidenceClaim(agent_name="Investigator", event_id="EVT-INVALID-101"),
        EvidenceClaim(agent_name="ThreatHunter", event_id="EVT-INVALID-202"),
        EvidenceClaim(agent_name="ThreatHunter", event_id="EVT-INVALID-303"),
        EvidenceClaim(agent_name="ContextAgent", event_id="EVT-INVALID-404"),
    ]

    result = EvidenceVerifier.verify(events=sample_incident, agent_outputs=claims)

    assert result.verification_status == VerificationStatus.PARTIAL
    assert result.total_claims == 5
    assert result.verified_count == 1
    assert result.unverified_count == 4
    assert set(result.invalid_event_ids) == {
        "EVT-INVALID-101",
        "EVT-INVALID-202",
        "EVT-INVALID-303",
        "EVT-INVALID-404",
    }

    # Verify agent tracking is preserved
    unverified_agents = {rec.claim.agent_name for rec in result.unverified_claims}
    assert unverified_agents == {"Investigator", "ThreatHunter", "ContextAgent"}
    assert result.agent_breakdown["Investigator"]["unverified"] == 1
    assert result.agent_breakdown["ThreatHunter"]["unverified"] == 2
    assert result.agent_breakdown["ContextAgent"]["unverified"] == 1
    assert result.agent_breakdown["ContextAgent"]["status"] == "FAILED"


# ============================================================================
# Test 4: Agent With No Evidence
# ============================================================================


def test_verification_agent_with_no_evidence(sample_incident):
    """Test 4: Agents that make no evidence claims are handled gracefully."""
    empty_investigator = InvestigatorAnalysis(
        incident_id="INC-2024-001",
        hypothesis="No hypothesis could be formed.",
        summary="No evidence available.",
        reasoning="Empty evidence.",
        supporting_evidence_ids=[],
        observed_facts=[],
        suspected_attack_type="UNKNOWN",
        uncertainty="Complete uncertainty.",
        confidence=0.1,
    )

    empty_hunter = ThreatHunterAnalysis(
        incident_id="INC-2024-001",
        search_reason="No search.",
        findings="None.",
        discovered_evidence_ids=[],
        supporting_evidence_ids=[],
        contradicting_evidence_ids=[],
        unexplored_areas=[],
        confidence=0.1,
        uncertainty="No data.",
    )

    result = EvidenceVerifier.verify(
        events=sample_incident,
        agent_outputs={
            "Investigator": empty_investigator,
            "ThreatHunter": empty_hunter,
        },
    )

    assert result.total_claims == 0
    assert result.verified_count == 0
    assert result.unverified_count == 0
    assert result.verification_status == VerificationStatus.NO_EVIDENCE
    assert result.is_fully_verified is False
    assert result.agent_breakdown["Investigator"]["total"] == 0
    assert result.agent_breakdown["Investigator"]["status"] == "NO_EVIDENCE"


# ============================================================================
# Test 5: Empty Event Set
# ============================================================================


def test_verification_empty_event_set(investigator_output_valid):
    """Test 5: Valid claims evaluated against an empty incident event set fail verification."""
    empty_events = []

    result = EvidenceVerifier.verify(
        events=empty_events,
        agent_outputs={"Investigator": investigator_output_valid},
        incident_id="INC-EMPTY",
    )

    assert result.incident_id == "INC-EMPTY"
    assert result.total_claims == 2
    assert result.verified_count == 0
    assert result.unverified_count == 2
    assert result.verification_status == VerificationStatus.FAILED
    assert set(result.invalid_event_ids) == {"EVT-001", "EVT-002"}
    assert result.agent_breakdown["Investigator"]["status"] == "FAILED"


# ============================================================================
# Test 6: Mixed Valid / Invalid Evidence
# ============================================================================


def test_verification_mixed_valid_and_invalid(sample_incident):
    """Test 6: Mixed valid and invalid evidence across multiple agent claim types."""
    schema_evidence_valid = Evidence(
        evidence_id="EVD-01",
        event_id="EVT-001",
        source="auth_log",
        description="Failed login attempt",
        snippet="Failed password for admin",
        confidence=0.85,
        supports="Brute force attempt",
    )
    schema_evidence_invalid = Evidence(
        evidence_id="EVD-02",
        event_id="EVT-999-FAKE",
        source="firewall",
        description="Port scan",
        snippet="Drop incoming",
        confidence=0.75,
        supports="Reconnaissance",
    )

    agent_outputs = {
        "Investigator": [schema_evidence_valid, schema_evidence_invalid],
        "ThreatHunter": {
            "discovered_evidence_ids": ["EVT-003"],
            "contradicting_evidence_ids": ["EVT-NONEXISTENT"],
        },
        "Skeptic": [
            EvidenceClaim(agent_name="Skeptic", event_id="EVT-002", claim_type="challenge"),
        ],
    }

    result = verify_evidence(events=sample_incident, agent_outputs=agent_outputs)

    assert result.verification_status == VerificationStatus.PARTIAL
    assert result.total_claims == 5
    assert result.verified_count == 3  # EVT-001, EVT-003, EVT-002
    assert result.unverified_count == 2  # EVT-999-FAKE, EVT-NONEXISTENT
    assert set(result.verified_event_ids) == {"EVT-001", "EVT-002", "EVT-003"}
    assert set(result.invalid_event_ids) == {"EVT-999-FAKE", "EVT-NONEXISTENT"}

    # Verify agent breakdowns
    assert result.agent_breakdown["Investigator"]["verified"] == 1
    assert result.agent_breakdown["Investigator"]["unverified"] == 1
    assert result.agent_breakdown["Investigator"]["status"] == "PARTIAL"

    assert result.agent_breakdown["ThreatHunter"]["verified"] == 1
    assert result.agent_breakdown["ThreatHunter"]["unverified"] == 1
    assert result.agent_breakdown["ThreatHunter"]["status"] == "PARTIAL"

    assert result.agent_breakdown["Skeptic"]["verified"] == 1
    assert result.agent_breakdown["Skeptic"]["unverified"] == 0
    assert result.agent_breakdown["Skeptic"]["status"] == "PASSED"


# ============================================================================
# Additional Tests: Helper Extraction and Schema Resilience
# ============================================================================


def test_verification_raw_event_id_strings(sample_incident):
    """Test verification when events are supplied as a set of raw strings."""
    event_ids = {"EVT-001", "EVT-002"}
    claims = ["EVT-001", "EVT-002", "EVT-003"]

    result = verify_evidence(events=event_ids, agent_outputs=claims)

    assert result.total_claims == 3
    assert result.verified_count == 2
    assert result.unverified_count == 1
    assert result.invalid_event_ids == ["EVT-003"]


def test_verification_extract_claims_from_dict_and_models():
    """Test claim extraction from various custom and dictionary payloads."""
    dict_payload = {
        "supporting_evidence_ids": ["EVT-1"],
        "discovered_evidence_ids": ["EVT-2"],
        "contradicting_evidence_ids": ["EVT-3"],
        "evidence_ids": ["EVT-4"],
        "event_ids": ["EVT-5"],
    }

    claims = EvidenceVerifier.extract_claims("CustomAgent", dict_payload)
    assert len(claims) == 5
    assert all(c.agent_name == "CustomAgent" for c in claims)
    assert {c.event_id for c in claims} == {"EVT-1", "EVT-2", "EVT-3", "EVT-4", "EVT-5"}


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
