"""
Risk and Confidence Engine Module

Calculates two distinct, independent, deterministic, and explainable metrics for security incidents:
1. RISK: "How dangerous is this incident if the conclusion is correct?" (0–100, clamped).
2. CONFIDENCE: "How certain are we that our conclusion is correct?" (0–100%, clamped).

Architectural Rule:
Risk and Confidence are strictly independent. Low confidence does not reduce risk,
and high confidence does not inflate risk.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# ==============================================================================
# RISK CONFIGURATION & WEIGHTS
# Formula:
# Risk = 0.25*attack_severity + 0.20*asset_criticality + 0.20*attack_progression
#        + 0.15*blast_radius + 0.10*persistence + 0.10*evidence_strength
# ==============================================================================

WEIGHT_ATTACK_SEVERITY: float = 0.25
WEIGHT_ASSET_CRITICALITY: float = 0.20
WEIGHT_ATTACK_PROGRESSION: float = 0.20
WEIGHT_BLAST_RADIUS: float = 0.15
WEIGHT_PERSISTENCE: float = 0.10
WEIGHT_EVIDENCE_STRENGTH: float = 0.10

DEFAULT_RISK_WEIGHTS: Dict[str, float] = {
    "attack_severity": WEIGHT_ATTACK_SEVERITY,
    "asset_criticality": WEIGHT_ASSET_CRITICALITY,
    "attack_progression": WEIGHT_ATTACK_PROGRESSION,
    "blast_radius": WEIGHT_BLAST_RADIUS,
    "persistence": WEIGHT_PERSISTENCE,
    "evidence_strength": WEIGHT_EVIDENCE_STRENGTH,
}

# ==============================================================================
# CONFIDENCE CONFIGURATION & WEIGHTS
# Formula:
# Confidence = 0.30*evidence_verification + 0.20*source_agreement + 0.20*correlation_strength
#              + 0.15*detection_reliability + 0.10*timeline_consistency + 0.05*context_consistency
# ==============================================================================

WEIGHT_EVIDENCE_VERIFICATION: float = 0.30
WEIGHT_SOURCE_AGREEMENT: float = 0.20
WEIGHT_CORRELATION_STRENGTH: float = 0.20
WEIGHT_DETECTION_RELIABILITY: float = 0.15
WEIGHT_TIMELINE_CONSISTENCY: float = 0.10
WEIGHT_CONTEXT_CONSISTENCY: float = 0.05

DEFAULT_CONFIDENCE_WEIGHTS: Dict[str, float] = {
    "evidence_verification": WEIGHT_EVIDENCE_VERIFICATION,
    "source_agreement": WEIGHT_SOURCE_AGREEMENT,
    "correlation_strength": WEIGHT_CORRELATION_STRENGTH,
    "detection_reliability": WEIGHT_DETECTION_RELIABILITY,
    "timeline_consistency": WEIGHT_TIMELINE_CONSISTENCY,
    "context_consistency": WEIGHT_CONTEXT_CONSISTENCY,
}

# ==============================================================================
# INHERENT RULE SEVERITY & RELIABILITY MAPPINGS
# ==============================================================================

RULE_SEVERITY_MAP: Dict[str, float] = {
    "PRIVILEGE_ESCALATION": 95.0,
    "SENSITIVE_RESOURCE_ACCESS": 90.0,
    "POWERSHELL_EXECUTION": 75.0,
    "SUCCESS_AFTER_FAILED_LOGINS": 65.0,
    "RAPID_MULTI_MACHINE_ACCESS": 65.0,
    "MULTIPLE_FAILED_LOGINS": 50.0,
    "UNKNOWN_OR_SUSPICIOUS_IP": 45.0,
    "UNUSUAL_LOGIN_TIME": 35.0,
}

RULE_RELIABILITY_MAP: Dict[str, float] = {
    "PRIVILEGE_ESCALATION": 95.0,
    "SENSITIVE_RESOURCE_ACCESS": 90.0,
    "POWERSHELL_EXECUTION": 90.0,
    "SUCCESS_AFTER_FAILED_LOGINS": 85.0,
    "RAPID_MULTI_MACHINE_ACCESS": 85.0,
    "MULTIPLE_FAILED_LOGINS": 80.0,
    "UNKNOWN_OR_SUSPICIOUS_IP": 70.0,
    "UNUSUAL_LOGIN_TIME": 65.0,
}

DEFAULT_RULE_SEVERITY: float = 40.0
DEFAULT_RULE_RELIABILITY: float = 70.0


# ==============================================================================
# CLASSIFICATION TIERS
# ==============================================================================

def classify_risk_level(score: float) -> str:
    """
    Maps risk score (0–100) to standardized risk tiers:
      0–19   -> LOW
      20–39  -> MODERATE
      40–59  -> HIGH
      60–79  -> VERY_HIGH
      80–100 -> CRITICAL
    """
    if score >= 80.0:
        return "CRITICAL"
    elif score >= 60.0:
        return "VERY_HIGH"
    elif score >= 40.0:
        return "HIGH"
    elif score >= 20.0:
        return "MODERATE"
    return "LOW"


def classify_confidence_level(score: float) -> str:
    """
    Maps confidence score (0–100) to standardized confidence tiers:
      0–39   -> LOW
      40–69  -> MODERATE
      70–84  -> HIGH
      85–100 -> VERY_HIGH
    """
    if score >= 85.0:
        return "VERY_HIGH"
    elif score >= 70.0:
        return "HIGH"
    elif score >= 40.0:
        return "MODERATE"
    return "LOW"


def clamp_score(value: Any, default: float = 0.0) -> float:
    """
    Safely clamps any numeric or convertible input strictly to the range [0.0, 100.0].
    Returns default if input cannot be parsed.
    """
    if value is None:
        return default
    try:
        val = float(value)
        if val < 0.0:
            return 0.0
        elif val > 100.0:
            return 100.0
        return val
    except (ValueError, TypeError):
        return default


def parse_timestamp(timestamp_str: Any) -> Optional[datetime]:
    """
    Safely parses an ISO timestamp string into a datetime object.
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None
    try:
        return datetime.fromisoformat(timestamp_str.strip())
    except (ValueError, TypeError):
        return None


# ==============================================================================
# ASSET CRITICALITY RESOLUTION
# ==============================================================================

def get_host_criticality(host_name: str) -> float:
    """
    Determines asset criticality based on host naming patterns and roles:
      - Domain Controllers / Auth Infrastructure: 95
      - Database / Backup / Storage Servers: 85
      - App Servers / Jumpboxes: 70
      - Workstations / Endpoints: 35
      - Fallback for unclassified host: 50
    """
    if not host_name or not isinstance(host_name, str):
        return 50.0

    name_upper = host_name.strip().upper()

    # Tier 1: Domain Controller / Identity Infrastructure
    if any(prefix in name_upper for prefix in ("DC-", "DC_", "DOMAIN", "AUTH", "IDP", "KEYCLOAK", "VAULT")):
        return 95.0

    # Tier 2: Database / Critical Data & Backup Servers
    if any(prefix in name_upper for prefix in ("DB", "DATABASE", "SQL", "BACKUP", "STORAGE", "NAS", "SAN")):
        return 85.0

    # Tier 3: Core Application Servers & Administrative Jumpboxes
    if any(prefix in name_upper for prefix in ("SRV-", "SERVER", "JUMPBOX", "BASTION", "APP", "GATEWAY", "PROXY")):
        return 70.0

    # Tier 4: Workstations / User Endpoints
    if any(prefix in name_upper for prefix in ("WKSTN", "WORKSTATION", "LAPTOP", "DESKTOP", "PC", "CLIENT")):
        return 35.0

    # Default fallback
    return 50.0


# ==============================================================================
# RISK FACTOR DERIVATION
# ==============================================================================

def compute_attack_severity(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the inherent severity of the triggered detection rules.
    """
    rules = incident.get("detection_rules") or []
    if not isinstance(rules, (list, set, tuple)) or not rules:
        return 20.0, "No detection rules present (fallback severity 20.0)"

    rule_scores = [RULE_SEVERITY_MAP.get(str(r), DEFAULT_RULE_SEVERITY) for r in rules]
    max_severity = max(rule_scores)

    # Corroboration bonus for multiple high-severity rules
    bonus = min(10.0, (len(rules) - 1) * 2.5) if len(rules) > 1 else 0.0
    total = clamp_score(max_severity + bonus)

    return total, f"Calculated from {len(rules)} rules (max rule severity {max_severity:.1f}, multi-rule bonus +{bonus:.1f})"


def compute_asset_criticality(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the criticality of all hosts affected by the incident.
    """
    hosts = incident.get("affected_hosts") or []
    if not isinstance(hosts, (list, set, tuple)) or not hosts:
        return 50.0, "No host information available (fallback criticality 50.0)"

    host_scores = [get_host_criticality(str(h)) for h in hosts if h]
    if not host_scores:
        return 50.0, "Host list contained no valid names (fallback criticality 50.0)"

    max_crit = max(host_scores)
    # Slight escalation if multiple production hosts targeted
    bonus = min(5.0, (len(host_scores) - 1) * 2.0)
    total = clamp_score(max_crit + bonus)

    return total, f"Calculated across {len(host_scores)} hosts (highest target asset score {max_crit:.1f})"


def compute_attack_progression(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates how far the attack has progressed across kill-chain phases:
      - Initial Access / Recon -> 30-40
      - Access Established -> 55-65
      - Execution & Lateral Movement -> 70-80
      - Privilege Escalation & Sensitive Access -> 85-95
    """
    rules = set(incident.get("detection_rules") or [])
    pattern = str(incident.get("attack_pattern") or "").lower()

    score = 20.0  # Base level

    has_auth_fail = "MULTIPLE_FAILED_LOGINS" in rules or "failed_login" in pattern
    has_auth_success = "SUCCESS_AFTER_FAILED_LOGINS" in rules or "successful_login" in pattern
    has_exec = "POWERSHELL_EXECUTION" in rules or "powershell" in pattern
    has_lateral = "RAPID_MULTI_MACHINE_ACCESS" in rules or "multi_host" in pattern
    has_priv_esc = "PRIVILEGE_ESCALATION" in rules or "privilege" in pattern
    has_sensitive = "SENSITIVE_RESOURCE_ACCESS" in rules or "sensitive" in pattern

    if has_sensitive or has_priv_esc:
        score = 90.0
    elif has_exec or has_lateral:
        score = 75.0
    elif has_auth_success:
        score = 55.0
    elif has_auth_fail:
        score = 35.0

    # Multi-stage progression chaining bonus
    stages_hit = sum([bool(has_auth_fail), bool(has_auth_success), bool(has_priv_esc or has_exec), bool(has_sensitive or has_lateral)])
    if stages_hit >= 3:
        score = min(100.0, score + 8.0)

    total = clamp_score(score)
    return total, f"Kill-chain progression score {total:.1f} based on {stages_hit} sequential stages"


def compute_blast_radius(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the scope of potential lateral and entity impact.
    """
    hosts = incident.get("affected_hosts") or []
    users = incident.get("affected_users") or []

    host_count = len(hosts) if isinstance(hosts, (list, set, tuple)) else 0
    user_count = len(users) if isinstance(users, (list, set, tuple)) else 0

    if host_count >= 4:
        score = 85.0
    elif host_count == 3:
        score = 70.0
    elif host_count == 2:
        score = 55.0
    elif host_count == 1:
        score = 30.0
    else:
        score = 20.0

    # Additional impact for multiple targeted users
    if user_count > 1:
        score = min(100.0, score + (user_count - 1) * 5.0)

    total = clamp_score(score)
    return total, f"Blast radius {total:.1f} across {host_count} hosts and {user_count} users"


def compute_persistence(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates evidence of attacker persistence and dwell/duration capability.
    """
    rules = set(incident.get("detection_rules") or [])
    events = incident.get("event_ids") or []
    event_count = len(events) if isinstance(events, (list, set, tuple)) else 0

    score = 25.0

    if "PRIVILEGE_ESCALATION" in rules:
        score += 45.0
    if "RAPID_MULTI_MACHINE_ACCESS" in rules:
        score += 25.0
    if event_count >= 5:
        score += 15.0
    elif event_count >= 3:
        score += 10.0

    total = clamp_score(score)
    return total, f"Persistence score {total:.1f} (event count: {event_count}, priv_esc: {'PRIVILEGE_ESCALATION' in rules})"


def compute_evidence_strength(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the quantity and diversity of evidence supporting the incident.
    """
    evidence = incident.get("evidence") or []
    events = incident.get("event_ids") or []
    rules = incident.get("detection_rules") or []

    ev_count = len(evidence) if isinstance(evidence, list) else 0
    event_count = len(events) if isinstance(events, (list, set, tuple)) else 0
    rule_count = len(rules) if isinstance(rules, (list, set, tuple)) else 0

    if event_count >= 6 and rule_count >= 3:
        score = 95.0
    elif event_count >= 4 or rule_count >= 2:
        score = 80.0
    elif event_count >= 2:
        score = 60.0
    elif event_count == 1:
        score = 40.0
    else:
        score = 20.0

    total = clamp_score(score)
    return total, f"Evidence strength {total:.1f} from {event_count} events and {ev_count} evidence items"


# ==============================================================================
# CONFIDENCE FACTOR DERIVATION
# ==============================================================================

def compute_evidence_verification(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates whether referenced event IDs and evidence objects are verified.
    """
    event_ids = set(incident.get("event_ids") or [])
    evidence = incident.get("evidence") or []

    if not event_ids:
        return 25.0, "No referenced event IDs (fallback verification 25.0)"

    verified_eids = set()
    if isinstance(evidence, list):
        for item in evidence:
            if isinstance(item, dict) and item.get("event_id"):
                verified_eids.add(str(item.get("event_id")))

    if not verified_eids:
        return 40.0, "No structured evidence records available to verify event IDs"

    ratio = len(verified_eids & event_ids) / max(1, len(event_ids))
    score = 40.0 + (ratio * 55.0)  # Maps 0.0..1.0 -> 40.0..95.0

    total = clamp_score(score)
    return total, f"Evidence verification {total:.1f} (verified {len(verified_eids & event_ids)}/{len(event_ids)} event IDs)"


def compute_source_agreement(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates whether multiple independent detection rules corroborate the activity.
    """
    rules = incident.get("detection_rules") or []
    rule_count = len(set(rules)) if isinstance(rules, (list, set, tuple)) else 0

    if rule_count >= 4:
        score = 95.0
    elif rule_count == 3:
        score = 85.0
    elif rule_count == 2:
        score = 75.0
    elif rule_count == 1:
        score = 55.0
    else:
        score = 20.0

    total = clamp_score(score)
    return total, f"Source agreement {total:.1f} based on {rule_count} distinct corroborating rules"


def compute_correlation_strength(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the consistency of primary entities (user, source IP) within the cluster.
    """
    users = incident.get("affected_users") or []
    ips = incident.get("source_ips") or []

    u_count = len(users) if isinstance(users, (list, set, tuple)) else 0
    ip_count = len(ips) if isinstance(ips, (list, set, tuple)) else 0

    if u_count == 1 and ip_count == 1:
        score = 95.0
    elif u_count == 1 and ip_count > 1:
        score = 80.0
    elif u_count > 1 and ip_count == 1:
        score = 75.0
    elif u_count > 1 and ip_count > 1:
        score = 60.0
    else:
        score = 40.0

    total = clamp_score(score)
    return total, f"Correlation strength {total:.1f} (users: {u_count}, source IPs: {ip_count})"


def compute_detection_reliability(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates the average deterministic reliability/fidelity of the triggered rules.
    """
    rules = incident.get("detection_rules") or []
    if not isinstance(rules, (list, set, tuple)) or not rules:
        return DEFAULT_RULE_RELIABILITY, "No rules specified (fallback reliability 70.0)"

    reliabilities = [RULE_RELIABILITY_MAP.get(str(r), DEFAULT_RULE_RELIABILITY) for r in rules]
    avg_rel = sum(reliabilities) / len(reliabilities)

    total = clamp_score(avg_rel)
    return total, f"Detection reliability {total:.1f} (average across {len(rules)} rules)"


def compute_timeline_consistency(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates chronological order and timestamp validity across timeline events.
    """
    timeline = incident.get("timeline") or []
    if not isinstance(timeline, list) or not timeline:
        return 40.0, "No timeline records available (fallback consistency 40.0)"

    timestamps = []
    for entry in timeline:
        if isinstance(entry, dict):
            ts = parse_timestamp(entry.get("timestamp"))
            if ts is not None:
                timestamps.append(ts)

    if not timestamps:
        return 30.0, "Timeline contained no parseable timestamps"

    # Check chronological ordering
    is_ordered = all(timestamps[i] <= timestamps[i + 1] for i in range(len(timestamps) - 1))
    valid_ratio = len(timestamps) / max(1, len(timeline))

    if is_ordered and valid_ratio >= 0.99:
        score = 95.0
    elif is_ordered:
        score = 80.0
    else:
        score = 65.0

    total = clamp_score(score)
    return total, f"Timeline consistency {total:.1f} ({len(timestamps)}/{len(timeline)} valid timestamps, ordered: {is_ordered})"


def compute_context_consistency(incident: Dict[str, Any]) -> Tuple[float, str]:
    """
    Evaluates whether contextual signals (external IP, off-hours, etc.) corroborate the incident.
    """
    evidence = incident.get("evidence") or []
    rules = set(incident.get("detection_rules") or [])

    has_context_rule = "UNKNOWN_OR_SUSPICIOUS_IP" in rules or "UNUSUAL_LOGIN_TIME" in rules

    if has_context_rule:
        score = 90.0
    elif len(rules) >= 2:
        score = 75.0
    else:
        score = 60.0

    total = clamp_score(score)
    return total, f"Context consistency {total:.1f} (contextual rules present: {has_context_rule})"


# ==============================================================================
# MAIN CALCULATION ENGINES
# ==============================================================================

def calculate_risk(
    incident: Dict[str, Any],
    custom_factors: Optional[Dict[str, Any]] = None,
    custom_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Calculates the deterministic Risk score, level, and individual factors for an incident.

    Formula:
      Risk = 0.25*attack_severity + 0.20*asset_criticality + 0.20*attack_progression
             + 0.15*blast_radius + 0.10*persistence + 0.10*evidence_strength
    """
    weights = dict(DEFAULT_RISK_WEIGHTS)
    if isinstance(custom_weights, dict):
        weights.update({k: float(v) for k, v in custom_weights.items() if k in weights})

    factors: Dict[str, float] = {}
    explanations: Dict[str, str] = {}

    # 1. Attack Severity
    if custom_factors and "attack_severity" in custom_factors:
        val = clamp_score(custom_factors["attack_severity"])
        factors["attack_severity"] = val
        explanations["attack_severity"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_attack_severity(incident)
        factors["attack_severity"] = val
        explanations["attack_severity"] = exp

    # 2. Asset Criticality
    if custom_factors and "asset_criticality" in custom_factors:
        val = clamp_score(custom_factors["asset_criticality"])
        factors["asset_criticality"] = val
        explanations["asset_criticality"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_asset_criticality(incident)
        factors["asset_criticality"] = val
        explanations["asset_criticality"] = exp

    # 3. Attack Progression
    if custom_factors and "attack_progression" in custom_factors:
        val = clamp_score(custom_factors["attack_progression"])
        factors["attack_progression"] = val
        explanations["attack_progression"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_attack_progression(incident)
        factors["attack_progression"] = val
        explanations["attack_progression"] = exp

    # 4. Blast Radius
    if custom_factors and "blast_radius" in custom_factors:
        val = clamp_score(custom_factors["blast_radius"])
        factors["blast_radius"] = val
        explanations["blast_radius"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_blast_radius(incident)
        factors["blast_radius"] = val
        explanations["blast_radius"] = exp

    # 5. Persistence
    if custom_factors and "persistence" in custom_factors:
        val = clamp_score(custom_factors["persistence"])
        factors["persistence"] = val
        explanations["persistence"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_persistence(incident)
        factors["persistence"] = val
        explanations["persistence"] = exp

    # 6. Evidence Strength
    if custom_factors and "evidence_strength" in custom_factors:
        val = clamp_score(custom_factors["evidence_strength"])
        factors["evidence_strength"] = val
        explanations["evidence_strength"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_evidence_strength(incident)
        factors["evidence_strength"] = val
        explanations["evidence_strength"] = exp

    # Weighted Sum
    raw_risk = sum(factors[k] * weights[k] for k in weights if k in factors)
    clamped_risk = clamp_score(raw_risk)
    final_score = int(round(clamped_risk))
    risk_level = classify_risk_level(final_score)

    reasoning = (
        f"Overall risk evaluated as {risk_level} ({final_score}/100). "
        f"Key drivers: severity={factors['attack_severity']:.0f}, asset={factors['asset_criticality']:.0f}, "
        f"progression={factors['attack_progression']:.0f}."
    )

    return {
        "score": final_score,
        "level": risk_level,
        "factors": {k: int(round(v)) for k, v in factors.items()},
        "weights": weights,
        "factor_explanations": explanations,
        "reasoning": reasoning,
    }


def calculate_confidence(
    incident: Dict[str, Any],
    custom_factors: Optional[Dict[str, Any]] = None,
    custom_weights: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Calculates the deterministic Confidence score, level, and individual factors for an incident.

    Formula:
      Confidence = 0.30*evidence_verification + 0.20*source_agreement + 0.20*correlation_strength
                   + 0.15*detection_reliability + 0.10*timeline_consistency + 0.05*context_consistency
    """
    weights = dict(DEFAULT_CONFIDENCE_WEIGHTS)
    if isinstance(custom_weights, dict):
        weights.update({k: float(v) for k, v in custom_weights.items() if k in weights})

    factors: Dict[str, float] = {}
    explanations: Dict[str, str] = {}

    # 1. Evidence Verification
    if custom_factors and "evidence_verification" in custom_factors:
        val = clamp_score(custom_factors["evidence_verification"])
        factors["evidence_verification"] = val
        explanations["evidence_verification"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_evidence_verification(incident)
        factors["evidence_verification"] = val
        explanations["evidence_verification"] = exp

    # 2. Source Agreement
    if custom_factors and "source_agreement" in custom_factors:
        val = clamp_score(custom_factors["source_agreement"])
        factors["source_agreement"] = val
        explanations["source_agreement"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_source_agreement(incident)
        factors["source_agreement"] = val
        explanations["source_agreement"] = exp

    # 3. Correlation Strength
    if custom_factors and "correlation_strength" in custom_factors:
        val = clamp_score(custom_factors["correlation_strength"])
        factors["correlation_strength"] = val
        explanations["correlation_strength"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_correlation_strength(incident)
        factors["correlation_strength"] = val
        explanations["correlation_strength"] = exp

    # 4. Detection Reliability
    if custom_factors and "detection_reliability" in custom_factors:
        val = clamp_score(custom_factors["detection_reliability"])
        factors["detection_reliability"] = val
        explanations["detection_reliability"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_detection_reliability(incident)
        factors["detection_reliability"] = val
        explanations["detection_reliability"] = exp

    # 5. Timeline Consistency
    if custom_factors and "timeline_consistency" in custom_factors:
        val = clamp_score(custom_factors["timeline_consistency"])
        factors["timeline_consistency"] = val
        explanations["timeline_consistency"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_timeline_consistency(incident)
        factors["timeline_consistency"] = val
        explanations["timeline_consistency"] = exp

    # 6. Context Consistency
    if custom_factors and "context_consistency" in custom_factors:
        val = clamp_score(custom_factors["context_consistency"])
        factors["context_consistency"] = val
        explanations["context_consistency"] = f"Explicitly provided: {val}"
    else:
        val, exp = compute_context_consistency(incident)
        factors["context_consistency"] = val
        explanations["context_consistency"] = exp

    # Weighted Sum
    raw_confidence = sum(factors[k] * weights[k] for k in weights if k in factors)
    clamped_confidence = clamp_score(raw_confidence)
    final_score = int(round(clamped_confidence))
    confidence_level = classify_confidence_level(final_score)

    reasoning = (
        f"Overall confidence evaluated as {confidence_level} ({final_score}%). "
        f"Verification={factors['evidence_verification']:.0f}%, source_agreement={factors['source_agreement']:.0f}%, "
        f"correlation={factors['correlation_strength']:.0f}%."
    )

    return {
        "score": final_score,
        "level": confidence_level,
        "percentage": f"{final_score}%",
        "factors": {k: int(round(v)) for k, v in factors.items()},
        "weights": weights,
        "factor_explanations": explanations,
        "reasoning": reasoning,
    }


def calculate_risk_and_confidence(
    incident: Dict[str, Any],
    custom_risk_factors: Optional[Dict[str, Any]] = None,
    custom_confidence_factors: Optional[Dict[str, Any]] = None,
    weights_config: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Main interface to calculate both Risk and Confidence for a given security incident.

    Args:
        incident: Incident dictionary containing entities, detection rules, evidence, timeline, etc.
        custom_risk_factors: Optional overrides for specific risk factors (e.g. for testing).
        custom_confidence_factors: Optional overrides for specific confidence factors.
        weights_config: Optional configuration object containing custom weights.

    Returns:
        Structured dictionary containing independent 'risk' and 'confidence' assessment objects.
    """
    if not isinstance(incident, dict):
        # Graceful defensive return for non-dict inputs
        empty_risk = calculate_risk({}, custom_factors=custom_risk_factors)
        empty_confidence = calculate_confidence({}, custom_factors=custom_confidence_factors)
        return {
            "risk": empty_risk,
            "confidence": empty_confidence,
        }

    risk_weights = getattr(weights_config, "risk_weights", None) if weights_config else None
    confidence_weights = getattr(weights_config, "confidence_weights", None) if weights_config else None

    risk_result = calculate_risk(
        incident,
        custom_factors=custom_risk_factors,
        custom_weights=risk_weights,
    )
    confidence_result = calculate_confidence(
        incident,
        custom_factors=custom_confidence_factors,
        custom_weights=confidence_weights,
    )

    return {
        "risk": risk_result,
        "confidence": confidence_result,
    }


def evaluate_incidents(
    incidents: List[Dict[str, Any]],
    config: Optional[Any] = None,
) -> List[Dict[str, Any]]:
    """
    Enriches a list of correlated incidents with comprehensive Risk and Confidence assessments.
    Updates 'risk_score', 'severity', and adds detailed 'risk' and 'confidence' sub-dictionaries.

    Returns:
        List of enriched incident dictionaries.
    """
    if not isinstance(incidents, list):
        return []

    evaluated: List[Dict[str, Any]] = []

    for inc in incidents:
        if not isinstance(inc, dict):
            continue

        enriched_inc = dict(inc)
        assessment = calculate_risk_and_confidence(enriched_inc, weights_config=config)

        # Attach explainable models
        enriched_inc["risk"] = assessment["risk"]
        enriched_inc["confidence"] = assessment["confidence"]

        # Synchronize root fields for full backward compatibility
        enriched_inc["risk_score"] = assessment["risk"]["score"]
        enriched_inc["severity"] = assessment["risk"]["level"]

        evaluated.append(enriched_inc)

    return evaluated


if __name__ == "__main__":
    sample_incident = {
        "incident_id": "INC-001",
        "threat_type": "Possible Credential Compromise",
        "affected_users": ["admin"],
        "source_ips": ["185.220.101.5"],
        "affected_hosts": ["DC-PROD-01"],
        "event_ids": ["E001", "E002", "E003", "E004", "E005", "E006", "E007"],
        "detection_rules": [
            "MULTIPLE_FAILED_LOGINS",
            "SUCCESS_AFTER_FAILED_LOGINS",
            "PRIVILEGE_ESCALATION",
            "POWERSHELL_EXECUTION",
            "SENSITIVE_RESOURCE_ACCESS",
        ],
        "attack_pattern": "failed_login_burst -> successful_login -> privilege_escalation -> powershell_execution -> sensitive_resource_access",
        "timeline": [
            {"timestamp": "2026-09-01T03:10:00", "event_id": "E001", "description": "Failed login"},
            {"timestamp": "2026-09-01T03:12:15", "event_id": "E004", "description": "Successful login"},
            {"timestamp": "2026-09-01T03:13:00", "event_id": "E005", "description": "Privilege escalation"},
            {"timestamp": "2026-09-01T03:14:10", "event_id": "E006", "description": "PowerShell execution"},
            {"timestamp": "2026-09-01T03:15:30", "event_id": "E007", "description": "Sensitive resource access"},
        ],
        "evidence": [
            {"event_id": "E001", "rule": "MULTIPLE_FAILED_LOGINS", "reason": "Failed login burst"},
            {"event_id": "E004", "rule": "SUCCESS_AFTER_FAILED_LOGINS", "reason": "Login success"},
            {"event_id": "E005", "rule": "PRIVILEGE_ESCALATION", "reason": "Privilege escalation"},
            {"event_id": "E006", "rule": "POWERSHELL_EXECUTION", "reason": "PowerShell execution"},
            {"event_id": "E007", "rule": "SENSITIVE_RESOURCE_ACCESS", "reason": "Sensitive data read"},
        ],
    }

    res = calculate_risk_and_confidence(sample_incident)
    print(json.dumps(res, indent=2))
