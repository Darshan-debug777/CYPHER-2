"""
Event Correlation Engine Module

Deterministic correlation engine that aggregates normalized, context-enriched
security events and detection findings into actionable, evidence-backed security incidents.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ==============================================================================
# CONFIGURATION CONSTANTS
# ==============================================================================

# Time window for clustering temporally related detection findings (in seconds)
CORRELATION_WINDOW_SECONDS: int = 1800  # 30 minutes

# Maximum allowable incident risk score
MAX_RISK_SCORE: int = 100


def calculate_severity(score: float) -> str:
    """
    Maps an aggregated incident risk score to a standardized severity level.

    Tiers:
      0–29   -> LOW
      30–59  -> MEDIUM
      60–79  -> HIGH
      80–100 -> CRITICAL
    """
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 30:
        return "MEDIUM"
    return "LOW"


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


def calculate_confidence(
    findings: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> float:
    """
    Calculates a transparent, deterministic confidence score (0.0 to 1.0)
    based on the depth and consistency of supporting evidence.

    Factors:
      - Baseline confidence for verified detection finding: 0.60
      - Multiple corroborating detection rules: +0.08 per extra rule (up to +0.25)
      - Event volume corroboration: +0.05 for >= 3 events, +0.05 for >= 5 events
      - Entity consistency (single user + single source IP): +0.05
      - Contextual anomaly confirmation (unknown IP or off-hours): +0.05
    """
    if not findings:
        return 0.0

    score = 0.60
    distinct_rules = set(f.get("rule", "") for f in findings if f.get("rule"))

    # Multi-rule corroboration
    if len(distinct_rules) > 1:
        score += min(0.25, (len(distinct_rules) - 1) * 0.08)

    # Corroborating event volume
    if len(events) >= 3:
        score += 0.05
    if len(events) >= 5:
        score += 0.05

    # Entity consistency
    users = set(ev.get("user") for ev in events if ev.get("user"))
    ips = set(ev.get("source_ip") for ev in events if ev.get("source_ip"))
    if len(users) <= 1 and len(ips) <= 1:
        score += 0.05

    # Contextual anomaly corroboration
    has_context_anomaly = any(
        ev.get("context", {}).get("known_ip") is False
        or ev.get("context", {}).get("normal_login_time") is False
        for ev in events
        if isinstance(ev.get("context"), dict)
    )
    if has_context_anomaly:
        score += 0.05

    return round(min(1.0, score), 2)


def determine_threat_type(
    findings: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> str:
    """
    Determines a concise, descriptive threat classification dynamically
    based on the combination of triggered rules and observed event behaviors.
    """
    rules = set(f.get("rule", "") for f in findings if f.get("rule"))

    has_auth_failure = "MULTIPLE_FAILED_LOGINS" in rules
    has_auth_success = "SUCCESS_AFTER_FAILED_LOGINS" in rules
    has_priv_esc = "PRIVILEGE_ESCALATION" in rules
    has_powershell = "POWERSHELL_EXECUTION" in rules
    has_sensitive_access = "SENSITIVE_RESOURCE_ACCESS" in rules
    has_lateral = "RAPID_MULTI_MACHINE_ACCESS" in rules

    # Credential Compromise & Post-Exploitation Pattern
    if (has_auth_failure or has_auth_success) and (
        has_priv_esc or has_powershell or has_sensitive_access
    ):
        return "Possible Credential Compromise"

    # Lateral Movement Pattern
    if has_lateral:
        return "Possible Lateral Movement"

    # Standalone Privilege Escalation
    if has_priv_esc:
        return "Privilege Escalation"

    # Authentication Attacks
    if has_auth_failure and has_auth_success:
        return "Credential Access / Password Spraying"
    if has_auth_failure:
        return "Brute Force Authentication"

    # Data Access
    if has_sensitive_access:
        return "Suspicious Sensitive Resource Access"

    # Process Execution
    if has_powershell:
        return "Suspicious Process Execution"

    return "Suspicious Security Incident"


def generate_event_description(event: Dict[str, Any]) -> str:
    """
    Creates a concise human-readable description for an event in the timeline.
    """
    action = str(event.get("action") or "activity")
    event_type = str(event.get("event_type") or "")
    status = str(event.get("status") or "")
    host = str(event.get("host") or "unknown-host")
    user = str(event.get("user") or "unknown-user")
    ip = str(event.get("source_ip") or "unknown-ip")

    if action == "login":
        if status == "failed":
            return f"Failed login attempt on {host} (User: {user}, IP: {ip})"
        return f"Successful login on {host} (User: {user}, IP: {ip})"
    elif action == "logout":
        return f"User {user} logged out from {host}"
    elif action == "escalate_privilege":
        return f"Privilege escalation executed on {host} (User: {user})"
    elif action == "powershell_execution" or "powershell" in action:
        return f"PowerShell command executed on {host} (User: {user})"
    elif action == "read_sensitive_data" or "sensitive" in action:
        return f"Sensitive resource access ({action}) on {host}"
    elif event_type == "remote_access" or action in {"rdp_connect", "ssh_connect", "smb_connect"}:
        return f"Remote access connection ({action}) to {host} from {ip}"
    else:
        return f"{action} ({status}) on {host} by {user}"


def build_attack_pattern(events: List[Dict[str, Any]]) -> str:
    """
    Synthesizes a machine-readable sequential attack pattern from chronologically
    sorted incident events.
    """
    if not events:
        return "unknown"

    pattern_steps: List[str] = []
    consecutive_failed_logins = 0

    for ev in events:
        action = str(ev.get("action") or "").lower()
        event_type = str(ev.get("event_type") or "").lower()
        status = str(ev.get("status") or "").lower()

        if action == "login" and status == "failed":
            consecutive_failed_logins += 1
            continue

        # Flush accumulated failed login burst if transitioning to another action
        if consecutive_failed_logins > 0:
            if consecutive_failed_logins >= 2:
                pattern_steps.append("failed_login_burst")
            else:
                pattern_steps.append("failed_login")
            consecutive_failed_logins = 0

        if action == "login" and status == "success":
            pattern_steps.append("successful_login")
        elif action == "escalate_privilege" or event_type == "privilege" or "privilege" in action:
            pattern_steps.append("privilege_escalation")
        elif action == "powershell_execution" or "powershell" in action:
            pattern_steps.append("powershell_execution")
        elif action == "read_sensitive_data" or "sensitive" in action:
            pattern_steps.append("sensitive_resource_access")
        elif event_type == "remote_access" or action in {"rdp_connect", "ssh_connect", "smb_connect"}:
            if "rapid_multi_host_access" not in pattern_steps:
                pattern_steps.append("rapid_multi_host_access")
        elif action == "logout":
            pattern_steps.append("logout")
        elif action:
            pattern_steps.append(action)

    if consecutive_failed_logins > 0:
        if consecutive_failed_logins >= 2:
            pattern_steps.append("failed_login_burst")
        else:
            pattern_steps.append("failed_login")

    # Remove consecutive identical tags
    deduped_steps: List[str] = []
    for step in pattern_steps:
        if not deduped_steps or deduped_steps[-1] != step:
            deduped_steps.append(step)

    return " -> ".join(deduped_steps) if deduped_steps else "unknown"


# ==============================================================================
# GRAPH / CLUSTERING LOGIC
# ==============================================================================

def cluster_findings(
    findings: List[Dict[str, Any]],
    events_by_id: Dict[str, Dict[str, Any]],
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
) -> List[List[Dict[str, Any]]]:
    """
    Groups related detection findings into incident clusters using entity overlap
    (user, source IP, shared event IDs) and temporal proximity.
    """
    if not findings:
        return []

    n = len(findings)
    parent = list(range(n))

    def find(i: int) -> int:
        if parent[i] == i:
            return i
        parent[i] = find(parent[i])
        return parent[i]

    def union(i: int, j: int) -> None:
        root_i = find(i)
        root_j = find(j)
        if root_i != root_j:
            parent[root_i] = root_j

    # Extract finding metadata for comparison
    finding_meta = []
    for f in findings:
        f_events = [
            events_by_id[eid]
            for eid in f.get("event_ids", [])
            if eid in events_by_id
        ]
        timestamps = [
            parse_timestamp(ev.get("timestamp"))
            for ev in f_events
        ]
        valid_ts = [t for t in timestamps if t is not None]

        min_t = min(valid_ts) if valid_ts else None
        max_t = max(valid_ts) if valid_ts else None

        users = set()
        user_val = str(f.get("user") or "").strip().lower()
        if user_val and user_val != "unknown":
            users.add(user_val)

        for ev in f_events:
            ev_user = str(ev.get("user") or "").strip().lower()
            if ev_user and ev_user != "unknown":
                users.add(ev_user)

        ips = set()
        for ip in f.get("source_ips", []):
            if ip and str(ip).strip():
                ips.add(str(ip).strip())

        for ev in f_events:
            ev_ip = str(ev.get("source_ip") or "").strip()
            if ev_ip:
                ips.add(ev_ip)

        event_ids = set(str(eid) for eid in f.get("event_ids", []) if eid)

        finding_meta.append({
            "min_t": min_t,
            "max_t": max_t,
            "users": users,
            "ips": ips,
            "event_ids": event_ids,
        })

    # Compare all pairs of findings
    for i in range(n):
        for j in range(i + 1, n):
            m_i = finding_meta[i]
            m_j = finding_meta[j]

            # Entity overlap check (only matches if non-empty sets overlap)
            has_user_match = bool(m_i["users"] and m_j["users"] and (m_i["users"] & m_j["users"]))
            has_ip_match = bool(m_i["ips"] and m_j["ips"] and (m_i["ips"] & m_j["ips"]))
            has_event_match = bool(m_i["event_ids"] and m_j["event_ids"] and (m_i["event_ids"] & m_j["event_ids"]))

            entities_related = has_user_match or has_ip_match or has_event_match

            # Temporal proximity check
            time_related = True
            if m_i["min_t"] and m_i["max_t"] and m_j["min_t"] and m_j["max_t"]:
                gap = max(
                    0.0,
                    (m_j["min_t"] - m_i["max_t"]).total_seconds(),
                    (m_i["min_t"] - m_j["max_t"]).total_seconds(),
                )
                time_related = gap <= window_seconds

            if entities_related and time_related:
                union(i, j)

    # Group findings by root representative
    clusters_map: Dict[int, List[Dict[str, Any]]] = {}
    for idx, f in enumerate(findings):
        root = find(idx)
        clusters_map.setdefault(root, []).append(f)

    return list(clusters_map.values())


# ==============================================================================
# MAIN CORRELATION ENGINE ENTRY POINT
# ==============================================================================

def correlate_events(
    enriched_events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    window_seconds: int = CORRELATION_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Correlates enriched security events and detection findings into consolidated security incidents.

    Returns:
        List of structured incident dictionaries, sorted by risk score descending.
    """
    if not isinstance(findings, list) or not findings:
        return []

    events_by_id: Dict[str, Dict[str, Any]] = {}
    if isinstance(enriched_events, list):
        for ev in enriched_events:
            if isinstance(ev, dict) and ev.get("event_id"):
                events_by_id[str(ev.get("event_id"))] = ev

    # Group findings into correlated clusters
    clusters = cluster_findings(findings, events_by_id, window_seconds=window_seconds)

    incidents: List[Dict[str, Any]] = []

    for cluster in clusters:
        # Collect all referenced event IDs from findings
        referenced_event_ids: Set[str] = set()
        detection_rules: Set[str] = set()
        raw_score: int = 0

        for finding in cluster:
            for eid in finding.get("event_ids", []):
                if eid:
                    referenced_event_ids.add(str(eid))
            if finding.get("rule"):
                detection_rules.add(str(finding.get("rule")))
            raw_score += int(finding.get("score", 0))

        # Retrieve matched event objects
        matched_events: List[Dict[str, Any]] = [
            events_by_id[eid]
            for eid in referenced_event_ids
            if eid in events_by_id
        ]

        # Chronologically sort events for timeline & pattern generation
        parsed_events: List[Tuple[datetime, Dict[str, Any]]] = []
        unparsed_events: List[Dict[str, Any]] = []
        for ev in matched_events:
            dt = parse_timestamp(ev.get("timestamp"))
            if dt is not None:
                parsed_events.append((dt, ev))
            else:
                unparsed_events.append(ev)

        parsed_events.sort(key=lambda x: x[0])
        ordered_events = [ev for _, ev in parsed_events] + unparsed_events

        # Extract affected entities
        affected_users: Set[str] = set()
        source_ips: Set[str] = set()
        affected_hosts: Set[str] = set()

        for ev in ordered_events:
            if ev.get("user"):
                affected_users.add(str(ev.get("user")))
            if ev.get("source_ip"):
                source_ips.add(str(ev.get("source_ip")))
            if ev.get("host"):
                affected_hosts.add(str(ev.get("host")))

        # Fallback to finding metadata if event metadata missing
        for f in cluster:
            if f.get("user"):
                affected_users.add(str(f.get("user")))
            for ip in f.get("source_ips", []):
                if ip:
                    source_ips.add(str(ip))
            for h in f.get("hosts", []):
                if h:
                    affected_hosts.add(str(h))

        # Cap risk score at 100
        risk_score = min(MAX_RISK_SCORE, raw_score)
        severity = calculate_severity(risk_score)
        confidence = calculate_confidence(cluster, ordered_events)
        threat_type = determine_threat_type(cluster, ordered_events)

        # Build evidence list referencing actual event IDs
        evidence_list: List[Dict[str, Any]] = []
        seen_evidence: Set[Tuple[str, str]] = set()

        for f in cluster:
            rule_name = str(f.get("rule", ""))
            reason = str(f.get("reason", ""))
            for eid in f.get("event_ids", []):
                key = (str(eid), rule_name)
                if key not in seen_evidence:
                    seen_evidence.add(key)
                    evidence_list.append({
                        "event_id": str(eid),
                        "rule": rule_name,
                        "reason": reason,
                    })

        # Build chronological timeline
        timeline: List[Dict[str, Any]] = []
        for ev in ordered_events:
            timeline.append({
                "timestamp": str(ev.get("timestamp") or ""),
                "event_id": str(ev.get("event_id") or ""),
                "description": generate_event_description(ev),
            })

        # Generate attack pattern string
        attack_pattern = build_attack_pattern(ordered_events)

        incident = {
            "incident_id": "",  # Assigned after sorting
            "threat_type": threat_type,
            "severity": severity,
            "risk_score": risk_score,
            "confidence": confidence,
            "affected_users": sorted(list(affected_users)),
            "source_ips": sorted(list(source_ips)),
            "affected_hosts": sorted(list(affected_hosts)),
            "event_ids": sorted(list(referenced_event_ids)),
            "detection_rules": sorted(list(detection_rules)),
            "evidence": evidence_list,
            "timeline": timeline,
            "attack_pattern": attack_pattern,
        }
        incidents.append(incident)

    # Sort incidents by risk score descending
    incidents.sort(key=lambda inc: inc["risk_score"], reverse=True)

    # Assign sequential incident IDs
    for idx, inc in enumerate(incidents, start=1):
        inc["incident_id"] = f"INC-{idx:03d}"

    return incidents


if __name__ == "__main__":
    import context_engine
    import detection_engine

    mock_file = Path(__file__).parent / "data" / "normalized_events.json"
    if mock_file.exists():
        with open(mock_file, "r", encoding="utf-8") as f:
            raw_events = json.load(f)

        enriched = context_engine.enrich_events(raw_events)
        findings = detection_engine.detect_threats(enriched)
        incidents = correlate_events(enriched, findings)

        print(f"Generated {len(incidents)} Correlated Security Incidents:\n")
        print(json.dumps(incidents, indent=2))

