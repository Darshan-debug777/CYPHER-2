"""
Threat Detection Engine Module

Deterministic rule-based detection engine analyzing normalized and context-enriched
security events to produce structured, evidence-backed detection findings.
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import context_engine

# ==============================================================================
# DETECTION RULE SCORES
# Starting weights for each independent detection rule
# ==============================================================================

SCORE_MULTIPLE_FAILED_LOGINS: int = 25
SCORE_SUCCESS_AFTER_FAILED_LOGINS: int = 20
SCORE_UNKNOWN_IP: int = 20
SCORE_UNUSUAL_LOGIN_TIME: int = 15
SCORE_POWERSHELL_EXECUTION: int = 20
SCORE_RAPID_MULTI_MACHINE: int = 20
SCORE_SENSITIVE_RESOURCE_ACCESS: int = 20
SCORE_PRIVILEGE_ESCALATION: int = 25

# ==============================================================================
# RULE NAMES & IDENTIFIERS
# ==============================================================================

RULE_MULTIPLE_FAILED_LOGINS: str = "MULTIPLE_FAILED_LOGINS"
RULE_SUCCESS_AFTER_FAILED_LOGINS: str = "SUCCESS_AFTER_FAILED_LOGINS"
RULE_UNKNOWN_IP: str = "UNKNOWN_OR_SUSPICIOUS_IP"
RULE_UNUSUAL_LOGIN_TIME: str = "UNUSUAL_LOGIN_TIME"
RULE_POWERSHELL_EXECUTION: str = "POWERSHELL_EXECUTION"
RULE_RAPID_MULTI_MACHINE: str = "RAPID_MULTI_MACHINE_ACCESS"
RULE_SENSITIVE_RESOURCE_ACCESS: str = "SENSITIVE_RESOURCE_ACCESS"
RULE_PRIVILEGE_ESCALATION: str = "PRIVILEGE_ESCALATION"

# ==============================================================================
# CONFIGURABLE TEMPORAL THRESHOLDS
# ==============================================================================

FAILED_LOGIN_WINDOW_SECONDS: int = 300       # 5 minutes
FAILED_LOGIN_THRESHOLD: int = 3             # minimum 3 failed attempts
SUCCESS_AFTER_FAILURES_WINDOW_SECONDS: int = 300  # 5 minutes
SUCCESS_AFTER_FAILURES_MIN_FAILS: int = 2   # minimum 2 prior failures
MULTI_HOST_WINDOW_SECONDS: int = 300        # 5 minutes
MULTI_HOST_THRESHOLD: int = 3               # minimum 3 distinct hosts


def calculate_severity(score: float) -> str:
    """
    Converts a numerical detection score into a standardized severity tier.

    Tiers:
      0–29  -> LOW
      30–59 -> MEDIUM
      60–79 -> HIGH
      80+   -> CRITICAL
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
    Returns None if parsing fails.
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return None
    try:
        return datetime.fromisoformat(timestamp_str.strip())
    except (ValueError, TypeError):
        return None


def create_finding(
    detection_id: str,
    rule: str,
    score: int,
    event_ids: List[str],
    user: str,
    source_ips: List[str],
    hosts: List[str],
    reason: str,
) -> Dict[str, Any]:
    """
    Constructs a structured detection finding dictionary.
    """
    return {
        "detection_id": detection_id,
        "rule": rule,
        "severity": calculate_severity(score),
        "score": score,
        "event_ids": sorted(list(set(str(eid) for eid in event_ids if eid))),
        "user": user or "unknown",
        "source_ips": sorted(list(set(str(ip) for ip in source_ips if ip))),
        "hosts": sorted(list(set(str(h) for h in hosts if h))),
        "reason": reason,
    }


# ==============================================================================
# INDIVIDUAL DETECTION RULES
# ==============================================================================

def detect_multiple_failed_logins(
    events: List[Dict[str, Any]],
    threshold: int = FAILED_LOGIN_THRESHOLD,
    window_seconds: int = FAILED_LOGIN_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Rule 1: Detects repeated failed authentication attempts for the same user/IP
    within a configurable time window.
    """
    findings: List[Dict[str, Any]] = []

    # Group failed authentication events by (user, source_ip)
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        if (
            str(event.get("event_type") or "").lower() == "authentication"
            and str(event.get("action") or "").lower() == "login"
            and str(event.get("status") or "").lower() == "failed"
        ):
            key = (str(event.get("user") or ""), str(event.get("source_ip") or ""))
            grouped.setdefault(key, []).append(event)

    for (user, source_ip), user_events in grouped.items():
        # Sort chronologically
        parsed_events = []
        for ev in user_events:
            dt = parse_timestamp(ev.get("timestamp"))
            if dt is not None:
                parsed_events.append((dt, ev))
        parsed_events.sort(key=lambda x: x[0])

        if len(parsed_events) < threshold:
            continue

        # Sliding window over failed attempts
        matched_event_ids: Set[str] = set()
        matched_hosts: Set[str] = set()

        for i in range(len(parsed_events)):
            window_group = [parsed_events[i]]
            for j in range(i + 1, len(parsed_events)):
                delta = (parsed_events[j][0] - parsed_events[i][0]).total_seconds()
                if 0 <= delta <= window_seconds:
                    window_group.append(parsed_events[j])

            if len(window_group) >= threshold:
                for _, ev in window_group:
                    eid = ev.get("event_id")
                    if eid:
                        matched_event_ids.add(str(eid))
                    if ev.get("host"):
                        matched_hosts.add(str(ev.get("host")))

        if matched_event_ids:
            findings.append(
                create_finding(
                    detection_id="",
                    rule=RULE_MULTIPLE_FAILED_LOGINS,
                    score=SCORE_MULTIPLE_FAILED_LOGINS,
                    event_ids=list(matched_event_ids),
                    user=user,
                    source_ips=[source_ip] if source_ip else [],
                    hosts=list(matched_hosts),
                    reason=(
                        f"Detected {len(matched_event_ids)} failed login attempts for user '{user}' "
                        f"from source IP {source_ip or 'unknown'} within {window_seconds}s window."
                    ),
                )
            )

    return findings


def detect_successful_login_after_failures(
    events: List[Dict[str, Any]],
    min_failures: int = SUCCESS_AFTER_FAILURES_MIN_FAILS,
    window_seconds: int = SUCCESS_AFTER_FAILURES_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Rule 2: Detects a successful login that occurs shortly after multiple failed logins
    for the same user and source IP.
    """
    findings: List[Dict[str, Any]] = []

    # Group authentication events by (user, source_ip)
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        if (
            str(event.get("event_type") or "").lower() == "authentication"
            and str(event.get("action") or "").lower() == "login"
        ):
            key = (str(event.get("user") or ""), str(event.get("source_ip") or ""))
            grouped.setdefault(key, []).append(event)

    for (user, source_ip), user_events in grouped.items():
        parsed_events = []
        for ev in user_events:
            dt = parse_timestamp(ev.get("timestamp"))
            if dt is not None:
                parsed_events.append((dt, ev))
        parsed_events.sort(key=lambda x: x[0])

        for idx, (success_dt, success_event) in enumerate(parsed_events):
            if str(success_event.get("status") or "").lower() == "success":
                prior_failures = [
                    (f_dt, f_ev)
                    for f_dt, f_ev in parsed_events[:idx]
                    if str(f_ev.get("status") or "").lower() == "failed"
                    and 0 <= (success_dt - f_dt).total_seconds() <= window_seconds
                ]

                if len(prior_failures) >= min_failures:
                    ev_ids = [str(f_ev.get("event_id")) for _, f_ev in prior_failures if f_ev.get("event_id")]
                    if success_event.get("event_id"):
                        ev_ids.append(str(success_event.get("event_id")))
                    hosts = [str(f_ev.get("host")) for _, f_ev in prior_failures if f_ev.get("host")]
                    if success_event.get("host"):
                        hosts.append(str(success_event.get("host")))

                    findings.append(
                        create_finding(
                            detection_id="",
                            rule=RULE_SUCCESS_AFTER_FAILED_LOGINS,
                            score=SCORE_SUCCESS_AFTER_FAILED_LOGINS,
                            event_ids=ev_ids,
                            user=user,
                            source_ips=[source_ip] if source_ip else [],
                            hosts=hosts,
                            reason=(
                                f"Successful login for user '{user}' from {source_ip or 'unknown'} "
                                f"after {len(prior_failures)} failed login attempts within {window_seconds}s."
                            ),
                        )
                    )

    return findings


def detect_unknown_ip(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule 3: Detects security events originating from unfamiliar or external IP addresses
    using Context Engine metadata or direct context baseline evaluation.
    """
    findings: List[Dict[str, Any]] = []

    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue

        source_ip = event.get("source_ip")
        if not source_ip:
            continue

        ctx = event.get("context")
        if isinstance(ctx, dict):
            known_ip = ctx.get("known_ip", True)
            flags = ctx.get("context_flags", [])
            is_suspicious = (not known_ip) or ("UNKNOWN_IP" in flags)
        else:
            # Fallback to Context Engine evaluation if context not attached
            is_suspicious = not context_engine.is_known_ip(str(source_ip))

        if is_suspicious:
            key = (str(event.get("user") or ""), str(source_ip))
            grouped.setdefault(key, []).append(event)

    for (user, source_ip), matched_events in grouped.items():
        event_ids = [str(ev.get("event_id")) for ev in matched_events if ev.get("event_id")]
        hosts = [str(ev.get("host")) for ev in matched_events if ev.get("host")]

        findings.append(
            create_finding(
                detection_id="",
                rule=RULE_UNKNOWN_IP,
                score=SCORE_UNKNOWN_IP,
                event_ids=event_ids,
                user=user,
                source_ips=[source_ip],
                hosts=hosts,
                reason=(
                    f"Activity observed from unknown / external source IP {source_ip} "
                    f"associated with user '{user or 'unknown'}' across {len(event_ids)} events."
                ),
            )
        )

    return findings


def detect_unusual_login_time(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule 4: Detects authentication login attempts occurring outside normal business hours
    using Context Engine metadata or direct context baseline evaluation.
    """
    findings: List[Dict[str, Any]] = []

    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue

        event_type = str(event.get("event_type") or "").lower()
        action = str(event.get("action") or "").lower()

        if event_type == "authentication" and action == "login":
            ctx = event.get("context")
            if isinstance(ctx, dict):
                normal_time = ctx.get("normal_login_time", True)
                flags = ctx.get("context_flags", [])
                is_unusual = (not normal_time) or ("UNUSUAL_LOGIN_TIME" in flags)
            else:
                # Fallback to Context Engine evaluation if context not attached
                normal_time, _ = context_engine.is_normal_login_time(event.get("timestamp"))
                is_unusual = not normal_time

            if is_unusual:
                key = (str(event.get("user") or ""), str(event.get("source_ip") or ""))
                grouped.setdefault(key, []).append(event)

    for (user, source_ip), matched_events in grouped.items():
        event_ids = [str(ev.get("event_id")) for ev in matched_events if ev.get("event_id")]
        hosts = [str(ev.get("host")) for ev in matched_events if ev.get("host")]

        findings.append(
            create_finding(
                detection_id="",
                rule=RULE_UNUSUAL_LOGIN_TIME,
                score=SCORE_UNUSUAL_LOGIN_TIME,
                event_ids=event_ids,
                user=user,
                source_ips=[source_ip] if source_ip else [],
                hosts=hosts,
                reason=(
                    f"Authentication login activity for user '{user or 'unknown'}' from {source_ip or 'unknown'} "
                    f"occurred outside normal operating hours ({len(event_ids)} attempts)."
                ),
            )
        )

    return findings


def detect_powershell_execution(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule 5: Detects PowerShell process execution events.
    """
    findings: List[Dict[str, Any]] = []

    for event in events:
        if not isinstance(event, dict):
            continue

        action = str(event.get("action") or "").lower()
        event_type = str(event.get("event_type") or "").lower()

        if action == "powershell_execution" or "powershell" in action or (
            event_type == "process" and "powershell" in action
        ):
            ev_id = str(event.get("event_id") or "")
            user = str(event.get("user") or "")
            source_ip = str(event.get("source_ip") or "")
            host = str(event.get("host") or "")

            findings.append(
                create_finding(
                    detection_id="",
                    rule=RULE_POWERSHELL_EXECUTION,
                    score=SCORE_POWERSHELL_EXECUTION,
                    event_ids=[ev_id] if ev_id else [],
                    user=user,
                    source_ips=[source_ip] if source_ip else [],
                    hosts=[host] if host else [],
                    reason=(
                        f"PowerShell execution detected on host '{host or 'unknown'}' "
                        f"by user '{user or 'unknown'}' (Event ID: {ev_id or 'N/A'})."
                    ),
                )
            )

    return findings


def detect_rapid_multi_machine_access(
    events: List[Dict[str, Any]],
    min_hosts: int = MULTI_HOST_THRESHOLD,
    window_seconds: int = MULTI_HOST_WINDOW_SECONDS,
) -> List[Dict[str, Any]]:
    """
    Rule 6: Detects a user rapidly connecting to multiple distinct hosts within a short time window.
    """
    findings: List[Dict[str, Any]] = []

    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue

        event_type = str(event.get("event_type") or "").lower()
        action = str(event.get("action") or "").lower()
        if (
            event_type in {"remote_access", "authentication"}
            or action in {"rdp_connect", "ssh_connect", "smb_connect", "login"}
        ):
            key = (str(event.get("user") or ""), str(event.get("source_ip") or ""))
            grouped.setdefault(key, []).append(event)

    for (user, source_ip), user_events in grouped.items():
        parsed_events = []
        for ev in user_events:
            dt = parse_timestamp(ev.get("timestamp"))
            if dt is not None:
                parsed_events.append((dt, ev))
        parsed_events.sort(key=lambda x: x[0])

        for i in range(len(parsed_events)):
            window_group = [parsed_events[i]]
            for j in range(i + 1, len(parsed_events)):
                delta = (parsed_events[j][0] - parsed_events[i][0]).total_seconds()
                if 0 <= delta <= window_seconds:
                    window_group.append(parsed_events[j])

            distinct_hosts = set(
                str(ev.get("host")) for _, ev in window_group if ev.get("host")
            )

            if len(distinct_hosts) >= min_hosts:
                ev_ids = [str(ev.get("event_id")) for _, ev in window_group if ev.get("event_id")]
                findings.append(
                    create_finding(
                        detection_id="",
                        rule=RULE_RAPID_MULTI_MACHINE,
                        score=SCORE_RAPID_MULTI_MACHINE,
                        event_ids=ev_ids,
                        user=user,
                        source_ips=[source_ip] if source_ip else [],
                        hosts=list(distinct_hosts),
                        reason=(
                            f"User '{user or 'unknown'}' from {source_ip or 'unknown'} accessed {len(distinct_hosts)} distinct hosts "
                            f"({', '.join(sorted(distinct_hosts))}) within {window_seconds}s window."
                        ),
                    )
                )
                break  # Record one consolidated finding per sliding cluster

    return findings


def detect_sensitive_resource_access(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule 7: Detects access to critical or sensitive files/resources.
    """
    findings: List[Dict[str, Any]] = []

    for event in events:
        if not isinstance(event, dict):
            continue

        action = str(event.get("action") or "").lower()
        if (
            action == "read_sensitive_data"
            or "sensitive" in action
            or action in {"access_sensitive_file", "export_database", "dump_credentials"}
        ):
            ev_id = str(event.get("event_id") or "")
            user = str(event.get("user") or "")
            source_ip = str(event.get("source_ip") or "")
            host = str(event.get("host") or "")

            findings.append(
                create_finding(
                    detection_id="",
                    rule=RULE_SENSITIVE_RESOURCE_ACCESS,
                    score=SCORE_SENSITIVE_RESOURCE_ACCESS,
                    event_ids=[ev_id] if ev_id else [],
                    user=user,
                    source_ips=[source_ip] if source_ip else [],
                    hosts=[host] if host else [],
                    reason=(
                        f"Sensitive resource access '{event.get('action')}' detected on host '{host or 'unknown'}' "
                        f"by user '{user or 'unknown'}' (Event ID: {ev_id or 'N/A'})."
                    ),
                )
            )

    return findings


def detect_privilege_escalation(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule 8: Detects privilege escalation attempts and successes.
    """
    findings: List[Dict[str, Any]] = []

    for event in events:
        if not isinstance(event, dict):
            continue

        action = str(event.get("action") or "").lower()
        event_type = str(event.get("event_type") or "").lower()

        if (
            action in {"escalate_privilege", "privilege_escalation"}
            or event_type == "privilege"
            or ("privilege" in action and "read" not in action)
        ):
            ev_id = str(event.get("event_id") or "")
            user = str(event.get("user") or "")
            source_ip = str(event.get("source_ip") or "")
            host = str(event.get("host") or "")

            findings.append(
                create_finding(
                    detection_id="",
                    rule=RULE_PRIVILEGE_ESCALATION,
                    score=SCORE_PRIVILEGE_ESCALATION,
                    event_ids=[ev_id] if ev_id else [],
                    user=user,
                    source_ips=[source_ip] if source_ip else [],
                    hosts=[host] if host else [],
                    reason=(
                        f"Privilege escalation event detected on host '{host or 'unknown'}' "
                        f"by user '{user or 'unknown'}' (Event ID: {ev_id or 'N/A'})."
                    ),
                )
            )

    return findings


# ==============================================================================
# MAIN DETECTION ENGINE RUNNER
# ==============================================================================

def detect_threats(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Executes all detection rules across normalized and enriched security events.
    Assigns unique detection IDs and returns structured findings.
    """
    if not isinstance(events, list) or not events:
        return []

    all_findings: List[Dict[str, Any]] = []

    # Execute all 8 detection rules independently
    all_findings.extend(detect_multiple_failed_logins(events))
    all_findings.extend(detect_successful_login_after_failures(events))
    all_findings.extend(detect_unknown_ip(events))
    all_findings.extend(detect_unusual_login_time(events))
    all_findings.extend(detect_powershell_execution(events))
    all_findings.extend(detect_rapid_multi_machine_access(events))
    all_findings.extend(detect_sensitive_resource_access(events))
    all_findings.extend(detect_privilege_escalation(events))

    # Assign sequential detection IDs
    for idx, finding in enumerate(all_findings, start=1):
        finding["detection_id"] = f"DET-{idx:03d}"

    return all_findings


if __name__ == "__main__":
    mock_file = Path(__file__).parent / "data" / "normalized_events.json"
    if mock_file.exists():
        with open(mock_file, "r", encoding="utf-8") as f:
            raw_events = json.load(f)

        enriched = context_engine.enrich_events(raw_events)
        findings = detect_threats(enriched)

        print(f"Generated {len(findings)} detection findings:\n")
        for f_item in findings:
            print(json.dumps(f_item, indent=2))

