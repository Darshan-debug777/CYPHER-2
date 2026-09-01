"""
Context Engine Module

Enriches normalized security events with contextual signals:
- IP address familiarity (internal vs. external/unknown)
- Working hour activity (business hours vs. unusual login times)
- Host familiarity (known enterprise assets vs. unknown hosts)

Calculates a deterministic context score and sets descriptive context flags.
Supports dynamic loading of external organizational baselines via SecurityConfig.
"""

from datetime import datetime
import ipaddress
import json
from pathlib import Path
from typing import Any, Collection, Dict, List, Optional, Set, Tuple

from config_loader import SecurityConfig, get_default_config, load_config

# ==============================================================================
# BASELINE CONFIGURATION DEFAULTS
# Fallback constants if external configuration is omitted
# ==============================================================================

# Default known internal IP addresses and corporate subnets
KNOWN_INTERNAL_IPS: Set[str] = {
    "10.0.1.45",
    "10.0.2.80",
    "10.0.0.0/16",
    "192.168.1.0/24",
    "127.0.0.1",
}

# Default known enterprise hosts and server assets
KNOWN_HOSTS: Set[str] = {
    "DC-PROD-01",
    "WKSTN-FIN-12",
    "JUMPBOX-01",
    "SRV-APP-01",
    "SRV-DB-02",
    "SRV-BACKUP-03",
}

# Default normal business hours (inclusive start hour, exclusive end hour)
NORMAL_LOGIN_START_HOUR: int = 8   # 08:00 AM
NORMAL_LOGIN_END_HOUR: int = 18    # 06:00 PM (18:00)

# ==============================================================================
# SCORING CONSTANTS & FLAGS
# Transparent weights for anomalous contextual dimensions
# ==============================================================================

SCORE_UNKNOWN_IP: int = 20
SCORE_UNUSUAL_TIME: int = 15
SCORE_UNKNOWN_HOST: int = 10

FLAG_UNKNOWN_IP: str = "UNKNOWN_IP"
FLAG_UNUSUAL_TIME: str = "UNUSUAL_LOGIN_TIME"
FLAG_UNKNOWN_HOST: str = "UNKNOWN_HOST"
FLAG_INVALID_TIMESTAMP: str = "INVALID_TIMESTAMP"


def is_known_ip(ip_str: Any, known_ips: Optional[Collection[str]] = None) -> bool:
    """
    Checks whether a source IP address belongs to known/internal IP baselines.
    Supports exact IP matches and CIDR network containment.
    Gracefully handles empty strings, None, and non-string inputs.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    ip_cleaned = ip_str.strip()
    if not ip_cleaned:
        return False

    baseline_ips = known_ips if known_ips is not None else KNOWN_INTERNAL_IPS

    # Direct match check
    if ip_cleaned in baseline_ips:
        return True

    # Subnet containment check via ipaddress module
    try:
        ip_obj = ipaddress.ip_address(ip_cleaned)
        for entry in baseline_ips:
            try:
                network = ipaddress.ip_network(str(entry).strip(), strict=False)
                if ip_obj in network:
                    return True
            except ValueError:
                continue
    except ValueError:
        return False

    return False


def is_normal_login_time(
    timestamp_str: Any,
    start_hour: int = NORMAL_LOGIN_START_HOUR,
    end_hour: int = NORMAL_LOGIN_END_HOUR,
) -> Tuple[bool, bool]:
    """
    Evaluates whether an event timestamp falls within normal business hours.

    Returns:
        Tuple of (is_normal_time, is_valid_timestamp)
    """
    if not timestamp_str or not isinstance(timestamp_str, str):
        return False, False

    ts_cleaned = timestamp_str.strip()
    if not ts_cleaned:
        return False, False

    try:
        # Handles ISO formats e.g. 2026-09-01T03:10:00 or ISO with offset
        dt = datetime.fromisoformat(ts_cleaned)
        is_normal = start_hour <= dt.hour < end_hour
        return is_normal, True
    except (ValueError, TypeError):
        # Gracefully handle malformed timestamp without crashing
        return False, False


def is_known_host(host_name: Any, known_hosts: Optional[Collection[str]] = None) -> bool:
    """
    Checks whether a host name matches the known enterprise host baseline.
    Gracefully handles None and non-string inputs.
    """
    if not host_name or not isinstance(host_name, str):
        return False

    host_cleaned = host_name.strip()
    if not host_cleaned:
        return False

    baseline_hosts = known_hosts if known_hosts is not None else KNOWN_HOSTS
    return host_cleaned in baseline_hosts


def enrich_event(
    event: Dict[str, Any],
    config: Optional[SecurityConfig] = None,
    known_ips: Optional[Collection[str]] = None,
    known_hosts: Optional[Collection[str]] = None,
    start_hour: Optional[int] = None,
    end_hour: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Enriches a single normalized event dictionary with contextual metadata.
    Preserves all original fields and adds a 'context' dictionary.

    Supports resolution from SecurityConfig with explicit parameter overrides.
    """
    if not isinstance(event, dict):
        return {
            "context": {
                "known_ip": False,
                "normal_login_time": False,
                "known_host": False,
                "context_flags": [FLAG_INVALID_TIMESTAMP],
                "context_score": 45,
            }
        }

    enriched: Dict[str, Any] = dict(event)

    # Determine baseline parameters from config / overrides / defaults
    resolved_ips: Collection[str] = (
        known_ips
        if known_ips is not None
        else (config.known_internal_ips if config else KNOWN_INTERNAL_IPS)
    )
    resolved_hosts: Collection[str] = (
        known_hosts
        if known_hosts is not None
        else (config.known_hosts if config else KNOWN_HOSTS)
    )
    resolved_start_hour: int = (
        start_hour
        if start_hour is not None
        else (config.normal_login_start_hour if config else NORMAL_LOGIN_START_HOUR)
    )
    resolved_end_hour: int = (
        end_hour
        if end_hour is not None
        else (config.normal_login_end_hour if config else NORMAL_LOGIN_END_HOUR)
    )

    source_ip = event.get("source_ip")
    timestamp = event.get("timestamp")
    host = event.get("host")

    known_ip = is_known_ip(source_ip, known_ips=resolved_ips)
    normal_time, valid_ts = is_normal_login_time(
        timestamp, start_hour=resolved_start_hour, end_hour=resolved_end_hour
    )
    known_host_val = is_known_host(host, known_hosts=resolved_hosts)

    context_flags: List[str] = []
    context_score: int = 0

    if not known_ip:
        context_flags.append(FLAG_UNKNOWN_IP)
        context_score += SCORE_UNKNOWN_IP

    if not normal_time:
        context_flags.append(FLAG_UNUSUAL_TIME)
        context_score += SCORE_UNUSUAL_TIME

    if not valid_ts:
        context_flags.append(FLAG_INVALID_TIMESTAMP)

    if not known_host_val:
        context_flags.append(FLAG_UNKNOWN_HOST)
        context_score += SCORE_UNKNOWN_HOST

    enriched["context"] = {
        "known_ip": known_ip,
        "normal_login_time": normal_time,
        "known_host": known_host_val,
        "context_flags": context_flags,
        "context_score": context_score,
    }

    return enriched


def enrich_events(
    events: List[Dict[str, Any]],
    config: Optional[SecurityConfig] = None,
    known_ips: Optional[Collection[str]] = None,
    known_hosts: Optional[Collection[str]] = None,
    start_hour: Optional[int] = None,
    end_hour: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Accepts a list of normalized events and returns a list of enriched events.
    """
    if not isinstance(events, list):
        return []

    return [
        enrich_event(
            event,
            config=config,
            known_ips=known_ips,
            known_hosts=known_hosts,
            start_hour=start_hour,
            end_hour=end_hour,
        )
        for event in events
        if isinstance(event, dict)
    ]


if __name__ == "__main__":
    # Attempt to load external config or fallback cleanly
    try:
        sec_config = load_config()
        print("Loaded external security configuration successfully.")
    except Exception as e:
        sec_config = get_default_config()
        print(f"Using default configuration ({e}).")

    mock_file = Path(__file__).parent / "data" / "normalized_events.json"
    if mock_file.exists():
        with open(mock_file, "r", encoding="utf-8") as f:
            raw_events = json.load(f)

        enriched_data = enrich_events(raw_events, config=sec_config)
        print(f"Enriched {len(enriched_data)} events successfully.")
        for sample in enriched_data[:3]:
            print(json.dumps(sample, indent=2))


