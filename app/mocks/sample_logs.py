"""Deterministic sample security logs for mock pipeline."""

from datetime import datetime, timedelta, timezone

BASE_TIME = datetime(2026, 3, 15, 2, 0, 0, tzinfo=timezone.utc)


def _ts(minutes: int) -> datetime:
    return BASE_TIME + timedelta(minutes=minutes)


SAMPLE_RAW_LOGS: list[dict] = [
    {
        "event_id": "raw-001",
        "source": "auth",
        "timestamp": _ts(0).isoformat(),
        "raw_message": "Failed login for user admin from 203.0.113.45 - invalid password",
        "metadata": {"user": "admin", "src_ip": "203.0.113.45", "result": "failure"},
    },
    {
        "event_id": "raw-002",
        "source": "auth",
        "timestamp": _ts(1).isoformat(),
        "raw_message": "Failed login for user admin from 203.0.113.45 - invalid password",
        "metadata": {"user": "admin", "src_ip": "203.0.113.45", "result": "failure"},
    },
    {
        "event_id": "raw-003",
        "source": "auth",
        "timestamp": _ts(2).isoformat(),
        "raw_message": "Failed login for user admin from 203.0.113.45 - invalid password",
        "metadata": {"user": "admin", "src_ip": "203.0.113.45", "result": "failure"},
    },
    {
        "event_id": "raw-004",
        "source": "auth",
        "timestamp": _ts(5).isoformat(),
        "raw_message": "Successful login for user admin from 203.0.113.45",
        "metadata": {"user": "admin", "src_ip": "203.0.113.45", "result": "success"},
    },
    {
        "event_id": "raw-005",
        "source": "vpn",
        "timestamp": _ts(8).isoformat(),
        "raw_message": "VPN session established for user admin from unknown geo IP 203.0.113.45",
        "metadata": {"user": "admin", "src_ip": "203.0.113.45", "geo": "unknown"},
    },
    {
        "event_id": "raw-006",
        "source": "edr",
        "timestamp": _ts(12).isoformat(),
        "raw_message": "powershell.exe spawned with encoded command on WORKSTATION-07",
        "metadata": {"host": "WORKSTATION-07", "process": "powershell.exe", "parent": "winlogon.exe"},
    },
    {
        "event_id": "raw-007",
        "source": "network",
        "timestamp": _ts(18).isoformat(),
        "raw_message": "SMB connection from WORKSTATION-07 to FILE-SERVER-01",
        "metadata": {"src_host": "WORKSTATION-07", "dst_host": "FILE-SERVER-01", "port": 445},
    },
    {
        "event_id": "raw-008",
        "source": "file_audit",
        "timestamp": _ts(25).isoformat(),
        "raw_message": "Sensitive file accessed: /finance/Q1_reports.xlsx by admin on FILE-SERVER-01",
        "metadata": {"user": "admin", "file": "/finance/Q1_reports.xlsx", "host": "FILE-SERVER-01"},
    },
]
