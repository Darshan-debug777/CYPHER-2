"""
KV Log Adapter

Adapts KV's CSV security-log format into the canonical CYPHER event contract.
The adapter accepts either the ZIP supplied by KV or a CSV file directly.

Raw/private logs are intentionally not copied into the repository by this module.
"""

from __future__ import annotations

import csv
import hashlib
import io
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


REQUIRED_FIELDS = (
    "timestamp",
    "user",
    "source_ip",
    "host",
    "event_type",
    "action",
    "status",
)

CANONICAL_FIELDS = (
    "event_id",
    "timestamp",
    "user",
    "source_ip",
    "host",
    "event_type",
    "action",
    "status",
)

SUPPORTED_TIMESTAMP_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M",
)


def generate_event_id(event: Dict[str, Any]) -> str:
    """Generate a deterministic event ID from the source event fields."""
    raw_data = "".join(str(event.get(field, "")) for field in REQUIRED_FIELDS)
    return "E-" + hashlib.sha256(raw_data.encode("utf-8")).hexdigest()[:12]


def normalize_timestamp(value: Any) -> str:
    """Convert KV timestamps to the ISO format expected by CYPHER."""
    if value is None:
        raise ValueError("timestamp is missing")

    timestamp = str(value).strip()
    for fmt in SUPPORTED_TIMESTAMP_FORMATS:
        try:
            return datetime.strptime(timestamp, fmt).isoformat()
        except ValueError:
            continue

    # Also accept already-valid ISO timestamps.
    try:
        return datetime.fromisoformat(timestamp).isoformat()
    except ValueError as exc:
        raise ValueError(f"unsupported timestamp format: {timestamp!r}") from exc


def _normalize_event_type_and_action(event_type: str, action: str) -> Tuple[str, str]:
    """Map KV vocabulary to the existing CYPHER detection vocabulary only where needed."""
    event_type = event_type.strip().lower()
    action = action.strip().lower()

    # CYPHER authentication rules expect event_type='authentication'.
    if event_type == "login" and action == "login":
        return "authentication", "login"

    # CYPHER's PowerShell rule expects powershell_execution in the action.
    if event_type == "powershell":
        return "process", "powershell_execution"

    return event_type, action


def normalize_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one KV row into the canonical CYPHER event contract."""
    missing = [field for field in REQUIRED_FIELDS if field not in raw_event]
    if missing:
        raise ValueError(f"missing required fields: {', '.join(missing)}")

    normalized = {
        "timestamp": normalize_timestamp(raw_event.get("timestamp")),
        "user": str(raw_event.get("user") or "").strip(),
        "source_ip": str(raw_event.get("source_ip") or "").strip(),
        "host": str(raw_event.get("host") or "").strip(),
        "event_type": str(raw_event.get("event_type") or "").strip().lower(),
        "action": str(raw_event.get("action") or "").strip().lower(),
        "status": str(raw_event.get("status") or "").strip().lower(),
    }

    normalized["event_type"], normalized["action"] = _normalize_event_type_and_action(
        normalized["event_type"], normalized["action"]
    )
    normalized["event_id"] = generate_event_id(normalized)

    return {field: normalized[field] for field in CANONICAL_FIELDS}


def _read_csv_stream(stream: io.TextIOBase) -> Tuple[List[Dict[str, Any]], int]:
    reader = csv.DictReader(stream)
    if reader.fieldnames is None:
        raise ValueError("KV CSV has no header row")

    headers = [str(header).strip() for header in reader.fieldnames]
    missing_headers = [field for field in REQUIRED_FIELDS if field not in headers]
    if missing_headers:
        raise ValueError(
            "KV CSV is missing required columns: " + ", ".join(missing_headers)
        )

    events: List[Dict[str, Any]] = []
    failures = 0

    for row_number, row in enumerate(reader, start=2):
        try:
            events.append(normalize_event(row))
        except ValueError as exc:
            failures += 1
            # Keep the error actionable without exposing raw event contents.
            print(f"[WARN] Skipping KV log row {row_number}: {exc}")

    return remove_duplicates(events), failures


def _find_csv_member(zf: zipfile.ZipFile) -> str:
    """Find the enterprise security CSV inside KV's ZIP without extracting it."""
    candidates = [
        name for name in zf.namelist()
        if not name.endswith("/") and Path(name).name == "enterprise_security_logs.csv"
    ]
    if not candidates:
        csv_candidates = [
            name for name in zf.namelist()
            if not name.endswith("/") and name.lower().endswith(".csv")
        ]
        if len(csv_candidates) == 1:
            return csv_candidates[0]
        raise ValueError("No unambiguous CSV log file found inside KV ZIP")
    return candidates[0]


def load_kv_logs(file_path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """
    Load and normalize KV logs from a ZIP or CSV.

    Returns:
        Tuple of (normalized_events, normalization_failure_count).
    """
    if not file_path.exists():
        raise FileNotFoundError(f"KV input file not found at: {file_path}")

    suffix = file_path.suffix.lower()
    if suffix == ".zip":
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                member = _find_csv_member(zf)
                with zf.open(member, "r") as raw:
                    text = io.TextIOWrapper(raw, encoding="utf-8", newline="")
                    try:
                        return _read_csv_stream(text)
                    finally:
                        text.detach()
        except zipfile.BadZipFile as exc:
            raise ValueError(f"Invalid ZIP archive: {file_path}") from exc

    if suffix == ".csv":
        with open(file_path, "r", encoding="utf-8", newline="") as stream:
            return _read_csv_stream(stream)

    raise ValueError(
        f"Unsupported KV input format {file_path.suffix!r}; expected .zip or .csv"
    )


def remove_duplicates(events: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate normalized events by deterministic event ID."""
    unique_events: Dict[str, Dict[str, Any]] = {}
    for event in events:
        event_id = str(event.get("event_id") or "")
        if event_id and event_id not in unique_events:
            unique_events[event_id] = event
    return list(unique_events.values())
