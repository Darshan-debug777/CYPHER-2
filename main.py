"""
Main Pipeline Orchestrator

Coordinates the security detection and correlation pipeline:
1. Loads normalized event datasets.
2. Loads and validates external security configuration (Config Loader).
3. Enriches events with contextual baselines (Context Engine).
4. Evaluates deterministic threat detection rules (Detection Engine).
5. Correlates findings and events into security incidents (Correlation Engine).
6. Evaluates independent Risk and Confidence metrics (Risk + Confidence Engine).
7. Persists structured incident reports and displays terminal summaries.
"""

from datetime import datetime
import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

import config_loader
import context_engine
import detection_engine
import correlation_engine
import kv_log_adapter
import risk_confidence_engine


def load_events(file_path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """
    Loads and validates normalized security events from a JSON file.

    Returns:
        Tuple of (valid_events_list, failure_count)
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found at: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON syntax in input file {file_path}: {exc}") from exc

    if not isinstance(data, list):
        raise ValueError(f"Expected a JSON list of event objects, got {type(data).__name__}")

    valid_events: List[Dict[str, Any]] = []
    failures = 0

    for item in data:
        if isinstance(item, dict):
            valid_events.append(item)
        else:
            failures += 1

    return valid_events, failures


def load_input_events(file_path: Path) -> Tuple[List[Dict[str, Any]], int]:
    """Load events from the existing normalized JSON input or KV ZIP/CSV input."""
    suffix = file_path.suffix.lower()
    if suffix == ".json":
        return load_events(file_path)
    if suffix in {".zip", ".csv"}:
        return kv_log_adapter.load_kv_logs(file_path)
    raise ValueError(
        f"Unsupported input format {file_path.suffix!r}; expected .json, .zip, or .csv"
    )


def save_incidents(
    incidents: List[Dict[str, Any]],
    output_file: Path,
    metrics: Dict[str, Any],
) -> None:
    """
    Saves correlated incidents and execution metrics summary to the target JSON output file.
    """
    output_file.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "summary": {
            # Canonical summary fields
            "total_events": metrics["events_received"],
            "detections": metrics["detections_generated"],
            "incidents": metrics["incidents_generated"],
            # Detailed granular pipeline metrics
            "events_received": metrics["events_received"],
            "events_enriched": metrics["events_enriched"],
            "detections_generated": metrics["detections_generated"],
            "events_correlated": metrics["events_correlated"],
            "events_ignored": metrics["events_ignored"],
            "incidents_generated": metrics["incidents_generated"],
            "processing_failures": metrics["processing_failures"],
        },
        "incidents": incidents,
    }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def print_summary(
    metrics: Dict[str, Any],
    incidents: List[Dict[str, Any]],
    output_path: Path,
    config_status: str = "Loaded",
) -> None:
    """
    Prints a formatted summary of the detection and correlation pipeline to the terminal.
    """
    print("\n" + "=" * 40)
    print("SECURITY EVENT CORRELATION ENGINE")
    print("=" * 40)
    print()
    print(f"Configuration: {config_status}")
    print(f"Events processed: {metrics['events_received']}")
    print(f"Events enriched with context: {metrics['events_enriched']}")
    print(f"Threat findings: {metrics['detections_generated']}")
    print(f"Events correlated into incidents: {metrics['events_correlated']}")
    print(f"Events ignored (normal baseline): {metrics['events_ignored']}")
    print(f"Incidents created: {metrics['incidents_generated']}")
    if metrics["processing_failures"] > 0:
        print(f"Processing failures: {metrics['processing_failures']}")
    print()
    print("-" * 40)
    print("INCIDENTS")
    print("-" * 40)

    if not incidents:
        print("\nNo security incidents detected.")
    else:
        for inc in incidents:
            inc_id = inc.get("incident_id", "N/A")
            threat = inc.get("threat_type", "Unknown Threat")
            
            # Risk display
            risk_info = inc.get("risk", {}) if isinstance(inc.get("risk"), dict) else {}
            risk_score = risk_info.get("score", inc.get("risk_score", 0))
            risk_level = risk_info.get("level", inc.get("severity", "LOW"))
            
            # Confidence display
            conf_info = inc.get("confidence", {}) if isinstance(inc.get("confidence"), dict) else {}
            conf_score = conf_info.get("percentage") or (
                f"{int(inc.get('confidence') * 100)}%" if isinstance(inc.get("confidence"), (int, float)) else str(inc.get("confidence", "N/A"))
            )
            conf_level = conf_info.get("level", "")
            
            event_ids = ", ".join(inc.get("event_ids", []))

            print()
            print(f"{inc_id} | {threat}")
            print(f"Risk: {risk_score}/100 ({risk_level})")
            print(f"Confidence: {conf_score} ({conf_level})" if conf_level else f"Confidence: {conf_score}")
            print(f"Events: {event_ids}")

    print()
    print("-" * 40)
    print()
    print("Output:")
    print(f"{output_path.as_posix()}")
    print()
    print("=" * 40 + "\n")


def run_pipeline(
    input_path: Optional[Path] = None,
    output_path: Optional[Path] = None,
    config_path: Optional[Path] = None,
) -> int:
    """
    Executes the end-to-end security processing pipeline.
    """
    base_dir = Path(__file__).parent.resolve()
    input_file = input_path if input_path else base_dir / "data" / "normalized_events.json"
    output_file = output_path if output_path else base_dir / "output" / "correlated_incidents.json"
    cfg_file = config_path if config_path else base_dir / "config" / "security_config.json"

    # 1. Load configuration
    try:
        if cfg_file.exists():
            sec_config = config_loader.load_config(cfg_file)
            config_status = f"Loaded ({cfg_file.name})"
        else:
            sec_config = config_loader.get_default_config()
            config_status = "Default (config file not found)"
    except (config_loader.ConfigError, Exception) as err:
        print(f"[ERROR] Security configuration error: {err}", file=sys.stderr)
        return 1

    # 2. Load input events. JSON remains the default; KV ZIP/CSV is normalized at the boundary.
    try:
        events, load_failures = load_input_events(input_file)
    except (FileNotFoundError, ValueError) as err:
        print(f"[ERROR] Failed to load input dataset: {err}", file=sys.stderr)
        return 1

    processing_failures = load_failures

    # 3. Context Engine enrichment (with external config)
    try:
        enriched_events = context_engine.enrich_events(events, config=sec_config)
    except Exception as err:
        print(f"[ERROR] Context Engine failure: {err}", file=sys.stderr)
        return 1

    # 4. Threat Detection Engine
    try:
        findings = detection_engine.detect_threats(enriched_events)
    except Exception as err:
        print(f"[ERROR] Detection Engine failure: {err}", file=sys.stderr)
        return 1

    # 5. Event Correlation Engine
    try:
        incidents = correlation_engine.correlate_events(enriched_events, findings)
    except Exception as err:
        print(f"[ERROR] Correlation Engine failure: {err}", file=sys.stderr)
        return 1

    # 6. Risk and Confidence Engine (Evaluates independent Risk & Confidence models)
    try:
        incidents = risk_confidence_engine.evaluate_incidents(incidents, config=sec_config)
    except Exception as err:
        print(f"[ERROR] Risk & Confidence Engine failure: {err}", file=sys.stderr)
        return 1

    # Calculate metrics
    correlated_event_ids: Set[str] = set()
    for inc in incidents:
        for eid in inc.get("event_ids", []):
            if eid:
                correlated_event_ids.add(str(eid))

    events_received = len(events)
    events_enriched = len(enriched_events)
    detections_generated = len(findings)
    events_correlated = len(correlated_event_ids)
    events_ignored = max(0, events_received - events_correlated)
    incidents_generated = len(incidents)

    metrics = {
        "events_received": events_received,
        "events_enriched": events_enriched,
        "detections_generated": detections_generated,
        "events_correlated": events_correlated,
        "events_ignored": events_ignored,
        "incidents_generated": incidents_generated,
        "processing_failures": processing_failures,
    }

    # 7. Save output report
    try:
        save_incidents(
            incidents=incidents,
            output_file=output_file,
            metrics=metrics,
        )
    except Exception as err:
        print(f"[ERROR] Failed to save incident report: {err}", file=sys.stderr)
        return 1

    # Relative display path for clean terminal output
    try:
        display_output_path = output_file.relative_to(base_dir)
    except ValueError:
        display_output_path = output_file

    # 8. Print formatted terminal summary
    print_summary(
        metrics=metrics,
        incidents=incidents,
        output_path=display_output_path,
        config_status=config_status,
    )

    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the CYPHER security detection and correlation pipeline."
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help=(
            "Input dataset (.json normalized events, or KV .zip/.csv). "
            "Defaults to data/normalized_events.json."
        ),
    )
    parser.add_argument("--output", type=Path, default=None, help="Incident report output path.")
    parser.add_argument("--config", type=Path, default=None, help="Security configuration JSON path.")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    sys.exit(
        run_pipeline(
            input_path=args.input,
            output_path=args.output,
            config_path=args.config,
        )
    )



