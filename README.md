# mrun-detection

Backend Threat Detection and Event Correlation Engine for SIH 2026 Cybersecurity Hackathon.

## Overview

`mrun-detection` processes normalized security events, enriches them with organizational context, evaluates deterministic threat detection rules, and correlates multi-stage attack activities into actionable security incidents with timelines, evidence references, risk scoring, and attack patterns.

---

## Directory Structure

```text
mrun-detection/
├── config/
│   └── security_config.json      # External baseline configuration (IPs, subnets, hosts, hours)
├── data/
│   └── normalized_events.json    # Existing normalized test fixture
├── private_data/
│   └── kv_logs.zip               # Local/private KV input (ignored by Git)
├── output/
│   └── correlated_incidents.json # Final correlated incidents and metrics report
├── config_loader.py              # Configuration loading and schema/network validation
├── context_engine.py             # Context enrichment engine (internal IP, hours, hosts)
├── detection_engine.py           # Deterministic rule-based threat detection engine
├── correlation_engine.py         # Graph-based event and finding correlation engine
├── kv_log_adapter.py            # KV ZIP/CSV → CYPHER event adapter
├── main.py                       # Pipeline orchestrator and CLI entry point
├── test_pipeline.py              # Automated validation and unit test suite
├── requirements.txt              # Project dependencies (Standard Library only)
└── README.md                     # Project documentation
```

---

## Configuration Architecture

Security baselines and working parameters are managed externally via JSON files in [`config/`](file:///C:/Users/Mrunmayee/Desktop/SIH-Cybersecurity/mrun-detection/config).

### `config/security_config.json` Example

```json
{
  "known_internal_ips": [
    "10.0.1.45",
    "10.0.2.80",
    "10.0.0.0/16",
    "192.168.1.0/24",
    "127.0.0.1"
  ],
  "known_hosts": [
    "DC-PROD-01",
    "WKSTN-FIN-12",
    "JUMPBOX-01",
    "SRV-APP-01",
    "SRV-DB-02",
    "SRV-BACKUP-03"
  ],
  "normal_login_hours": {
    "start": 8,
    "end": 18
  }
}
```

### Configuration Fields & Validation

The [`config_loader.py`](file:///C:/Users/Mrunmayee/Desktop/SIH-Cybersecurity/mrun-detection/config_loader.py) module performs strict syntactic and semantic validation:

1. **`known_internal_ips`**:
   - List of exact IP addresses (e.g. `10.0.1.45`, `127.0.0.1`) and CIDR subnets (e.g. `10.0.0.0/16`, `192.168.1.0/24`).
   - Validated using Python's standard `ipaddress` module (`ipaddress.ip_address` and `ipaddress.ip_network`).
   - Invalid formats raise `ConfigValidationError`.
2. **`known_hosts`**:
   - List of known server and workstation asset identifiers.
   - Must be non-empty strings.
3. **`normal_login_hours`**:
   - Object with `start` and `end` integers representing 24-hour clock values (0–24).
   - Validates that `0 <= start < end <= 24`.

---

## How Configuration is Loaded

```text
config/security_config.json
          │
          ▼
   config_loader.py ──(Validates IPs, CIDRs, Hours)──► SecurityConfig object
                                                               │
                                                               ▼
                                                       context_engine.py
                                                               │
                                                               ▼
                                                       detection_engine.py
```

1. **Automatic Loading**: [`main.py`](file:///C:/Users/Mrunmayee/Desktop/SIH-Cybersecurity/mrun-detection/main.py) automatically attempts to load [`config/security_config.json`](file:///C:/Users/Mrunmayee/Desktop/SIH-Cybersecurity/mrun-detection/config/security_config.json).
2. **Graceful Fallback**: If the configuration file is omitted or missing, [`context_engine.py`](file:///C:/Users/Mrunmayee/Desktop/SIH-Cybersecurity/mrun-detection/context_engine.py) seamlessly falls back to default constants.
3. **Custom Config Path**: `main.run_pipeline(config_path=...)` allows programmatic injection of alternate configuration files.

---

## Running the Pipeline

### Run Main Pipeline:
```bash
python main.py
```

The default input remains the existing normalized JSON fixture.

### Run with KV ZIP input:
Place KV's ZIP at `private_data/kv_logs.zip` locally (this directory is Git-ignored), then run:

```bash
python main.py --input private_data/kv_logs.zip
```

The adapter reads the CSV directly from the ZIP, normalizes it to CYPHER's canonical event schema, and passes the resulting events into the existing Context, Detection, Correlation, and Risk + Confidence engines. The raw ZIP is not required to be extracted into `data/` and must not be committed to GitHub.

You can also pass a KV CSV directly:

```bash
python main.py --input path/to/enterprise_security_logs.csv
```

### Run Pipeline with Custom Paths (Python):
```python
from pathlib import Path
import main

main.run_pipeline(
    input_path=Path("data/normalized_events.json"),
    output_path=Path("output/correlated_incidents.json"),
    config_path=Path("config/security_config.json")
)
```

---

## Running the Test Suite

Run the complete automated test suite (20 unit & integration tests):

```bash
python test_pipeline.py
```

