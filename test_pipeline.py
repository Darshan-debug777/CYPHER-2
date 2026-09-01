"""
Automated Validation and Unit Test Suite for SIH 2026 Cybersecurity Module:
Context Engine, Threat Detection Engine, Event Correlation Engine, Config Loader, and Pipeline Orchestration.
"""

from datetime import datetime
import json
from pathlib import Path
import tempfile
import unittest

import config_loader
from config_loader import ConfigError, ConfigNotFoundError, ConfigValidationError, SecurityConfig
import context_engine
import detection_engine
import correlation_engine
import main


class TestConfigLoader(unittest.TestCase):
    def test_valid_config_loading(self):
        valid_dict = {
            "known_internal_ips": ["10.0.0.0/8", "192.168.1.100"],
            "known_hosts": ["PROD-SERVER-01", "BACKUP-01"],
            "normal_login_hours": {"start": 9, "end": 17}
        }
        cfg = config_loader.validate_and_parse_config(valid_dict)
        self.assertIn("10.0.0.0/8", cfg.known_internal_ips)
        self.assertIn("192.168.1.100", cfg.known_internal_ips)
        self.assertIn("PROD-SERVER-01", cfg.known_hosts)
        self.assertEqual(cfg.normal_login_start_hour, 9)
        self.assertEqual(cfg.normal_login_end_hour, 17)

    def test_invalid_ip_cidr(self):
        invalid_dict = {
            "known_internal_ips": ["999.999.999.999"],
            "known_hosts": ["HOST-01"],
            "normal_login_hours": {"start": 8, "end": 18}
        }
        with self.assertRaises(ConfigValidationError):
            config_loader.validate_and_parse_config(invalid_dict)

    def test_invalid_login_hours_range(self):
        # start >= end
        invalid_dict_1 = {
            "known_internal_ips": ["10.0.0.1"],
            "known_hosts": ["HOST-01"],
            "normal_login_hours": {"start": 18, "end": 8}
        }
        with self.assertRaises(ConfigValidationError):
            config_loader.validate_and_parse_config(invalid_dict_1)

        # hour out of bounds (> 24 or < 0)
        invalid_dict_2 = {
            "known_internal_ips": ["10.0.0.1"],
            "known_hosts": ["HOST-01"],
            "normal_login_hours": {"start": -1, "end": 18}
        }
        with self.assertRaises(ConfigValidationError):
            config_loader.validate_and_parse_config(invalid_dict_2)

    def test_missing_required_fields(self):
        # Missing known_hosts
        incomplete_dict = {
            "known_internal_ips": ["10.0.0.1"],
            "normal_login_hours": {"start": 8, "end": 18}
        }
        with self.assertRaises(ConfigValidationError):
            config_loader.validate_and_parse_config(incomplete_dict)

    def test_missing_config_file(self):
        with self.assertRaises(ConfigNotFoundError):
            config_loader.load_config(Path("nonexistent_config_path.json"))

    def test_custom_config_respected_in_context_engine(self):
        # Custom config where 185.220.101.5 is explicitly KNOWN, and 03:00 is within working hours (00:00 - 06:00)
        custom_cfg = SecurityConfig(
            known_internal_ips={"185.220.101.5"},
            known_hosts={"CUSTOM-DC-99"},
            normal_login_start_hour=0,
            normal_login_end_hour=6
        )

        event = {
            "event_id": "T_CUSTOM",
            "timestamp": "2026-09-01T03:10:00",
            "user": "admin",
            "source_ip": "185.220.101.5",
            "host": "CUSTOM-DC-99",
            "event_type": "authentication",
            "action": "login",
            "status": "success"
        }

        # With default config: IP 185.220.101.5 is unknown, 03:10 is off-hours, CUSTOM-DC-99 is unknown host -> context_score = 45
        default_enriched = context_engine.enrich_event(event)
        self.assertFalse(default_enriched["context"]["known_ip"])
        self.assertFalse(default_enriched["context"]["normal_login_time"])
        self.assertFalse(default_enriched["context"]["known_host"])
        self.assertEqual(default_enriched["context"]["context_score"], 45)

        # With custom config: IP is known, 03:10 is within 00-06, host is known -> context_score = 0
        custom_enriched = context_engine.enrich_event(event, config=custom_cfg)
        self.assertTrue(custom_enriched["context"]["known_ip"])
        self.assertTrue(custom_enriched["context"]["normal_login_time"])
        self.assertTrue(custom_enriched["context"]["known_host"])
        self.assertEqual(custom_enriched["context"]["context_score"], 0)


class TestContextEngine(unittest.TestCase):
    def test_known_vs_unknown_ip(self):
        self.assertTrue(context_engine.is_known_ip("10.0.1.45"))
        self.assertTrue(context_engine.is_known_ip("10.0.99.1"))  # 10.0.0.0/16 subnet
        self.assertTrue(context_engine.is_known_ip("192.168.1.50"))  # 192.168.1.0/24 subnet
        self.assertFalse(context_engine.is_known_ip("185.220.101.5"))
        self.assertFalse(context_engine.is_known_ip(""))
        self.assertFalse(context_engine.is_known_ip(None))
        self.assertFalse(context_engine.is_known_ip("invalid-ip"))

    def test_normal_vs_unusual_hours(self):
        # 09:15 is within 08:00-18:00
        normal, valid = context_engine.is_normal_login_time("2026-09-01T09:15:00")
        self.assertTrue(normal)
        self.assertTrue(valid)

        # 03:10 is outside 08:00-18:00
        normal, valid = context_engine.is_normal_login_time("2026-09-01T03:10:00")
        self.assertFalse(normal)
        self.assertTrue(valid)

        # Malformed timestamps
        normal, valid = context_engine.is_normal_login_time("not-a-timestamp")
        self.assertFalse(normal)
        self.assertFalse(valid)

        normal, valid = context_engine.is_normal_login_time(None)
        self.assertFalse(normal)
        self.assertFalse(valid)

    def test_enrich_event_structure(self):
        event = {
            "event_id": "T001",
            "timestamp": "2026-09-01T09:30:00",
            "user": "alice",
            "source_ip": "10.0.1.45",
            "host": "WKSTN-FIN-12",
            "event_type": "authentication",
            "action": "login",
            "status": "success"
        }
        enriched = context_engine.enrich_event(event)
        self.assertIn("context", enriched)
        self.assertTrue(enriched["context"]["known_ip"])
        self.assertTrue(enriched["context"]["normal_login_time"])
        self.assertTrue(enriched["context"]["known_host"])
        self.assertEqual(enriched["context"]["context_score"], 0)
        self.assertEqual(enriched["context"]["context_flags"], [])


class TestDetectionEngine(unittest.TestCase):
    def test_normal_activity_no_findings(self):
        events = [
            {
                "event_id": "N001",
                "timestamp": "2026-09-01T09:15:00",
                "user": "alice",
                "source_ip": "10.0.1.45",
                "host": "WKSTN-FIN-12",
                "event_type": "authentication",
                "action": "login",
                "status": "success"
            },
            {
                "event_id": "N002",
                "timestamp": "2026-09-01T09:20:00",
                "user": "alice",
                "source_ip": "10.0.1.45",
                "host": "WKSTN-FIN-12",
                "event_type": "file_access",
                "action": "read_document",
                "status": "success"
            },
            {
                "event_id": "N003",
                "timestamp": "2026-09-01T17:30:00",
                "user": "alice",
                "source_ip": "10.0.1.45",
                "host": "WKSTN-FIN-12",
                "event_type": "authentication",
                "action": "logout",
                "status": "success"
            }
        ]
        enriched = context_engine.enrich_events(events)
        findings = detection_engine.detect_threats(enriched)
        self.assertEqual(len(findings), 0, "Normal office-hour activity must produce 0 findings")

    def test_suspicious_event_detection(self):
        event = {
            "event_id": "S001",
            "timestamp": "2026-09-01T10:00:00",
            "user": "admin",
            "source_ip": "10.0.1.45",
            "host": "DC-PROD-01",
            "event_type": "process",
            "action": "powershell_execution",
            "status": "success"
        }
        enriched = context_engine.enrich_events([event])
        findings = detection_engine.detect_threats(enriched)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["rule"], "POWERSHELL_EXECUTION")
        self.assertIn("S001", findings[0]["event_ids"])

    def test_contextual_change_affects_detection(self):
        # Event 1: Internal IP during business hours -> 0 unknown IP detections
        event_benign = {
            "event_id": "C001",
            "timestamp": "2026-09-01T11:00:00",
            "user": "charlie",
            "source_ip": "10.0.1.45",
            "host": "WKSTN-FIN-12",
            "event_type": "authentication",
            "action": "login",
            "status": "success"
        }
        # Event 2: External unknown IP -> Triggers unknown IP detection
        event_unknown_ip = {
            "event_id": "C002",
            "timestamp": "2026-09-01T11:00:00",
            "user": "charlie",
            "source_ip": "198.51.100.25",
            "host": "WKSTN-FIN-12",
            "event_type": "authentication",
            "action": "login",
            "status": "success"
        }
        # Event 3: Unusual off-hours login (02:00 AM) -> Triggers unusual time detection
        event_off_hours = {
            "event_id": "C003",
            "timestamp": "2026-09-01T02:00:00",
            "user": "charlie",
            "source_ip": "10.0.1.45",
            "host": "WKSTN-FIN-12",
            "event_type": "authentication",
            "action": "login",
            "status": "success"
        }

        # Benign check
        enriched_benign = context_engine.enrich_events([event_benign])
        self.assertEqual(len(detection_engine.detect_unknown_ip(enriched_benign)), 0)
        self.assertEqual(len(detection_engine.detect_unusual_login_time(enriched_benign)), 0)

        # Unknown IP check
        enriched_ip = context_engine.enrich_events([event_unknown_ip])
        ip_findings = detection_engine.detect_unknown_ip(enriched_ip)
        self.assertEqual(len(ip_findings), 1)
        self.assertEqual(ip_findings[0]["rule"], "UNKNOWN_OR_SUSPICIOUS_IP")

        # Off-hours check
        enriched_time = context_engine.enrich_events([event_off_hours])
        time_findings = detection_engine.detect_unusual_login_time(enriched_time)
        self.assertEqual(len(time_findings), 1)
        self.assertEqual(time_findings[0]["rule"], "UNUSUAL_LOGIN_TIME")


class TestCorrelationEngine(unittest.TestCase):
    def test_multiple_related_events_one_incident(self):
        events = [
            {
                "event_id": "R001",
                "timestamp": "2026-09-01T03:00:00",
                "user": "attacker",
                "source_ip": "185.10.10.10",
                "host": "DC-PROD-01",
                "event_type": "authentication",
                "action": "login",
                "status": "failed"
            },
            {
                "event_id": "R002",
                "timestamp": "2026-09-01T03:00:30",
                "user": "attacker",
                "source_ip": "185.10.10.10",
                "host": "DC-PROD-01",
                "event_type": "authentication",
                "action": "login",
                "status": "failed"
            },
            {
                "event_id": "R003",
                "timestamp": "2026-09-01T03:01:00",
                "user": "attacker",
                "source_ip": "185.10.10.10",
                "host": "DC-PROD-01",
                "event_type": "authentication",
                "action": "login",
                "status": "failed"
            },
            {
                "event_id": "R004",
                "timestamp": "2026-09-01T03:02:00",
                "user": "attacker",
                "source_ip": "185.10.10.10",
                "host": "DC-PROD-01",
                "event_type": "authentication",
                "action": "login",
                "status": "success"
            },
            {
                "event_id": "R005",
                "timestamp": "2026-09-01T03:03:00",
                "user": "attacker",
                "source_ip": "185.10.10.10",
                "host": "DC-PROD-01",
                "event_type": "privilege",
                "action": "escalate_privilege",
                "status": "success"
            }
        ]
        enriched = context_engine.enrich_events(events)
        findings = detection_engine.detect_threats(enriched)
        self.assertGreater(len(findings), 1)

        incidents = correlation_engine.correlate_events(enriched, findings)
        self.assertEqual(len(incidents), 1, "Related sequential attacker events must form exactly 1 incident")
        self.assertEqual(incidents[0]["threat_type"], "Possible Credential Compromise")
        self.assertIn("attacker", incidents[0]["affected_users"])
        self.assertIn("185.10.10.10", incidents[0]["source_ips"])
        self.assertEqual(len(incidents[0]["event_ids"]), 5)

    def test_unrelated_suspicious_events_separate_incidents(self):
        # Attacker 1 in Subnet Alpha at 03:00
        attacker1_events = [
            {
                "event_id": "A001",
                "timestamp": "2026-09-01T03:00:00",
                "user": "attacker1",
                "source_ip": "185.1.1.1",
                "host": "SRV-APP-01",
                "event_type": "process",
                "action": "powershell_execution",
                "status": "success"
            }
        ]
        # Attacker 2 in Subnet Beta at 16:00
        attacker2_events = [
            {
                "event_id": "B001",
                "timestamp": "2026-09-01T16:00:00",
                "user": "attacker2",
                "source_ip": "198.51.100.99",
                "host": "SRV-DB-02",
                "event_type": "file_access",
                "action": "read_sensitive_data",
                "status": "success"
            }
        ]

        all_events = attacker1_events + attacker2_events
        enriched = context_engine.enrich_events(all_events)
        findings = detection_engine.detect_threats(enriched)
        self.assertEqual(len(findings), 4)

        incidents = correlation_engine.correlate_events(enriched, findings)
        self.assertEqual(len(incidents), 2, "Unrelated attackers at different times/IPs must form separate incidents")
        self.assertNotEqual(incidents[0]["affected_users"], incidents[1]["affected_users"])


class TestEdgeCasesAndRobustness(unittest.TestCase):
    def test_empty_input(self):
        enriched = context_engine.enrich_events([])
        self.assertEqual(enriched, [])
        findings = detection_engine.detect_threats(enriched)
        self.assertEqual(findings, [])
        incidents = correlation_engine.correlate_events(enriched, findings)
        self.assertEqual(incidents, [])

    def test_malformed_and_missing_fields(self):
        malformed_events = [
            {},
            {"event_id": "M001", "timestamp": None, "user": None, "source_ip": None},
            {"event_id": "M002", "timestamp": "not-a-date", "action": 12345, "event_type": None},
            "not a dictionary record"
        ]
        enriched = context_engine.enrich_events(malformed_events)
        self.assertEqual(len(enriched), 3)
        findings = detection_engine.detect_threats(enriched)
        incidents = correlation_engine.correlate_events(enriched, findings)
        self.assertIsInstance(incidents, list)

    def test_duplicate_events(self):
        event = {
            "event_id": "D001",
            "timestamp": "2026-09-01T10:00:00",
            "user": "admin",
            "source_ip": "10.0.1.45",
            "host": "DC-PROD-01",
            "event_type": "process",
            "action": "powershell_execution",
            "status": "success"
        }
        # Duplicate same event twice
        enriched = context_engine.enrich_events([event, event])
        findings = detection_engine.detect_threats(enriched)
        incidents = correlation_engine.correlate_events(enriched, findings)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["event_ids"], ["D001"])


class TestEndToEndPipeline(unittest.TestCase):
    def test_full_dataset_execution_with_config(self):
        dataset_path = Path(__file__).parent / "data" / "normalized_events.json"
        config_path = Path(__file__).parent / "config" / "security_config.json"
        self.assertTrue(dataset_path.exists(), "data/normalized_events.json must exist")
        self.assertTrue(config_path.exists(), "config/security_config.json must exist")

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "test_incidents.json"
            res = main.run_pipeline(input_path=dataset_path, output_path=out_file, config_path=config_path)
            self.assertEqual(res, 0, "Pipeline must exit with code 0")
            self.assertTrue(out_file.exists(), "Output file must be written")

            with open(out_file, "r", encoding="utf-8") as f:
                report = json.load(f)

            self.assertEqual(report["summary"]["events_received"], 15)
            self.assertEqual(report["summary"]["events_enriched"], 15)
            self.assertEqual(report["summary"]["detections_generated"], 8)
            self.assertEqual(report["summary"]["incidents_generated"], 2)
            self.assertEqual(report["summary"]["events_correlated"], 11)
            self.assertEqual(report["summary"]["events_ignored"], 4)
            self.assertEqual(report["summary"]["processing_failures"], 0)
            self.assertEqual(len(report["incidents"]), 2)


class TestKVLogAdapter(unittest.TestCase):
    def test_kv_csv_normalization(self):
        import csv
        import tempfile
        import kv_log_adapter

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = Path(tmpdir) / "enterprise_security_logs.csv"
            with open(csv_path, "w", encoding="utf-8", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=kv_log_adapter.REQUIRED_FIELDS)
                writer.writeheader()
                writer.writerow({
                    "timestamp": "2026-09-01 02:00:00",
                    "user": "admin",
                    "source_ip": "185.220.101.10",
                    "host": "Server-01",
                    "event_type": "login",
                    "action": "login",
                    "status": "failed",
                })

            events, failures = kv_log_adapter.load_kv_logs(csv_path)

        self.assertEqual(failures, 0)
        self.assertEqual(len(events), 1)
        self.assertEqual(
            set(events[0].keys()),
            {
                "event_id", "timestamp", "user", "source_ip", "host",
                "event_type", "action", "status"
            },
        )

    def test_kv_login_and_powershell_mapping(self):
        import kv_log_adapter

        login = kv_log_adapter.normalize_event({
            "timestamp": "2026-09-01 02:00:00",
            "user": "admin",
            "source_ip": "185.220.101.10",
            "host": "Server-01",
            "event_type": "login",
            "action": "login",
            "status": "failed",
        })
        self.assertEqual(login["event_type"], "authentication")
        self.assertEqual(login["action"], "login")
        self.assertEqual(login["timestamp"], "2026-09-01T02:00:00")
        self.assertTrue(login["event_id"].startswith("E-"))

        powershell = kv_log_adapter.normalize_event({
            "timestamp": "2026-09-01 02:02:00",
            "user": "admin",
            "source_ip": "185.220.101.10",
            "host": "Server-01",
            "event_type": "powershell",
            "action": "script_execution",
            "status": "success",
        })
        self.assertEqual(powershell["event_type"], "process")
        self.assertEqual(powershell["action"], "powershell_execution")


if __name__ == "__main__":
    unittest.main()
