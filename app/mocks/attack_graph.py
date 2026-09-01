"""Mock attack graph and timeline (ROHIT placeholder)."""

import logging

from app.core.errors import EmptyResultError, InvalidModuleOutputError
from app.schemas.detection import CorrelatedIncident
from app.schemas.graph import AttackGraph, GraphEdge, GraphNode, IncidentTimeline, TimelineEntry
from app.schemas.enums import Severity

logger = logging.getLogger(__name__)


class MockAttackGraphService:
    async def build(self, incident: CorrelatedIncident) -> tuple[AttackGraph, IncidentTimeline]:
        if not incident.normalized_events:
            raise EmptyResultError("attack_graph", "No events for graph construction")

        nodes = [
            GraphNode(node_id="ip-ext", label="203.0.113.45", node_type="ip", attributes={"geo": "unknown"}),
            GraphNode(node_id="user-admin", label="admin", node_type="user"),
            GraphNode(node_id="host-ws07", label="WORKSTATION-07", node_type="host"),
            GraphNode(node_id="proc-ps", label="powershell.exe", node_type="process"),
            GraphNode(node_id="host-fs01", label="FILE-SERVER-01", node_type="host"),
            GraphNode(node_id="file-finance", label="Q1_reports.xlsx", node_type="file"),
        ]

        edges: list[GraphEdge] = []
        timeline_entries: list[TimelineEntry] = []

        stage_map = {
            "failed_login": ("initial_access", "Brute force login attempts", "T1110", Severity.MEDIUM),
            "successful_login": ("credential_access", "Successful login after brute force", "T1078", Severity.HIGH),
            "vpn_session": ("persistence", "Remote VPN access established", "T1133", Severity.MEDIUM),
            "process_execution": ("execution", "PowerShell executed with encoded payload", "T1059.001", Severity.HIGH),
            "lateral_movement": ("lateral_movement", "SMB lateral movement to file server", "T1021.002", Severity.HIGH),
            "sensitive_file_access": ("collection", "Sensitive finance file accessed", "T1005", Severity.CRITICAL),
        }

        edge_relationships = {
            "failed_login": ("ip-ext", "user-admin", "authenticated_to"),
            "successful_login": ("ip-ext", "user-admin", "authenticated_to"),
            "vpn_session": ("user-admin", "host-ws07", "connected_to"),
            "process_execution": ("user-admin", "proc-ps", "executed"),
            "lateral_movement": ("host-ws07", "host-fs01", "connected_to"),
            "sensitive_file_access": ("user-admin", "file-finance", "accessed"),
        }

        for idx, event in enumerate(incident.normalized_events):
            stage_info = stage_map.get(event.event_type)
            rel = edge_relationships.get(event.event_type)
            if stage_info:
                stage, desc, mitre, sev = stage_info
                timeline_entries.append(
                    TimelineEntry(
                        entry_id=f"tl-{idx+1:03d}",
                        timestamp=event.timestamp,
                        event_id=event.event_id,
                        stage=stage,
                        description=desc,
                        severity=sev,
                        mitre_technique=mitre,
                    )
                )
            if rel:
                src, tgt, relationship = rel
                edges.append(
                    GraphEdge(
                        edge_id=f"edge-{idx+1:03d}",
                        source_id=src,
                        target_id=tgt,
                        relationship=relationship,
                        event_id=event.event_id,
                        timestamp=event.timestamp,
                    )
                )

        if not timeline_entries:
            raise InvalidModuleOutputError("attack_graph", "Failed to build timeline entries")

        graph = AttackGraph(
            incident_id=incident.incident_id,
            nodes=nodes,
            edges=edges,
            entry_point="ip-ext",
            objective="file-finance",
        )

        timeline = IncidentTimeline(
            incident_id=incident.incident_id,
            entries=timeline_entries,
            attack_chain=[e.mitre_technique for e in timeline_entries if e.mitre_technique],
        )

        logger.info("Mock attack graph built for %s", incident.incident_id)
        return graph, timeline
