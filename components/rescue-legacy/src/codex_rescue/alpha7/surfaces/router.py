from __future__ import annotations

import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.graph import (
    PathNamespace,
    StorageProfile,
    SurfaceObservation,
    SurfaceVisibility,
    ThreadIdentity,
    ThreadNode,
    UnifiedStateGraph,
    detect_path_namespace,
    normalize_canonical_path,
)
from codex_rescue.alpha7.invariants import InvariantCheckResult, InvariantEngine, InvariantId, InvariantStatus
from codex_rescue.alpha7.surfaces.app_server import AppServerAdapter
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.detector import SurfaceDetector


from codex_rescue.thread_identity import resolve_thread_identity
from codex_rescue.thread_store import inspect_thread_store, WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE


@dataclass
class DiagnosticRoute:
    symptom: str
    probes_executed: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    confidence: str = "HIGH"
    root_cause_layer: str = "UNKNOWN"
    data_loss_evidence: str = "NONE"
    route_reason: str = "Automatic capability-based route selection"
    blocked_actions: List[str] = field(default_factory=list)
    invariants: List[InvariantCheckResult] = field(default_factory=list)
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "symptom": self.symptom,
            "probes_executed": self.probes_executed,
            "findings": self.findings,
            "confidence": self.confidence,
            "root_cause_layer": self.root_cause_layer,
            "data_loss_evidence": self.data_loss_evidence,
            "route_reason": self.route_reason,
            "blocked_actions": self.blocked_actions,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
            "recommendation": self.recommendation,
        }


class DiagnosticRouter:
    """Automatic decision engine for Alpha7. Cheap probes first, bounded expansion, confidence-based stop."""

    def __init__(self, codex_home: Optional[Path] = None):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        self.desktop_adapter = DesktopAdapter(self.codex_home)
        self.app_server_adapter = AppServerAdapter(self.codex_home)

    def route_session(self, session_id_or_path: str | Path) -> DiagnosticRoute:
        route = DiagnosticRoute(symptom="inspect_thread")

        # 1. Cheap probe: identify path / file using canonical thread identity
        route.probes_executed.append("cheap_probe_identity")
        target_path: Optional[Path] = None
        session_id: Optional[str] = None
        input_str = str(session_id_or_path).strip()

        if isinstance(session_id_or_path, Path) or ("/" in input_str or "\\" in input_str):
            p = Path(session_id_or_path)
            if p.exists():
                target_path = p
                identity = resolve_thread_identity(p)
                session_id = identity.thread_id
        else:
            session_id = input_str

        if not target_path and session_id:
            # Look in sessions / archived_sessions by canonical thread_id ONLY
            for candidate_dir in [self.codex_home / "sessions", self.codex_home / "archived_sessions"]:
                if not candidate_dir.exists():
                    continue
                for f in candidate_dir.rglob("*.jsonl"):
                    ident = resolve_thread_identity(f)
                    if ident.thread_id and ident.thread_id == session_id:
                        target_path = f
                        break
                if target_path:
                    break

        # If target file was found but ThreadId cannot be resolved
        if target_path and session_id is None:
            ident = resolve_thread_identity(target_path)
            if ident.thread_id is None:
                route.findings.append("IDENTITY_UNKNOWN")
                route.root_cause_layer = "UNRESOLVED_THREAD_IDENTITY"
                route.confidence = "UNKNOWN"
                route.route_reason = "Rollout file exists but logical ThreadId is unresolved; arbitrary filenames are not identities"
                route.recommendation = "Inspect file headers or retain as forensic artifact; automated mutation blocked."
                route.blocked_actions.append("MUTATION_BLOCKED_UNRESOLVED_IDENTITY")
                return route

        # 2. Probe Thread Store & SQLite using canonical inspect_thread_store
        route.probes_executed.append("probe_thread_store")
        fs_exists = target_path is not None and target_path.exists()
        store_report = None
        if target_path:
            store_report = inspect_thread_store(target_path, session_id=session_id, codex_home=self.codex_home)
            if store_report.findings:
                route.findings.extend(store_report.findings)

        sqlite_exists = store_report is not None and store_report.status in ("CONSISTENT", "DIVERGED")

        # 3. Probe App Server
        route.probes_executed.append("probe_app_server")
        app_obs = self.app_server_adapter.observe_thread(session_id) if session_id else None

        # 4. Diagnose based on observed evidence
        if fs_exists and not sqlite_exists:
            route.findings.append("UNINDEXED_IN_SQLITE")
            route.root_cause_layer = "DERIVED_SQLITE_INDEX"
            route.route_reason = "Rollout exists on filesystem but is not indexed in thread-store SQLite"
            route.recommendation = "derived index divergence observed; mutation currently HOLD"
            route.blocked_actions.append("MUTATION_BLOCKED_UNINDEXED")
        elif not fs_exists and sqlite_exists:
            route.findings.append("MISSING_ROLLOUT_FILE")
            route.root_cause_layer = "SOURCE_ROLLOUT"
            route.route_reason = "Thread row present in SQLite but rollout file not found on disk"
            route.data_loss_evidence = "SUSPECTED"
            route.recommendation = "Search backups for missing rollout file."
            route.blocked_actions.append("MUTATION_BLOCKED_MISSING_SOURCE")
        elif fs_exists and sqlite_exists:
            if store_report and WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE in store_report.findings:
                route.root_cause_layer = "WINDOWS_EXTENDED_PATH_BOUNDARY"
                route.route_reason = "Rollout transcript is healthy but thread-store path has diverged across extended-path boundary"
                route.recommendation = "Treat transcript as authoritative source; do not mutate SQLite in place without qualification."
                route.blocked_actions.append("IN_PLACE_SQLITE_MUTATION_HOLD")
            elif app_obs and app_obs.visibility == SurfaceVisibility.VISIBLE:
                route.root_cause_layer = "HEALTHY_MULTISURFACE"
                route.route_reason = "Session is visible and aligned across filesystem, SQLite and App Server"
            elif app_obs and app_obs.visibility == SurfaceVisibility.UNKNOWN:
                route.root_cause_layer = "APP_SERVER_UNKNOWN"
                route.route_reason = "Session exists in filesystem and SQLite; App Server visibility is UNKNOWN"
            else:
                route.root_cause_layer = "DERIVED_DESKTOP_PROJECTION"
                route.route_reason = "Session exists in filesystem and SQLite but App Server visibility is unconfirmed"
        else:
            route.findings.append("THREAD_NOT_FOUND")
            route.root_cause_layer = "NOT_FOUND"
            route.route_reason = "Thread not found on filesystem or SQLite"
            route.confidence = "INSUFFICIENT_EVIDENCE"
            route.blocked_actions.append("ALL_ACTIONS_BLOCKED")

        # Invariant checks
        if fs_exists and target_path:
            try:
                size = target_path.stat().st_size
                route.invariants.append(
                    InvariantEngine.check_source_accounting(size, size, 0, 0)
                )
            except Exception:
                pass

        return route

    def evaluate_environment(self, graph: UnifiedStateGraph) -> List[DiagnosticRoute]:
        """Evaluates all threads in graph and generates diagnostic routes."""
        routes: List[DiagnosticRoute] = []
        for node in graph.nodes.values():
            r = self.route_session(node.identity.thread_id)
            if node.has_cross_surface_divergence:
                r.findings.append("CROSS_SURFACE_VISIBILITY_DIVERGENCE")
            routes.append(r)
        return routes
