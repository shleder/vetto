from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.graph import (
    PathNamespace,
    SurfaceObservation,
    SurfaceVisibility,
    ThreadIdentity,
    ThreadNode,
    UnifiedStateGraph,
    detect_path_namespace,
    normalize_canonical_path,
)
from codex_rescue.alpha7.invariants import (
    InvariantCheckResult,
    InvariantEngine,
    InvariantEvaluation,
    InvariantId,
    InvariantStatus,
)
from codex_rescue.alpha7.simulation.transaction import TransactionResult, TransactionalRepairEngine
from codex_rescue.alpha7.surfaces.app_server import AppServerAdapter, RealAppServerClient
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.detector import EnvironmentTopology, SurfaceDetector
from codex_rescue.alpha7.surfaces.ide import IDEAdapter
from codex_rescue.alpha7.surfaces.router import DiagnosticRoute, DiagnosticRouter


@dataclass
class AutopilotResult:
    topology: EnvironmentTopology
    selected_surface: str
    action_taken: str  # "INSPECTED", "SIMULATION_PASSED", "REPAIRED", "ROLLED_BACK", "ROLLBACK_FAILED", "BLOCKED", "NO_REPAIRABLE_TARGETS", "MULTIPLE_REPAIR_TARGETS", "SURFACE_SELECTION_REQUIRED", "CANCELLED"
    diagnostics: List[DiagnosticRoute] = field(default_factory=list)
    transaction: Optional[TransactionResult] = None
    discovered_sessions_count: int = 0
    is_truncated_discovery: bool = False
    invariants: List[InvariantCheckResult] = field(default_factory=list)
    message: str = ""
    observed_surfaces: Dict[str, str] = field(default_factory=dict)
    evidence: Dict[str, Any] = field(default_factory=dict)
    selected_route: str = "INSPECT"
    blocked_actions: List[str] = field(default_factory=list)
    recommended_next_step: str = "Review diagnostic findings"
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "topology": self.topology.to_dict(),
            "selected_surface": self.selected_surface,
            "action_taken": self.action_taken,
            "discovered_sessions_count": self.discovered_sessions_count,
            "is_truncated_discovery": self.is_truncated_discovery,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "transaction": self.transaction.to_dict() if self.transaction else None,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
            "message": self.message,
            "observed_surfaces": self.observed_surfaces,
            "evidence": self.evidence,
            "selected_route": self.selected_route,
            "blocked_actions": self.blocked_actions,
            "recommended_next_step": self.recommended_next_step,
            "confidence": self.confidence,
        }


class AutopilotEngine:
    """Orchestrates end-to-end multi-surface detection, diagnostic routing, and safe repair."""

    def __init__(self, codex_home: Optional[Path] = None):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        self.detector = SurfaceDetector()
        self.desktop_adapter = DesktopAdapter(self.codex_home)
        self.app_server_adapter = AppServerAdapter(self.codex_home)
        self.ide_adapter = IDEAdapter(self.codex_home)
        self.router = DiagnosticRouter(self.codex_home)
        self.repair_engine = TransactionalRepairEngine(self.codex_home)

    def prompt_surface_selection(self, available_surfaces: List[str]) -> str:
        """Prompts user interactively on terminal for surface selection with bounded retries and non-TTY safety."""
        if not sys.stdin.isatty():
            # In non-interactive pipe/script without explicit flag, fail-closed
            return "SURFACE_SELECTION_REQUIRED"

        mapping = {
            "1": "cli",
            "2": "desktop",
            "3": "ide",
            "4": "all",
            "cli": "cli",
            "desktop": "desktop",
            "ide": "ide",
            "all": "all",
            "everything": "all",
        }

        retries = 3
        while retries > 0:
            sys.stdout.write("\nCodex Rescue detected multiple Codex surfaces.\n")
            sys.stdout.write("What do you want to inspect?\n")
            sys.stdout.write("  1. CLI\n")
            sys.stdout.write("  2. Desktop\n")
            sys.stdout.write("  3. IDE / Extension\n")
            sys.stdout.write("  4. Everything\n")
            sys.stdout.write("Select [1-4]: ")
            sys.stdout.flush()

            try:
                line = sys.stdin.readline()
                if not line:  # EOF
                    sys.stdout.write("\n")
                    return "CANCELLED"
                choice = line.strip().lower()
            except (EOFError, KeyboardInterrupt):
                sys.stdout.write("\n")
                return "CANCELLED"

            if choice in mapping:
                return mapping[choice]

            retries -= 1
            if retries > 0:
                sys.stdout.write(f"Invalid selection '{choice}'. Please enter 1, 2, 3, or 4.\n")
            else:
                sys.stdout.write("Too many invalid selections. Aborting surface prompt.\n")
                return "CANCELLED"

        return "CANCELLED"

    def run_autopilot(
        self,
        surface: Optional[str] = None,
        repair_safe: bool = False,
        no_prompt: bool = False,
        target_session: Optional[Path] = None,
    ) -> AutopilotResult:
        # 1. Discover environment topology
        topology = self.detector.detect_all_surfaces(self.codex_home)
        detected_surfaces = [
            s_name for s_name, s_info in topology.surfaces.items() if s_info.available
        ]

        # 2. Determine target surface
        if surface and surface.lower() != "auto":
            selected_surface = surface.lower()
        elif len(detected_surfaces) == 1:
            selected_surface = detected_surfaces[0]
        elif len(detected_surfaces) > 1:
            if no_prompt:
                selected_surface = "all"
            else:
                selected_surface = self.prompt_surface_selection(detected_surfaces)
        else:
            selected_surface = "all"

        if selected_surface == "SURFACE_SELECTION_REQUIRED":
            return AutopilotResult(
                topology=topology,
                selected_surface="unknown",
                action_taken="SURFACE_SELECTION_REQUIRED",
                message="Multiple Codex surfaces detected in non-interactive environment. Explicit selection required: pass --surface <cli|desktop|ide|all> or --no-prompt.",
            )

        if selected_surface == "CANCELLED":
            return AutopilotResult(
                topology=topology,
                selected_surface="cancelled",
                action_taken="CANCELLED",
                message="Autopilot surface selection was cancelled.",
            )

        # 3. Discover all sessions (standard, nested, and archived)
        discovered_sessions, is_trunc = self.desktop_adapter.discover_all_sessions()
        session_count = len(discovered_sessions)

        # 4. Build UnifiedStateGraph according to requested surface
        graph = UnifiedStateGraph()
        app_client = RealAppServerClient(self.codex_home)
        app_server_launched = False

        if selected_surface in ("all", "app_server"):
            if app_client.launch_stdio_server():
                try:
                    app_client.initialize()
                    app_server_launched = True
                except Exception:
                    app_client.shutdown()

        try:
            for s_info in discovered_sessions:
                ns = detect_path_namespace(s_info.path)
                canon = normalize_canonical_path(s_info.path)
                node = ThreadNode(
                    identity=ThreadIdentity(
                        session_id=s_info.session_id,
                        raw_path=str(s_info.path),
                        canonical_path=canon,
                        namespace=ns,
                        is_archived=s_info.is_archived,
                    )
                )

                # CLI / Filesystem probe (runs for cli, desktop, ide, all)
                node.surfaces["cli"] = SurfaceObservation(
                    surface="cli",
                    visibility=SurfaceVisibility.VISIBLE if s_info.path.exists() else SurfaceVisibility.HIDDEN,
                    notes=f"Discovered at {s_info.path}",
                )

                # Desktop probe (runs for desktop and all)
                if selected_surface in ("desktop", "all"):
                    d_diff = self.desktop_adapter.get_session_diff(s_info.session_id)
                    node.surfaces["desktop"] = SurfaceObservation(
                        surface="desktop",
                        visibility=SurfaceVisibility.UNKNOWN if d_diff["sqlite_exists"] else SurfaceVisibility.HIDDEN,
                        notes=f"SQLite matches: {len(d_diff['sqlite_matches'])} (presentation UNKNOWN)",
                    )
                else:
                    node.surfaces["desktop"] = SurfaceObservation(
                        surface="desktop",
                        visibility=SurfaceVisibility.UNSUPPORTED,
                        notes="Surface not selected in routing",
                    )

                # App Server probe (runs for app_server and all)
                if selected_surface in ("app_server", "all"):
                    node.surfaces["app_server"] = self.app_server_adapter.observe_thread(
                        s_info.session_id, client=app_client if app_server_launched else None
                    )
                else:
                    node.surfaces["app_server"] = SurfaceObservation(
                        surface="app_server",
                        visibility=SurfaceVisibility.UNSUPPORTED,
                        notes="Surface not selected in routing",
                    )

                # IDE probe (runs for ide and all)
                if selected_surface in ("ide", "all"):
                    node.surfaces["ide"] = self.ide_adapter.observe_thread(s_info.session_id)
                else:
                    node.surfaces["ide"] = SurfaceObservation(
                        surface="ide",
                        visibility=SurfaceVisibility.UNSUPPORTED,
                        notes="Surface not selected in routing",
                    )

                graph.add_or_update_node(node)
        finally:
            if app_server_launched:
                app_client.shutdown()

        # 5. Diagnostic Routing
        diagnostics = self.router.evaluate_environment(graph)

        # 6. Transactional Repair Target Selection & Execution (INV-012, Section 14, 15)
        tx_result: Optional[TransactionResult] = None
        action_taken = "INSPECTED"
        invariants: List[InvariantCheckResult] = []

        inv_flag = InvariantEngine.check_flags_cannot_bypass_safety(
            yes_flag=False, no_prompt_flag=no_prompt
        )
        invariants.append(inv_flag)

        if repair_safe:
            if target_session:
                tx_result = self.repair_engine.execute_derived_index_repair(target_session)
                action_taken = tx_result.status
                invariants.extend(tx_result.invariants)
            else:
                # Find only sessions with registered diagnostic findings
                repairable_sessions = []
                for s in discovered_sessions:
                    diff = self.desktop_adapter.get_session_diff(s.session_id)
                    if not diff["sqlite_exists"]:
                        repairable_sessions.append(s)

                if len(repairable_sessions) == 0:
                    action_taken = "NO_REPAIRABLE_TARGETS"
                elif len(repairable_sessions) == 1:
                    tx_result = self.repair_engine.execute_derived_index_repair(repairable_sessions[0].path)
                    action_taken = tx_result.status
                    invariants.extend(tx_result.invariants)
                elif no_prompt:
                    action_taken = "MULTIPLE_REPAIR_TARGETS"
                else:
                    # In interactive mode when multiple targets exist, do NOT blindly fallback to [0]
                    action_taken = "MULTIPLE_REPAIR_TARGETS"

        msg = (
            f"Autopilot analyzed {session_count} sessions across surface '{selected_surface}'"
            + (" (discovery truncated at limit)" if is_trunc else ".")
        )

        observed_surfaces = {k: v.status for k, v in topology.surfaces.items()}
        blocked_actions = []
        if not repair_safe:
            blocked_actions.append("MUTATION_HEURISTIC_OFF")
        for d in diagnostics:
            blocked_actions.extend(d.blocked_actions)

        recommendations = [d.recommendation for d in diagnostics if d.recommendation]
        recommended_next = (
            recommendations[0] if recommendations else "Review diagnostic findings; all systems inspected safely."
        )

        return AutopilotResult(
            topology=topology,
            selected_surface=selected_surface,
            action_taken=action_taken,
            diagnostics=diagnostics,
            transaction=tx_result,
            discovered_sessions_count=session_count,
            is_truncated_discovery=is_trunc,
            invariants=invariants,
            message=msg,
            observed_surfaces=observed_surfaces,
            evidence={
                "session_count": session_count,
                "diagnostics_count": len(diagnostics),
                "is_truncated": is_trunc,
            },
            selected_route=f"ROUTE_{selected_surface.upper()}",
            blocked_actions=sorted(list(set(blocked_actions))),
            recommended_next_step=recommended_next,
            confidence="HIGH" if not is_trunc else "MEDIUM",
        )
