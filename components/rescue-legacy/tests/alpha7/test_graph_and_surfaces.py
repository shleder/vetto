from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

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
from codex_rescue.alpha7.surfaces.app_server import AppServerAdapter
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.detector import SurfaceDetector
from codex_rescue.alpha7.surfaces.ide import IDEAdapter
from codex_rescue.alpha7.surfaces.router import DiagnosticRouter


class GraphAndSurfacesTests(unittest.TestCase):
    def test_path_namespace_detection(self):
        self.assertEqual(detect_path_namespace(r"C:\src\project"), PathNamespace.WINDOWS_STANDARD)
        self.assertEqual(detect_path_namespace(r"\\?\C:\src\project"), PathNamespace.WINDOWS_EXTENDED)
        self.assertEqual(detect_path_namespace(r"\\server\share\file"), PathNamespace.WINDOWS_UNC)
        self.assertEqual(detect_path_namespace(r"\\?\UNC\server\share\file"), PathNamespace.WINDOWS_EXTENDED_UNC)
        self.assertEqual(detect_path_namespace("/mnt/c/src/project"), PathNamespace.WSL_MNT)
        self.assertEqual(detect_path_namespace("/home/user/project"), PathNamespace.POSIX_STANDARD)

    def test_normalize_canonical_path(self):
        self.assertEqual(normalize_canonical_path(r"C:\src\project\..\project"), "C:/src/project")
        self.assertEqual(normalize_canonical_path(r"\\?\C:\src\project"), "C:/src/project")

    def test_unified_state_graph_coalescence_and_divergence(self):
        graph = UnifiedStateGraph()
        node1 = ThreadNode(
            identity=ThreadIdentity(
                session_id="sess_001",
                raw_path=r"C:\src\sess_001.jsonl",
                canonical_path="C:/src/sess_001.jsonl",
                namespace=PathNamespace.WINDOWS_STANDARD,
            )
        )
        node1.surfaces["cli"] = SurfaceObservation("cli", SurfaceVisibility.VISIBLE)
        node1.surfaces["desktop"] = SurfaceObservation("desktop", SurfaceVisibility.HIDDEN)

        graph.add_or_update_node(node1)
        self.assertEqual(graph.get_by_session_id("sess_001"), node1)
        self.assertEqual(graph.get_by_path(r"\\?\C:\src\sess_001.jsonl"), node1)
        self.assertTrue(node1.has_cross_surface_divergence)
        self.assertEqual(len(graph.get_cross_surface_divergences()), 1)

    def test_surface_detector_discovery(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            (chome / "sessions").mkdir()
            (chome / "state.db").write_text("", encoding="utf-8")

            topo = SurfaceDetector.detect_topology(chome)
            self.assertTrue(topo.surfaces["cli"].available)
            self.assertTrue(topo.surfaces["desktop"].available)
            self.assertGreaterEqual(topo.detected_surface_count, 2)

    def test_desktop_adapter_report_and_diff(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            sdir = chome / "sessions"
            sdir.mkdir()
            sess_uuid = "11111111-2222-3333-4444-555555555555"
            (sdir / f"rollout-2026-08-19T12-00-00-{sess_uuid}.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            adapter = DesktopAdapter(chome)
            rep = adapter.get_status()
            self.assertEqual(rep.filesystem_threads_count, 1)
            self.assertEqual(rep.sqlite_threads_count, 0)
            self.assertEqual(rep.filesystem_only_count, 1)
            self.assertEqual(rep.overall_status, "DEGRADED")

            diff = adapter.get_session_diff(sess_uuid)
            self.assertTrue(diff["filesystem_exists"])
            self.assertFalse(diff["sqlite_exists"])
            self.assertEqual(diff["status"], "DIVERGENT")

    def test_app_server_graceful_fallback_when_offline(self):
        with tempfile.TemporaryDirectory() as td:
            adapter = AppServerAdapter(Path(td))
            status = adapter.probe_server()
            self.assertFalse(status.reachable)

            obs = adapter.observe_thread("any_thread")
            self.assertEqual(obs.visibility, SurfaceVisibility.UNSUPPORTED)

    def test_ide_adapter_graceful_fallback(self):
        with tempfile.TemporaryDirectory() as td:
            adapter = IDEAdapter(Path(td))
            obs = adapter.observe_thread("any_thread")
            self.assertIn(obs.visibility, (SurfaceVisibility.UNSUPPORTED, SurfaceVisibility.UNKNOWN))

    def test_diagnostic_router_classifies_unindexed_thread(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            sdir = chome / "sessions"
            sdir.mkdir()
            sfile = sdir / "rollout-2026-08-19T12-00-00-11111111-2222-3333-4444-555555555555.jsonl"
            sfile.write_text('{"turn":1}\n', encoding="utf-8")

            router = DiagnosticRouter(chome)
            route = router.route_session(sfile)
            self.assertIn("UNINDEXED_IN_SQLITE", route.findings)
            self.assertEqual(route.root_cause_layer, "DERIVED_SQLITE_INDEX")


if __name__ == "__main__":
    unittest.main()
