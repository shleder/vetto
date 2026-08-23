from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.blackbox.fingerprint import FingerprintEngine
from codex_rescue.alpha7.blackbox.incident import IncidentEngine
from codex_rescue.alpha7.blackbox.recorder import BlackBoxRecorder, EventType
from codex_rescue.alpha7.blackbox.reproducer import ReproducerEngine
from codex_rescue.alpha7.compatibility.engine import CompatibilityEngine
from codex_rescue.alpha7.compatibility.path_remap import PathRemappingEngine
from codex_rescue.alpha7.compatibility.portable import PortableSessionEngine
from codex_rescue.alpha7.graph import (
    PathNamespace,
    SurfaceObservation,
    SurfaceVisibility,
    ThreadIdentity,
    ThreadNode,
    UnifiedStateGraph,
    detect_path_namespace,
)
from codex_rescue.alpha7.invariants import InvariantCheckResult, InvariantEngine, InvariantId, InvariantStatus
from codex_rescue.alpha7.privacy.redaction import PrivacyRedactionEngine
from codex_rescue.alpha7.recovery.backup import BackupEngine
from codex_rescue.alpha7.recovery.salvage_stream import StreamSalvageEngine
from codex_rescue.alpha7.simulation.simulator import RepairSimulator
from codex_rescue.alpha7.surfaces.app_server import AppServerAdapter
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.detector import SurfaceDetector
from codex_rescue.alpha7.surfaces.ide import IDEAdapter
from codex_rescue.alpha7.surfaces.router import DiagnosticRouter


class DeepEdgeCasesTests(unittest.TestCase):
    def test_null_bytes_in_source_fails_accounting(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "null_bytes.jsonl"
            f.write_bytes(b'{"turn": 1}\x00\x00\x00{"turn": 2}\n')
            res = StreamSalvageEngine().scan_file(f)
            self.assertEqual(res.source_status, "CORRUPTED")
            self.assertGreater(res.malformed_records_count, 0)

    def test_active_writer_pid_namespace_tracking(self):
        inv = InvariantEngine.check_active_writer(
            has_active_writer=True, writer_pid=9999, is_mutation_operation=True
        )
        self.assertFalse(inv.passed)
        self.assertEqual(inv.evidence["writer_pid"], 9999)

    def test_multiple_divergent_surfaces(self):
        graph = UnifiedStateGraph()
        node = ThreadNode(
            identity=ThreadIdentity("sess_multi", "C:/s.jsonl", "C:/s.jsonl", PathNamespace.WINDOWS_STANDARD)
        )
        node.surfaces["cli"] = SurfaceObservation("cli", SurfaceVisibility.VISIBLE)
        node.surfaces["desktop"] = SurfaceObservation("desktop", SurfaceVisibility.HIDDEN)
        node.surfaces["app_server"] = SurfaceObservation("app_server", SurfaceVisibility.VISIBLE)
        node.surfaces["ide"] = SurfaceObservation("ide", SurfaceVisibility.INACCESSIBLE)

        graph.add_or_update_node(node)
        self.assertTrue(node.has_cross_surface_divergence)

    def test_privacy_redacts_nested_github_and_openai_tokens(self):
        dirty = "Token ghp_123456789012345678901234567890123456 and sk-abcdef1234567890abcdef123456"
        clean, audit = PrivacyRedactionEngine.sanitize_text(dirty)
        self.assertNotIn("ghp_", clean)
        self.assertNotIn("sk-", clean)
        self.assertEqual(audit.secrets_found_and_redacted, 2)
        self.assertTrue(audit.passed_validation)

    def test_path_remap_unc_extended(self):
        res = PathRemappingEngine.translate_path(r"\\?\UNC\server\share\file.txt", target_platform="windows")
        self.assertEqual(res.source_namespace, PathNamespace.WINDOWS_EXTENDED_UNC)

    def test_portable_export_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            PortableSessionEngine.export_session(Path("nonexistent_file.jsonl"), Path("out.zip"))

    def test_portable_inspect_invalid_zip_raises(self):
        with tempfile.TemporaryDirectory() as td:
            bad_zip = Path(td) / "bad.zip"
            bad_zip.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # Empty zip
            with self.assertRaises(ValueError):
                PortableSessionEngine.inspect_package(bad_zip)

    def test_simulation_source_immutability_failure_if_modified(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "rollout.jsonl"
            f.write_text('{"turn":1}\n', encoding="utf-8")
            res = RepairSimulator.simulate_derived_index_repair(f)
            self.assertTrue(res.source_preserved)
            self.assertTrue(res.safe_to_apply)

    def test_timeline_reconstruction_with_multiple_anomalies(self):
        recorder = BlackBoxRecorder()
        e1 = recorder.record_event(EventType.ROLLOUT_CREATED, session_id="t1")
        e2 = recorder.record_event(EventType.PROJECTION_CURSOR_ADVANCED, session_id="t1")
        e3 = recorder.record_event(EventType.PROJECTION_CURSOR_REGRESSED, session_id="t1", details={"error": "Regression"})
        e4 = recorder.record_event(EventType.PROJECTION_CURSOR_STOPPED, session_id="t1", details={"error": "Stopped"})

        engine = IncidentEngine()
        report = engine.analyze_events("inc_t1", [e1, e2, e3, e4])
        self.assertEqual(report.anomalies_count, 2)
        self.assertEqual(report.first_known_bad_time, e3.timestamp)
        self.assertEqual(report.last_known_good_time, e2.timestamp)

    def test_reproducer_minimizer_preserves_single_defect(self):
        rep = ReproducerEngine.create_reproducer("WEDGED_CURSOR", total_records=1000, inject_defect_at=500)
        minimized = ReproducerEngine.minimize_reproducer(rep)
        self.assertLessEqual(minimized.total_records, 5)
        self.assertTrue(any(r.is_malformed for r in minimized.records))

    def test_stream_salvage_gigantic_record_attribution(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "giant.jsonl"
            giant_str = "G" * 500_000
            f.write_text(f'{{"turn":1,"giant":"{giant_str}"}}\n', encoding="utf-8")
            res = StreamSalvageEngine(oversized_threshold=100_000).scan_file(f)
            self.assertEqual(res.oversized_records_count, 1)
            self.assertGreaterEqual(res.largest_record_bytes, 500_000)


if __name__ == "__main__":
    unittest.main()
