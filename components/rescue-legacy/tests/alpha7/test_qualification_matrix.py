from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.blackbox.recorder import BlackBoxRecorder, EventType
from codex_rescue.alpha7.compatibility.engine import CompatibilityEngine
from codex_rescue.alpha7.graph import (
    PathNamespace,
    StorageProfile,
    SurfaceObservation,
    SurfaceVisibility,
    ThreadIdentity,
    ThreadNode,
    UnifiedStateGraph,
)
from codex_rescue.alpha7.invariants import (
    InvariantCheckResult,
    InvariantEngine,
    InvariantEvaluation,
    InvariantId,
    InvariantStatus,
)
from codex_rescue.alpha7.privacy.redaction import PrivacyRedactionEngine
from codex_rescue.alpha7.recovery.backup import BackupEngine
from codex_rescue.alpha7.recovery.salvage_stream import StreamSalvageEngine
from codex_rescue.alpha7.simulation.simulator import RepairSimulator
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter
from codex_rescue.alpha7.surfaces.detector import SurfaceDetector


class QualificationMatrixTests(unittest.TestCase):
    def test_inv_evaluation_aggregate_all_passed(self):
        c1 = InvariantCheckResult(InvariantId.INV_001, InvariantStatus.PASS, "ok")
        c2 = InvariantCheckResult(InvariantId.INV_002, InvariantStatus.PASS, "ok")
        eval_res = InvariantEvaluation([c1, c2])
        self.assertTrue(eval_res.all_passed)
        self.assertEqual(len(eval_res.failures), 0)

    def test_inv_evaluation_aggregate_with_failures(self):
        c1 = InvariantCheckResult(InvariantId.INV_001, InvariantStatus.PASS, "ok")
        c2 = InvariantCheckResult(InvariantId.INV_003, InvariantStatus.FAIL, "Active writer lock")
        eval_res = InvariantEvaluation([c1, c2])
        self.assertFalse(eval_res.all_passed)
        self.assertEqual(len(eval_res.failures), 1)
        self.assertEqual(eval_res.failures[0].invariant_id, InvariantId.INV_003)

    def test_storage_amplification_profile(self):
        profile = StorageProfile(
            total_bytes=31_000_000_000,
            record_count=1000,
            largest_record_bytes=521_000_000,
            inline_image_bytes=23_000_000_000,
            tool_output_bytes=4_000_000_000,
            compaction_product_bytes=3_000_000_000,
            other_bytes=1_000_000_000,
            amplification_ratio=12.8,
        )
        d = profile.to_dict()
        self.assertEqual(d["total_bytes"], 31_000_000_000)
        self.assertEqual(d["amplification_ratio"], 12.8)

    def test_reinstallation_recovery_synthetic_case(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            sdir = chome / "sessions"
            sdir.mkdir()
            (sdir / "saved_session.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            # SQLite is lost (no state.db)
            adapter = DesktopAdapter(chome)
            rep = adapter.get_status()
            self.assertEqual(rep.filesystem_threads_count, 1)
            self.assertEqual(rep.sqlite_threads_count, 0)
            self.assertEqual(rep.filesystem_only_count, 1)

            # Proves derived state recoverable without data loss
            self.assertEqual(rep.data_loss_evidence, "NONE")

    def test_privacy_redaction_removes_various_api_keys(self):
        samples = [
            "sk-123456789012345678901234567890",
            "gho_abcdef1234567890abcdef123456",
            "bearer: 'xyz987654321012345678'",
        ]
        for s in samples:
            san, audit = PrivacyRedactionEngine.sanitize_text(s)
            self.assertNotIn("sk-1234", san)
            self.assertNotIn("gho_abc", san)
            self.assertTrue(audit.passed_validation)

    def test_update_guard_detects_version_change(self):
        recorder = BlackBoxRecorder()
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            sdir = chome / "sessions"
            sdir.mkdir()
            (sdir / "s1.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            snap_before = recorder.create_snapshot(chome)
            snap_before.codex_version = "26.1"

            # Upgrade simulation: modify session
            (sdir / "s1.jsonl").write_text('{"turn":1}\n{"turn":2}\n', encoding="utf-8")
            snap_after = recorder.create_snapshot(chome)
            snap_after.codex_version = "26.2"

            diff = recorder.compare_snapshots(snap_before, snap_after)
            self.assertEqual(len(diff["modified_sessions"]), 1)


if __name__ == "__main__":
    unittest.main()
