from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.storage_health import (
    LargeRolloutInfo,
    StorageHealthEngine,
    StorageHealthLimits,
    StorageHealthReport,
)


class StorageHealthTests(unittest.TestCase):
    def test_missing_codex_home_returns_unknown_status(self) -> None:
        rep = StorageHealthEngine.scan_codex_home(Path("/nonexistent/codex/home"))
        self.assertEqual(rep.codex_home_bytes_status, "UNKNOWN")
        self.assertIsNone(rep.codex_home_bytes)

    def test_scans_sessions_and_state_dbs_accurately(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sdir = home / "sessions"
            adir = home / "archived_sessions"
            sdir.mkdir()
            adir.mkdir()

            uuid1 = "11111111-2222-3333-4444-555555555555"
            uuid2 = "22222222-3333-4444-5555-666666666666"

            f1 = sdir / f"rollout-2026-08-19T12-00-00-{uuid1}.jsonl"
            f1.write_text('{"turn":1}\n' * 100, encoding="utf-8")

            f2 = adir / f"rollout-2026-08-19T12-00-00-{uuid2}.jsonl"
            f2.write_text('{"turn":1}\n' * 50, encoding="utf-8")

            db = home / "state_5.sqlite"
            db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 1000)

            rep = StorageHealthEngine.scan_codex_home(home)
            self.assertEqual(rep.codex_home_bytes_status, "MEASURED")
            self.assertEqual(rep.sessions_count, 1)
            self.assertEqual(rep.archived_sessions_count, 1)
            self.assertIn("state_5.sqlite", rep.state_db_sizes)
            self.assertGreater(rep.rollout_bytes_total, 0)
            self.assertFalse(rep.scan_truncated)

    def test_detects_large_rollout_with_resolved_identity(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sdir = home / "sessions"
            sdir.mkdir()

            uuid = "33333333-4444-5555-6666-777777777777"
            large_file = sdir / f"rollout-2026-08-19T12-00-00-{uuid}.jsonl"
            # 1MB file with custom 500KB threshold
            large_file.write_bytes(b"X" * 1_000_000)

            limits = StorageHealthLimits(large_file_threshold_bytes=500_000)
            rep = StorageHealthEngine.scan_codex_home(home, limits=limits)
            self.assertEqual(len(rep.large_rollouts), 1)
            self.assertEqual(rep.large_rollouts[0].thread_id, uuid)
            self.assertEqual(rep.large_rollouts[0].bytes, 1_000_000)

    def test_bounded_scan_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sdir = home / "sessions"
            sdir.mkdir()

            for i in range(10):
                (sdir / f"rollout_{i}.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            limits = StorageHealthLimits(max_files=5)
            rep = StorageHealthEngine.scan_codex_home(home, limits=limits)
            self.assertTrue(rep.scan_truncated)
            self.assertEqual(rep.codex_home_bytes_status, "ESTIMATED")


if __name__ == "__main__":
    unittest.main()
