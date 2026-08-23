from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.storage_health import (
    StorageHealthEngine,
    StorageHealthLimits,
)


class StorageHealthStreamingTests(unittest.TestCase):
    def test_streaming_oversized_record_detection_zero_whole_file_memory(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_file = Path(td) / "rollout-2026-08-21T10-00-00-11111111-2222-3333-4444-555555555555.jsonl"

            # Write a small line followed by a 2MB single line (exceeding 1MB threshold)
            # using buffered chunks
            with open(session_file, "wb") as f:
                f.write(b'{"turn": 1, "type": "start"}\n')
                # 2MB of payload in a single line
                chunk = b'{"type": "huge", "data": "' + b"A" * 65500
                f.write(chunk)
                for _ in range(32):
                    f.write(b"A" * 65536)
                f.write(b'"}\n')
                f.write(b'{"turn": 2, "type": "end"}\n')

            # Threshold 1MB
            max_rec, over_cnt = StorageHealthEngine.scan_oversized_records_streaming(
                session_file,
                threshold_bytes=1024 * 1024,
            )

            self.assertEqual(over_cnt, 1)
            self.assertGreater(max_rec, 2 * 1024 * 1024)

    def test_scan_codex_home_detects_streaming_duplicates_and_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sdir = home / "sessions"
            adir = home / "archived_sessions"
            sdir.mkdir()
            adir.mkdir()

            uuid1 = "11111111-2222-3333-4444-555555555555"
            uuid2 = "22222222-3333-4444-5555-666666666666"

            f1 = sdir / f"rollout-2026-08-21T10-00-00-{uuid1}.jsonl"
            # Write 100KB file
            content = b'{"turn": 1, "payload": "data"}\n' * 3000
            f1.write_bytes(content)

            # Duplicate file with different name in archived_sessions
            f2 = adir / f"rollout-2026-08-21T10-00-00-{uuid2}.jsonl"
            f2.write_bytes(content)

            limits = StorageHealthLimits(
                large_file_threshold_bytes=50_000,
                oversized_record_threshold_bytes=1_000_000,
            )

            report = StorageHealthEngine.scan_codex_home(home, limits=limits)

            self.assertFalse(report.scan_truncated)
            self.assertFalse(report.truncated_by_limit)
            self.assertEqual(len(report.large_rollouts), 2)
            self.assertEqual(len(report.duplicate_physical_sources), 1)
            self.assertEqual(len(report.duplicate_physical_sources[0]["paths"]), 2)

    def test_scan_codex_home_limit_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sdir = home / "sessions"
            sdir.mkdir()

            for i in range(10):
                (sdir / f"rollout_{i}.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            limits = StorageHealthLimits(max_files=3)
            report = StorageHealthEngine.scan_codex_home(home, limits=limits)

            self.assertTrue(report.scan_truncated)
            self.assertTrue(report.truncated_by_limit)
            self.assertEqual(report.codex_home_bytes_status, "ESTIMATED")


if __name__ == "__main__":
    unittest.main()
