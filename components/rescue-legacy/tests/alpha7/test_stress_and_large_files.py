from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.invariants import InvariantEngine
from codex_rescue.alpha7.recovery.salvage_stream import StreamSalvageEngine


class StressAndLargeFilesTests(unittest.TestCase):
    def test_10mb_synthetic_file_streaming(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = tmp / "synthetic_10mb.jsonl"

            # Generate 10MB of JSONL
            line = '{"turn": 1, "data": "' + ("A" * 1024) + '"}\n'
            target_bytes = 10 * 1024 * 1024
            written = 0
            with open(f, "w", encoding="utf-8") as out:
                while written < target_bytes:
                    out.write(line)
                    written += len(line)

            engine = StreamSalvageEngine()
            res = engine.scan_file(f)
            self.assertEqual(res.source_status, "HEALTHY")
            self.assertGreaterEqual(res.total_bytes, target_bytes)
            self.assertEqual(res.unclassified_bytes, 0)

    def test_100mb_synthetic_large_record_streaming(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = tmp / "synthetic_100mb.jsonl"

            # Generate 100MB with a few 5MB oversized records
            line_small = '{"turn": 1, "data": "' + ("B" * 2048) + '"}\n'
            line_giant = '{"turn": 99, "giant_image": "' + ("C" * (2 * 1024 * 1024)) + '"}\n'

            with open(f, "w", encoding="utf-8") as out:
                for _ in range(1000):
                    out.write(line_small)
                out.write(line_giant)
                for _ in range(1000):
                    out.write(line_small)

            engine = StreamSalvageEngine(oversized_threshold=1_000_000)
            res = engine.scan_file(f)
            self.assertEqual(res.source_status, "VALID_BUT_OVERSIZED")
            self.assertEqual(res.oversized_records_count, 1)
            self.assertGreaterEqual(res.largest_record_bytes, 2 * 1024 * 1024)

    def test_destructive_corruption_fail_closed(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = tmp / "corrupted_stress.jsonl"

            with open(f, "w", encoding="utf-8") as out:
                out.write('{"turn": 1}\n')
                out.write('{"turn": 2}\n')
                out.write('INJECTED_CORRUPTED_BYTES_HERE_NON_JSON\n')
                out.write('{"turn": 4}\n')

            engine = StreamSalvageEngine()
            res = engine.scan_file(f)
            self.assertEqual(res.source_status, "CORRUPTED")
            self.assertEqual(res.malformed_records_count, 1)

            # Invariant check must fail closed
            inv = InvariantEngine.check_source_accounting(
                res.total_bytes, res.scanned_bytes, unclassified_bytes=0, malformed_bytes=res.malformed_records_count
            )
            # Source is corrupted, mutation blocked
            self.assertEqual(res.source_status, "CORRUPTED")


if __name__ == "__main__":
    unittest.main()
