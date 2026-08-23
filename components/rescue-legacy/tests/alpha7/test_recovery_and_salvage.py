from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.recovery.backup import BackupEngine
from codex_rescue.alpha7.recovery.salvage_stream import StreamSalvageEngine


class RecoveryAndSalvageTests(unittest.TestCase):
    def test_backup_and_atomic_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "session.jsonl"
            f1.write_text('{"turn":1}\n', encoding="utf-8")

            b_engine = BackupEngine(backup_root=tmp / "backups")
            manifest = b_engine.create_pre_mutation_backup([f1])
            self.assertTrue(manifest.verified)
            self.assertEqual(len(manifest.entries), 1)

            # Mutate original file
            f1.write_text('{"turn":2,"modified":true}\n', encoding="utf-8")
            self.assertIn("modified", f1.read_text(encoding="utf-8"))

            # Rollback
            ok = b_engine.rollback(manifest)
            self.assertTrue(ok)
            self.assertEqual(f1.read_text(encoding="utf-8"), '{"turn":1}\n')

    def test_backup_corrupted_backup_fails_rollback(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "session.jsonl"
            f1.write_text('{"turn":1}\n', encoding="utf-8")

            b_engine = BackupEngine(backup_root=tmp / "backups")
            manifest = b_engine.create_pre_mutation_backup([f1])

            # Corrupt the backup file itself
            backup_file = Path(manifest.entries[0].backup_path)
            backup_file.write_text("CORRUPTED_BACKUP", encoding="utf-8")

            # Rollback must be blocked per INV-008
            ok = b_engine.rollback(manifest)
            self.assertFalse(ok)

    def test_stream_salvage_clean_file(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "clean.jsonl"
            f1.write_text('{"turn":1}\n{"turn":2}\n{"turn":3}\n', encoding="utf-8")

            engine = StreamSalvageEngine()
            res = engine.scan_file(f1)
            self.assertEqual(res.source_status, "HEALTHY")
            self.assertEqual(res.valid_records_count, 3)
            self.assertEqual(res.malformed_records_count, 0)
            self.assertEqual(res.unclassified_bytes, 0)

    def test_stream_salvage_oversized_record(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "oversized.jsonl"
            big_payload = "x" * 2000
            f1.write_text(f'{{"turn":1,"big":"{big_payload}"}}\n', encoding="utf-8")

            engine = StreamSalvageEngine(oversized_threshold=1000)
            res = engine.scan_file(f1)
            self.assertEqual(res.source_status, "VALID_BUT_OVERSIZED")
            self.assertEqual(res.oversized_records_count, 1)

    def test_stream_salvage_truncated_tail(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "truncated.jsonl"
            f1.write_text('{"turn":1}\n{"turn":2}\n{"turn":3, "incomp', encoding="utf-8")

            engine = StreamSalvageEngine()
            res = engine.scan_file(f1)
            self.assertEqual(res.source_status, "TRUNCATED_TRANSCRIPT")
            self.assertTrue(res.has_truncated_tail)
            self.assertEqual(res.valid_records_count, 2)
            self.assertGreater(res.valid_prefix_bytes, 0)

    def test_stream_salvage_mid_file_corruption(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f1 = tmp / "corrupt_mid.jsonl"
            f1.write_text('{"turn":1}\nMALFORMED_JSON_MIDDLE\n{"turn":3}\n', encoding="utf-8")

            engine = StreamSalvageEngine()
            res = engine.scan_file(f1)
            self.assertEqual(res.source_status, "CORRUPTED")
            self.assertEqual(res.malformed_records_count, 1)


if __name__ == "__main__":
    unittest.main()
