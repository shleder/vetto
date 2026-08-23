from __future__ import annotations

import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from codex_rescue.alpha7.compatibility.portable import PortableSessionEngine
from codex_rescue.alpha7.invariants import InvariantId, InvariantStatus
from codex_rescue.alpha7.recovery.backup import BackupEngine
from codex_rescue.alpha7.simulation.transaction import (
    SchemaFingerprint,
    TransactionalRepairEngine,
    compute_file_sha256,
)
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter, ProbeOutcome, ProcessProbeResult, WriterStatus


class MutationNegativeAndRollbackTests(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.codex_home = Path(self.td.name)
        (self.codex_home / "sessions").mkdir(parents=True, exist_ok=True)
        self.session_file = self.codex_home / "sessions" / "rollout-2026-08-18T10-00-00-11111111-2222-3333-4444-555555555555.jsonl"
        self.session_file.write_text('{"turn": 1, "type": "session_meta"}\n', encoding="utf-8")

    def tearDown(self):
        self.td.cleanup()

    def _setup_valid_state_db(self) -> Path:
        state_db = self.codex_home / "state_5.sqlite"
        conn = sqlite3.connect(str(state_db))
        conn.execute("PRAGMA user_version = 5")
        conn.execute(
            """
            CREATE TABLE threads (
                id TEXT PRIMARY KEY,
                rollout_path TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
        conn.close()
        return state_db

    def test_writer_active_blocks_mutation(self):
        self._setup_valid_state_db()
        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.ACTIVE_CONFIRMED):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "BLOCKED")
            self.assertTrue(res.source_preserved)
            self.assertIn("writer state is ACTIVE_CONFIRMED", res.message)

    def test_writer_unknown_probe_error_blocks_mutation(self):
        self._setup_valid_state_db()
        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(
            engine.desktop_adapter,
            "detect_running_processes_detailed",
            return_value=ProcessProbeResult(status=ProbeOutcome.ERROR, error="Access Denied on process probe"),
        ):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "BLOCKED")
            self.assertTrue(res.source_preserved)
            self.assertIn("UNKNOWN", res.message)

    def test_missing_state_db_blocks_mutation_without_synthetic_manufacture(self):
        """Ensures Rescue refuses to manufacture a synthetic state_5.sqlite when none exists."""
        state_db = self.codex_home / "state_5.sqlite"
        if state_db.exists():
            state_db.unlink()

        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "BLOCKED")
            self.assertFalse(state_db.exists(), "Rescue illegally manufactured synthetic state_5.sqlite!")
            self.assertIn("Target state database does not exist", res.message)

    def test_missing_threads_table_blocks_mutation(self):
        state_db = self.codex_home / "state_5.sqlite"
        conn = sqlite3.connect(str(state_db))
        conn.execute("CREATE TABLE other_table (id TEXT)")
        conn.commit()
        conn.close()

        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "BLOCKED")
            self.assertIn("threads table is missing", res.message)

    def test_existing_thread_id_blocks_destructive_overwrite(self):
        state_db = self._setup_valid_state_db()
        conn = sqlite3.connect(str(state_db))
        conn.execute(
            "INSERT INTO threads (id, rollout_path, created_at, updated_at) VALUES (?, ?, ?, ?)",
            ("11111111-2222-3333-4444-555555555555", "/existing/path.jsonl", 1000, 1000),
        )
        conn.commit()
        conn.close()

        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "BLOCKED")
            self.assertIn("already exists in threads table", res.message)

    def test_stale_plan_detected_and_aborted(self):
        self._setup_valid_state_db()
        engine = TransactionalRepairEngine(self.codex_home)

        # Mutate file during backup step to simulate concurrent alteration
        orig_backup = engine.backup_engine.create_pre_mutation_backup

        def concurrent_alteration(targets, operation_id=None):
            manifest = orig_backup(targets, operation_id=operation_id)
            self.session_file.write_text('{"turn": 2, "modified": true}\n', encoding="utf-8")
            return manifest

        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            with patch.object(engine.backup_engine, "create_pre_mutation_backup", side_effect=concurrent_alteration):
                res = engine.execute_derived_index_repair(self.session_file)
                self.assertEqual(res.status, "STALE_PLAN")
                self.assertIn("Source rollout changed immediately prior to mutation", res.message)

    def test_successful_repair_and_post_verification(self):
        state_db = self._setup_valid_state_db()
        engine = TransactionalRepairEngine(self.codex_home)
        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            res = engine.execute_derived_index_repair(self.session_file)
            self.assertEqual(res.status, "REPAIRED")
            self.assertEqual(res.applied_mutations_count, 1)

            # Check DB row
            conn = sqlite3.connect(str(state_db))
            cur = conn.cursor()
            cur.execute("SELECT rollout_path FROM threads WHERE id = ?", ("11111111-2222-3333-4444-555555555555",))
            row = cur.fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(Path(row[0]).resolve(), self.session_file.resolve())
            conn.close()

    def test_rollback_failed_status_when_backup_corrupted(self):
        state_db = self._setup_valid_state_db()
        engine = TransactionalRepairEngine(self.codex_home)

        real_connect = sqlite3.connect

        def faulty_connect(*args, **kwargs):
            # If timeout is 5.0 (the mutation step), raise operational error
            if kwargs.get("timeout") == 5.0:
                raise sqlite3.OperationalError("Disk I/O failure during mutation")
            return real_connect(*args, **kwargs)

        with patch.object(engine.desktop_adapter, "detect_writer_status", return_value=WriterStatus.INACTIVE_CONFIRMED):
            # Force rollback failure by mocking rollback to return False
            with patch.object(engine.backup_engine, "rollback", return_value=False):
                with patch("sqlite3.connect", side_effect=faulty_connect):
                    res = engine.execute_derived_index_repair(self.session_file)
                    self.assertEqual(res.status, "ROLLBACK_FAILED")
                    self.assertIn("CRITICAL", res.message)


if __name__ == "__main__":
    unittest.main()
