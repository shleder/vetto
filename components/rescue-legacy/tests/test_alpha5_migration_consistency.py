import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from codex_rescue.doctor import doctor_session
from codex_rescue.migration_consistency import inspect_migration_consistency
from codex_rescue.transcript import parse_transcript


class Alpha5MigrationConsistencyTests(unittest.TestCase):
    THREAD_ID = "019fffff-2222-7222-8222-222222222222"

    @staticmethod
    def _session_path(root: Path) -> Path:
        session_dir = root / "sessions" / "2026" / "08" / "18"
        session_dir.mkdir(parents=True, exist_ok=True)
        return session_dir / f"rollout-2026-08-18T00-00-00-{Alpha5MigrationConsistencyTests.THREAD_ID}.jsonl"

    def test_subagent_boundary_at_eof_is_suspect_not_data_loss_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._session_path(root)
            records = [
                {
                    "type": "session_meta",
                    "ordinal": 0,
                    "payload": {
                        "id": self.THREAD_ID,
                        "session_id": self.THREAD_ID,
                        "history_mode": "paginated",
                        "subagent_history_start_ordinal": 3,
                    },
                },
                {
                    "type": "response_item",
                    "ordinal": 1,
                    "payload": {"type": "message", "role": "user", "content": "child-local"},
                },
                {
                    "type": "response_item",
                    "ordinal": 2,
                    "payload": {"type": "message", "role": "assistant", "content": "reply"},
                },
            ]
            path.write_text(
                "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
                encoding="utf-8",
            )
            report = inspect_migration_consistency(path, parse_transcript(path))
            self.assertTrue(report.subagent_boundary_suspect)
            self.assertIn("SUBAGENT_HISTORY_BOUNDARY_SUSPECT", report.findings)
            diagnosis = doctor_session(path)
            self.assertIn("SUBAGENT_HISTORY_BOUNDARY_SUSPECT", diagnosis.findings)

    def test_valid_subagent_boundary_is_not_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._session_path(root)
            records = [
                {
                    "type": "session_meta",
                    "ordinal": 0,
                    "payload": {
                        "id": self.THREAD_ID,
                        "session_id": self.THREAD_ID,
                        "history_mode": "paginated",
                        "subagent_history_start_ordinal": 1,
                    },
                },
                {
                    "type": "response_item",
                    "ordinal": 1,
                    "payload": {"type": "message", "role": "user", "content": "child-local"},
                },
            ]
            path.write_text(
                "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
                encoding="utf-8",
            )
            report = inspect_migration_consistency(path, parse_transcript(path))
            self.assertFalse(report.subagent_boundary_suspect)

    def test_paginated_sqlite_missing_name_while_index_has_name_is_divergence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._session_path(root)
            path.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "ordinal": 0,
                        "payload": {
                            "id": self.THREAD_ID,
                            "session_id": self.THREAD_ID,
                            "history_mode": "paginated",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "session_index.jsonl").write_text(
                json.dumps(
                    {
                        "id": self.THREAD_ID,
                        "thread_name": "private synthetic name",
                        "updated_at": "2026-08-18T00:00:00Z",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            connection = sqlite3.connect(root / "state_5.sqlite")
            try:
                connection.execute(
                    "CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT, history_mode TEXT)"
                )
                connection.execute(
                    "INSERT INTO threads VALUES (?, NULL, 'paginated')",
                    (self.THREAD_ID,),
                )
                connection.commit()
            finally:
                connection.close()

            report = inspect_migration_consistency(path, parse_transcript(path))
            self.assertTrue(report.name_metadata_diverged)
            self.assertTrue(report.session_index_name_present)
            self.assertFalse(report.sqlite_name_present)
            self.assertEqual(report.session_index_name_length, len("private synthetic name"))
            self.assertFalse(hasattr(report, "session_index_name_sha256"))
            diagnosis = doctor_session(path)
            self.assertIn("THREAD_NAME_METADATA_DIVERGED", diagnosis.findings)
            serialized = diagnosis.to_dict()["migration_consistency"]
            self.assertNotIn("private synthetic name", json.dumps(serialized))
            self.assertNotIn("sha256", json.dumps(serialized).lower())

    def test_sqlite_name_present_does_not_flag_divergence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = self._session_path(root)
            path.write_text(
                json.dumps(
                    {
                        "type": "session_meta",
                        "ordinal": 0,
                        "payload": {
                            "id": self.THREAD_ID,
                            "session_id": self.THREAD_ID,
                            "history_mode": "paginated",
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "session_index.jsonl").write_text(
                json.dumps({"id": self.THREAD_ID, "thread_name": "same"}) + "\n",
                encoding="utf-8",
            )
            connection = sqlite3.connect(root / "state_5.sqlite")
            try:
                connection.execute(
                    "CREATE TABLE threads (id TEXT PRIMARY KEY, name TEXT, history_mode TEXT)"
                )
                connection.execute(
                    "INSERT INTO threads VALUES (?, 'same', 'paginated')",
                    (self.THREAD_ID,),
                )
                connection.commit()
            finally:
                connection.close()
            report = inspect_migration_consistency(path, parse_transcript(path))
            self.assertFalse(report.name_metadata_diverged)


if __name__ == "__main__":
    unittest.main()
