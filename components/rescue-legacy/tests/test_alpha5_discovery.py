import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from codex_rescue.discovery_alpha5 import discover_sessions, path_identity
from codex_rescue.doctor import doctor_session


class Alpha5DiscoveryTests(unittest.TestCase):
    @staticmethod
    def _rollout(root: Path, thread_id: str, *, archived: bool = False, message: str = "hello") -> Path:
        base = root / ("archived_sessions" if archived else "sessions") / "2026" / "08" / "17"
        base.mkdir(parents=True, exist_ok=True)
        path = base / f"rollout-2026-08-17T00-00-00-{thread_id}.jsonl"
        records = [
            {"type": "session_meta", "payload": {"id": thread_id, "session_id": thread_id}},
            {"type": "event_msg", "payload": {"type": "user_message", "message": message}},
        ]
        path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        return path

    @staticmethod
    def _db(root: Path, rows: list[tuple[str, str, str, int, int]], *, include_preview: bool = False) -> Path:
        db = root / "state_5.sqlite"
        connection = sqlite3.connect(db)
        try:
            extra = ", first_user_message TEXT, preview TEXT" if include_preview else ""
            connection.execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT, cwd TEXT, archived INTEGER, updated_at INTEGER"
                + extra
                + ")"
            )
            for thread_id, rollout_path, cwd, archived, updated_at in rows:
                if include_preview:
                    connection.execute(
                        "INSERT INTO threads VALUES (?, ?, ?, ?, ?, '', '')",
                        (thread_id, rollout_path, cwd, archived, updated_at),
                    )
                else:
                    connection.execute(
                        "INSERT INTO threads VALUES (?, ?, ?, ?, ?)",
                        (thread_id, rollout_path, cwd, archived, updated_at),
                    )
            connection.commit()
        finally:
            connection.close()
        return db

    def test_rollout_exists_db_row_absent_remains_discoverable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            thread_id = "019fffff-0001-7000-8000-000000000001"
            path = self._rollout(root, thread_id)
            self._db(root, [])
            sessions = discover_sessions(root, limit=100)
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].path, path.resolve())
            self.assertEqual(sessions[0].inventory_mismatch, "rollout_not_indexed")
            self.assertFalse(sessions[0].indexed)

    def test_db_row_exists_rollout_absent_is_inventory_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            thread_id = "019fffff-0002-7000-8000-000000000002"
            rel = f"sessions/2026/08/17/rollout-x-{thread_id}.jsonl"
            self._db(root, [(thread_id, rel, "/work/repo", 0, int(time.time()))])
            sessions = discover_sessions(root, limit=100)
            self.assertEqual(len(sessions), 1)
            self.assertFalse(sessions[0].exists)
            self.assertEqual(sessions[0].inventory_mismatch, "indexed_rollout_missing")

    def test_empty_preview_and_first_user_message_do_not_hide_rollout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            thread_id = "019fffff-0003-7000-8000-000000000003"
            path = self._rollout(root, thread_id, message="")
            rel = str(path.relative_to(root))
            self._db(root, [(thread_id, rel, "/work/repo", 0, int(time.time()))], include_preview=True)
            sessions = discover_sessions(root, limit=100)
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].exists)
            self.assertTrue(sessions[0].indexed)
            self.assertIsNone(sessions[0].prompt_preview)

    def test_archived_session_is_discovered(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            thread_id = "019fffff-0004-7000-8000-000000000004"
            self._rollout(root, thread_id, archived=True)
            sessions = discover_sessions(root, limit=100, include_archived=True)
            self.assertEqual(len(sessions), 1)
            self.assertTrue(sessions[0].archived)

    def test_duplicate_candidates_with_same_thread_id_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            thread_id = "019fffff-0005-7000-8000-000000000005"
            active = self._rollout(root, thread_id, archived=False, message="active")
            archived = self._rollout(root, thread_id, archived=True, message="archived")
            os.utime(active, (1000, 1000))
            os.utime(archived, (2000, 2000))
            sessions = discover_sessions(root, limit=100, include_archived=True)
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].session_id, thread_id)

    def test_malformed_rollout_candidate_is_visible_as_damaged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "sessions" / "2026" / "08" / "17"
            base.mkdir(parents=True)
            path = base / "rollout-malformed.jsonl"
            path.write_bytes(b'{"type":"session_meta","payload":{"id":"bad"}}\n{broken\n')
            sessions = discover_sessions(root, limit=100)
            self.assertEqual(len(sessions), 1)
            self.assertEqual(sessions[0].status, "damaged")

    def test_direct_doctor_path_does_not_depend_on_discovery(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "direct.jsonl"
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": "direct"}}) + "\n"
                + json.dumps({"type": "event_msg", "payload": {"type": "user_message", "message": "ok"}}) + "\n",
                encoding="utf-8",
            )
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.status, "HEALTHY")
            self.assertEqual(diagnosis.projection.status, "not_applicable")

    def test_windows_wsl_path_identity(self):
        self.assertEqual(
            path_identity(r"C:\\Users\\Alice\\.codex\\sessions\\rollout.jsonl"),
            path_identity("/mnt/c/Users/Alice/.codex/sessions/rollout.jsonl"),
        )

    def test_limit_is_stable_after_inventory_correlation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for index in range(3):
                thread_id = f"019fffff-001{index}-7000-8000-00000000001{index}"
                path = self._rollout(root, thread_id, message=str(index))
                os.utime(path, (1000 + index, 1000 + index))
                paths.append(path)
            sessions = discover_sessions(root, limit=2)
            self.assertEqual(len(sessions), 2)
            self.assertGreaterEqual(sessions[0].mtime, sessions[1].mtime)

    def test_limit_counts_unique_sessions_after_deduplication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate_id = "019fffff-0020-7000-8000-000000000020"
            second_id = "019fffff-0021-7000-8000-000000000021"
            third_id = "019fffff-0022-7000-8000-000000000022"
            active = self._rollout(root, duplicate_id, archived=False, message="active")
            archived = self._rollout(root, duplicate_id, archived=True, message="archived")
            second = self._rollout(root, second_id, message="second")
            third = self._rollout(root, third_id, message="third")
            os.utime(active, (4000, 4000))
            os.utime(archived, (5000, 5000))
            os.utime(second, (3000, 3000))
            os.utime(third, (2000, 2000))

            sessions = discover_sessions(root, limit=2, include_archived=True)
            self.assertEqual(len(sessions), 2)
            self.assertEqual({session.session_id for session in sessions}, {duplicate_id, second_id})


if __name__ == "__main__":
    unittest.main()
