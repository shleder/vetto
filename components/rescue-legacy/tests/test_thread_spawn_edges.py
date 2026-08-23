from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from codex_rescue.spawn_edges import (
    SPAWN_EDGE_CLOSED,
    SPAWN_EDGE_OPEN,
    SPAWN_EDGE_UNKNOWN,
    SPAWN_EDGE_UNRECORDED,
    inspect_thread_spawn_edge,
)


class ThreadSpawnEdgeEvidenceTests(unittest.TestCase):
    def _layout(self, directory: str) -> tuple[Path, Path, Path]:
        home = Path(directory) / ".codex"
        sessions = home / "sessions"
        sessions.mkdir(parents=True)
        rollout = sessions / "child.jsonl"
        rollout.write_text('{}\n', encoding="utf-8")
        return home, rollout, home / "state_5.sqlite"

    @staticmethod
    def _create_exact_table(db_path: Path) -> sqlite3.Connection:
        db = sqlite3.connect(db_path)
        db.execute(
            "CREATE TABLE thread_spawn_edges ("
            "parent_thread_id TEXT NOT NULL, "
            "child_thread_id TEXT NOT NULL PRIMARY KEY, "
            "status TEXT NOT NULL)"
        )
        return db

    def test_open_edge_is_read_from_exact_current_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = self._create_exact_table(db_path)
            try:
                db.execute("INSERT INTO thread_spawn_edges VALUES (?, ?, ?)", ("parent", "child", "open"))
                db.commit()
            finally:
                db.close()
            result = inspect_thread_spawn_edge(
                rollout, child_thread_id="child", parent_thread_id="parent", codex_home=home
            )
            self.assertEqual(result.status, SPAWN_EDGE_OPEN)
            self.assertEqual(result.parent_thread_id, "parent")
            self.assertEqual(result.child_thread_id, "child")
            self.assertEqual(result.to_dict()["status"], SPAWN_EDGE_OPEN)

    def test_closed_edge_is_read_without_mutating_database(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = self._create_exact_table(db_path)
            try:
                db.execute("INSERT INTO thread_spawn_edges VALUES (?, ?, ?)", ("parent", "child", "closed"))
                db.commit()
            finally:
                db.close()
            before = hashlib.sha256(db_path.read_bytes()).hexdigest()
            result = inspect_thread_spawn_edge(
                rollout, child_thread_id="child", parent_thread_id="parent", codex_home=home
            )
            after = hashlib.sha256(db_path.read_bytes()).hexdigest()
            self.assertEqual(result.status, SPAWN_EDGE_CLOSED)
            self.assertEqual(before, after)

    def test_no_row_is_unrecorded_not_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = self._create_exact_table(db_path)
            db.close()
            result = inspect_thread_spawn_edge(rollout, child_thread_id="child", codex_home=home)
            self.assertEqual(result.status, SPAWN_EDGE_UNRECORDED)
            self.assertNotEqual(result.status, SPAWN_EDGE_CLOSED)

    def test_missing_edge_table_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = sqlite3.connect(db_path)
            db.execute("CREATE TABLE unrelated (id TEXT)")
            db.commit()
            db.close()
            result = inspect_thread_spawn_edge(rollout, child_thread_id="child", codex_home=home)
            self.assertEqual(result.status, SPAWN_EDGE_UNKNOWN)

    def test_unreadable_database_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db_path.write_bytes(b"not sqlite")
            result = inspect_thread_spawn_edge(rollout, child_thread_id="child", codex_home=home)
            self.assertEqual(result.status, SPAWN_EDGE_UNKNOWN)

    def test_unknown_edge_status_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = self._create_exact_table(db_path)
            try:
                db.execute("INSERT INTO thread_spawn_edges VALUES (?, ?, ?)", ("parent", "child", "paused"))
                db.commit()
            finally:
                db.close()
            result = inspect_thread_spawn_edge(rollout, child_thread_id="child", codex_home=home)
            self.assertEqual(result.status, SPAWN_EDGE_UNKNOWN)

    def test_unknown_schema_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = sqlite3.connect(db_path)
            db.execute(
                "CREATE TABLE thread_spawn_edges ("
                "parent_thread_id TEXT NOT NULL, "
                "child_thread_id TEXT NOT NULL PRIMARY KEY, "
                "status TEXT NOT NULL, extra TEXT)"
            )
            db.commit()
            db.close()
            result = inspect_thread_spawn_edge(rollout, child_thread_id="child", codex_home=home)
            self.assertEqual(result.status, SPAWN_EDGE_UNKNOWN)

    def test_parent_identity_conflict_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home, rollout, db_path = self._layout(directory)
            db = self._create_exact_table(db_path)
            try:
                db.execute("INSERT INTO thread_spawn_edges VALUES (?, ?, ?)", ("other-parent", "child", "closed"))
                db.commit()
            finally:
                db.close()
            result = inspect_thread_spawn_edge(
                rollout, child_thread_id="child", parent_thread_id="expected-parent", codex_home=home
            )
            self.assertEqual(result.status, SPAWN_EDGE_UNKNOWN)
            self.assertEqual(result.parent_thread_id, "other-parent")


if __name__ == "__main__":
    unittest.main()
