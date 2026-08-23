import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from codex_rescue.thread_store import (
    INDEX_DIVERGENCE,
    NEVER_PERSISTED_TEMP_CHILD,
    ROLLOUT_MISSING,
    WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE,
    classify_rollout_presence,
    inspect_thread_store,
)
from codex_rescue.windows_paths import (
    compare_windows_paths,
    normalize_windows_extended_path,
    path_identity,
)


class WindowsPathIdentityTests(unittest.TestCase):
    def test_normalize_windows_extended_path_varieties(self):
        self.assertEqual(
            normalize_windows_extended_path(r"\\?\C:\Users\Alice\foo\bar"),
            "C:/Users/Alice/foo/bar",
        )
        self.assertEqual(
            normalize_windows_extended_path(r"//?/c:/Users/Alice/foo/bar"),
            "C:/Users/Alice/foo/bar",
        )
        self.assertEqual(
            normalize_windows_extended_path(r"c:\users\alice\foo\bar"),
            "C:/users/alice/foo/bar",
        )
        self.assertEqual(
            normalize_windows_extended_path(r"\\?\UNC\server\share\foo\bar"),
            "//server/share/foo/bar",
        )
        self.assertEqual(
            normalize_windows_extended_path(r"//?/UNC/server/share/foo/bar"),
            "//server/share/foo/bar",
        )
        self.assertEqual(
            normalize_windows_extended_path("/mnt/c/Users/Alice/foo/bar"),
            "C:/Users/Alice/foo/bar",
        )

    def test_normalize_windows_extended_path_posix_preservation(self):
        self.assertEqual(
            normalize_windows_extended_path("/home/user/project/file.txt"),
            "/home/user/project/file.txt",
        )
        self.assertEqual(
            normalize_windows_extended_path("/tmp/test/session.jsonl"),
            "/tmp/test/session.jsonl",
        )
        self.assertEqual(normalize_windows_extended_path(""), "")

    def test_drive_extended_prefix_forward_is_equivalent(self):
        result = compare_windows_paths(
            r"C:\Users\Alice\.codex\sessions\rollout.jsonl",
            r"\\?\C:\Users\Alice\.codex\sessions\rollout.jsonl",
        )
        self.assertEqual(result.relation, "EQUIVALENT")
        self.assertTrue(result.namespace_divergence)

    def test_drive_extended_prefix_reverse_is_equivalent(self):
        result = compare_windows_paths(
            r"\\?\C:\USERS\ALICE\.CODEX\sessions\rollout.jsonl",
            r"c:/users/alice/.codex/sessions/rollout.jsonl",
        )
        self.assertEqual(result.relation, "EQUIVALENT")
        self.assertTrue(result.namespace_divergence)

    def test_genuinely_different_rollouts_are_not_equivalent(self):
        result = compare_windows_paths(
            r"C:\Users\Alice\.codex\sessions\one.jsonl",
            r"\\?\C:\Users\Alice\.codex\sessions\two.jsonl",
        )
        self.assertEqual(result.relation, "DIFFERENT")
        self.assertFalse(result.namespace_divergence)

    def test_extended_unc_and_normal_unc_are_equivalent(self):
        result = compare_windows_paths(
            r"\\server\share\.codex\sessions\rollout.jsonl",
            r"\\?\UNC\server\share\.codex\sessions\rollout.jsonl",
        )
        self.assertEqual(result.relation, "EQUIVALENT")
        self.assertTrue(result.namespace_divergence)

    def test_device_and_ambiguous_extended_paths_fail_closed(self):
        self.assertEqual(compare_windows_paths(r"\\.\C:\x", r"C:\x").relation, "UNKNOWN")
        self.assertEqual(compare_windows_paths(r"\\?\C:\x\..\y", r"C:\y").relation, "UNKNOWN")
        self.assertEqual(compare_windows_paths(r"\\?\C:\x.\y", r"C:\x\y").relation, "UNKNOWN")

    def test_drive_case_separator_and_wsl_identity_remain_stable(self):
        self.assertEqual(path_identity(r"C:\Users\Alice\x"), path_identity(r"c:/users/alice/x"))
        self.assertEqual(path_identity(r"C:\Users\Alice\x"), path_identity("/mnt/c/Users/Alice/x"))

    def test_posix_behavior_is_not_case_folded(self):
        self.assertNotEqual(path_identity("/tmp/A/rollout.jsonl"), path_identity("/tmp/a/rollout.jsonl"))

    def test_presence_classification_does_not_fabricate_missing_rollout(self):
        self.assertEqual(
            classify_rollout_presence(
                rollout_exists=False,
                db_row_present=False,
                known_never_persisted_temp_child=True,
            ),
            NEVER_PERSISTED_TEMP_CHILD,
        )
        self.assertEqual(classify_rollout_presence(rollout_exists=False, db_row_present=True), ROLLOUT_MISSING)
        self.assertEqual(classify_rollout_presence(rollout_exists=True, db_row_present=False), INDEX_DIVERGENCE)
        self.assertEqual(classify_rollout_presence(rollout_exists=None, db_row_present=True), "UNKNOWN")

    def test_unreadable_db_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "sessions"
            sessions.mkdir()
            rollout = sessions / "rollout.jsonl"
            rollout.write_text('{}\n', encoding="utf-8")
            (root / "state_5.sqlite").write_bytes(b"not sqlite")
            report = inspect_thread_store(rollout, codex_home=root)
            self.assertEqual(report.status, "UNKNOWN")
            self.assertEqual(report.findings, ())

    @unittest.skipUnless(os.name == "nt", "requires real Windows filesystem semantics")
    def test_windows_state5_extended_path_integration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "sessions"
            sessions.mkdir()
            thread_id = "019fffff-1000-7000-8000-000000001000"
            rollout = sessions / f"rollout-2026-08-19T00-00-00-{thread_id}.jsonl"
            rollout.write_text('{}\n', encoding="utf-8")
            resolved = str(rollout.resolve())
            extended = resolved if resolved.startswith("\\\\?\\") else "\\\\?\\" + resolved
            db = sqlite3.connect(root / "state_5.sqlite")
            try:
                db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)")
                db.execute("INSERT INTO threads VALUES (?, ?)", (thread_id, extended))
                db.commit()
            finally:
                db.close()
            report = inspect_thread_store(rollout, session_id=thread_id, codex_home=root)
            self.assertEqual(report.status, "DIVERGED")
            self.assertEqual(report.path_relation, "EQUIVALENT")
            self.assertIn(WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE, report.findings)


class ThreadStoreContractTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "requires Windows doctor path semantics")
    def test_healthy_source_and_path_divergence_remain_separate(self):
        import json
        from codex_rescue.doctor import doctor_session

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sessions = root / "sessions" / "2026" / "08" / "19"
            sessions.mkdir(parents=True)
            thread_id = "019fffff-1001-7000-8000-000000001001"
            rollout = sessions / f"rollout-2026-08-19T00-00-00-{thread_id}.jsonl"
            records = [
                {"type": "session_meta", "payload": {"id": thread_id, "session_id": "029fffff-1001-7000-8000-000000001001"}},
                {"type": "event_msg", "payload": {"type": "user_message", "message": "healthy"}},
            ]
            rollout.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
            normal = str(rollout.resolve())
            extended = normal if normal.startswith("\\\\?\\") else "\\\\?\\" + normal
            db = sqlite3.connect(root / "state_5.sqlite")
            try:
                db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)")
                db.execute("INSERT INTO threads VALUES (?, ?)", (thread_id, extended))
                db.commit()
            finally:
                db.close()

            result = doctor_session(rollout)
            self.assertEqual(result.thread_identity.thread_id, thread_id)
            self.assertEqual(result.thread_identity.metadata_field, "id")
            self.assertEqual(result.source_integrity["status"], "HEALTHY")
            self.assertEqual(result.thread_store.status, "DIVERGED")
            self.assertIn(WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE, result.findings)
            self.assertEqual(result.status, WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE)

            payload = result.to_dict()
            self.assertEqual(payload["thread_identity"]["thread_id"], thread_id)
            self.assertEqual(payload["source_integrity"]["status"], "HEALTHY")
            self.assertEqual(payload["thread_store"]["status"], "DIVERGED")
            self.assertIn(WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE, payload["thread_store"]["findings"])
            self.assertEqual(payload["status"], WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE)


if __name__ == "__main__":
    unittest.main()
