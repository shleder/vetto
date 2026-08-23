from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.fixtures import materialize_fixture_git_repo, _hash_tree_files

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


class FixturePortabilityTests(unittest.TestCase):
    def test_fixture_session_cwds_use_portable_separators(self) -> None:
        """Synthetic relative cwd values must work on Windows and POSIX hosts."""
        for session in FIXTURES_DIR.glob("*/source_session/*.jsonl"):
            first_line = session.read_bytes().splitlines()[0]
            record = json.loads(first_line)
            payload = record.get("payload", {})
            cwd = payload.get("cwd")
            if isinstance(cwd, str) and not Path(cwd).is_absolute():
                with self.subTest(session=str(session)):
                    self.assertNotIn("\\", cwd)

    def test_fixtures_are_plain_snapshots_and_materialize_cleanly(self) -> None:
        self.assertTrue(FIXTURES_DIR.exists(), "fixtures directory missing")
        fixture_dirs = [d for d in FIXTURES_DIR.iterdir() if d.is_dir()]
        self.assertGreaterEqual(len(fixture_dirs), 5, "Expected at least 5 fixtures")

        for fixture in fixture_dirs:
            repo_before = fixture / "repo_before"
            repo_actual = fixture / "repo_actual"

            self.assertTrue(repo_before.exists(), f"repo_before missing in {fixture.name}")
            self.assertTrue(repo_actual.exists(), f"repo_actual missing in {fixture.name}")

            # Verify no committed .git directories exist inside fixture snapshots
            self.assertFalse((repo_before / ".git").exists(), f"repo_before contains .git in {fixture.name}")
            self.assertFalse((repo_actual / ".git").exists(), f"repo_actual contains .git in {fixture.name}")

            before_hashes = _hash_tree_files(repo_actual)

            # Test runtime materialization context manager
            with materialize_fixture_git_repo(fixture) as materialized_path:
                self.assertEqual(materialized_path, repo_actual)
                self.assertTrue((repo_actual / ".git").exists(), f"Runtime .git not materialized in {fixture.name}")

            # Verify cleanup
            self.assertFalse((repo_actual / ".git").exists(), f"Runtime .git not cleaned up in {fixture.name}")
            after_hashes = _hash_tree_files(repo_actual)
            self.assertEqual(before_hashes, after_hashes, f"repo_actual mutated after fixture {fixture.name}")

    def test_materialization_ignores_transient_git_locks(self) -> None:
        fixture = FIXTURES_DIR / "kill_apply_patch"
        repo_actual = fixture / "repo_actual"
        real_copytree = shutil.copytree

        def copytree_with_maintenance_lock(src: str | Path, dst: str | Path, *args: object, **kwargs: object) -> Path:
            if Path(src).name == ".git":
                lock = Path(src) / "objects" / "maintenance.lock"
                lock.parent.mkdir(parents=True, exist_ok=True)
                lock.write_text("transient\n", encoding="utf-8")
            return real_copytree(src, dst, *args, **kwargs)

        with patch("codex_rescue.fixtures.shutil.copytree", side_effect=copytree_with_maintenance_lock):
            with materialize_fixture_git_repo(fixture):
                self.assertFalse((repo_actual / ".git" / "objects" / "maintenance.lock").exists())


if __name__ == "__main__":
    unittest.main()
