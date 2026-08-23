from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_rescue.gitstate import compare_git_state, inspect_git_state


class GitStateHardeningTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(
            ["git", "config", "user.email", "gitstate-hardening@example.invalid"],
            cwd=repo,
            check=True,
        )
        subprocess.run(["git", "config", "user.name", "GitState Hardening"], cwd=repo, check=True)
        (repo / "normal.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "--", "normal.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
        return repo

    def test_utf8_path_names_are_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(Path(td))
            name = "\u044e\u043d\u0438\u043a\u043e\u0434.txt"
            path = repo / name
            path.write_text("before\n", encoding="utf-8")
            subprocess.run(["git", "add", "--", name], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "unicode"], cwd=repo, check=True)
            path.write_text("after\n", encoding="utf-8")

            state = inspect_git_state(repo)

            self.assertIn(name, state.modified)
            self.assertIn(name, state.changed_files)

    def test_assume_unchanged_is_reported_and_blocks_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(Path(td))
            clean = inspect_git_state(repo)
            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "--", "normal.txt"],
                cwd=repo,
                check=True,
            )
            (repo / "normal.txt").write_text("hidden modification\n", encoding="utf-8")

            state = inspect_git_state(repo)
            conflicts = compare_git_state(clean.to_dict(), state)

            self.assertIn("assume-unchanged:normal.txt", state.index_flags)
            self.assertEqual(state.modified, ())
            self.assertTrue(any("index flags require review" in item for item in conflicts))
            self.assertEqual(
                subprocess.run(
                    ["git", "ls-files", "-v", "--", "normal.txt"],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout[:1],
                "h",
            )

    def test_skip_worktree_is_reported_and_blocks_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = self._repo(Path(td))
            clean = inspect_git_state(repo)
            subprocess.run(
                ["git", "update-index", "--skip-worktree", "--", "normal.txt"],
                cwd=repo,
                check=True,
            )
            (repo / "normal.txt").write_text("hidden skip-worktree modification\n", encoding="utf-8")

            state = inspect_git_state(repo)
            conflicts = compare_git_state(clean.to_dict(), state)

            self.assertIn("skip-worktree:normal.txt", state.index_flags)
            self.assertEqual(state.modified, ())
            self.assertTrue(any("index flags require review" in item for item in conflicts))
            self.assertEqual(
                subprocess.run(
                    ["git", "ls-files", "-v", "--", "normal.txt"],
                    cwd=repo,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout[:1],
                "S",
            )


if __name__ == "__main__":
    unittest.main()
