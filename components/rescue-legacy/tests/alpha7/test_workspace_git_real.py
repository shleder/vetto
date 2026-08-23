from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.workspace_continuity import (
    GitMetadata,
    WorkspaceContinuityEngine,
    WorkspaceContinuityStatus,
)


class RealWorkspaceGitTests(unittest.TestCase):
    def _run_git(self, repo_dir: Path, *args: str) -> str:
        res = subprocess.run(
            ["git", "-C", str(repo_dir)] + list(args),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()

    def test_real_git_repository_and_detached_head(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()

            self._run_git(repo, "init")
            self._run_git(repo, "config", "user.name", "Test")
            self._run_git(repo, "config", "user.email", "test@example.com")
            (repo / "file.txt").write_text("initial", encoding="utf-8")
            self._run_git(repo, "add", "file.txt")
            self._run_git(repo, "commit", "-m", "commit 1")

            # Normal inspection
            meta = WorkspaceContinuityEngine.inspect_git_read_only(repo)
            self.assertTrue(meta.is_git_repository)
            self.assertIsNotNone(meta.head_commit)
            self.assertFalse(meta.is_detached_head)
            self.assertFalse(meta.is_worktree)

            # Detached HEAD
            head = meta.head_commit
            self._run_git(repo, "checkout", head)
            meta_detached = WorkspaceContinuityEngine.inspect_git_read_only(repo)
            self.assertTrue(meta_detached.is_detached_head)

    def test_real_git_worktree_detection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            main_repo = Path(td) / "main_repo"
            main_repo.mkdir()
            self._run_git(main_repo, "init")
            self._run_git(main_repo, "config", "user.name", "Test")
            self._run_git(main_repo, "config", "user.email", "test@example.com")
            (main_repo / "file.txt").write_text("initial", encoding="utf-8")
            self._run_git(main_repo, "add", "file.txt")
            self._run_git(main_repo, "commit", "-m", "commit 1")

            wt_dir = Path(td) / "worktree_branch"
            self._run_git(main_repo, "worktree", "add", "-b", "feature", str(wt_dir))

            meta_wt = WorkspaceContinuityEngine.inspect_git_read_only(wt_dir)
            self.assertTrue(meta_wt.is_git_repository)
            self.assertTrue(meta_wt.is_worktree)
            self.assertEqual(meta_wt.branch, "feature")

    def test_same_folder_name_different_repo_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            repo1 = Path(td1) / "my_project"
            repo1.mkdir()
            self._run_git(repo1, "init")
            self._run_git(repo1, "config", "user.name", "Test")
            self._run_git(repo1, "config", "user.email", "test@example.com")
            self._run_git(repo1, "config", "remote.origin.url", "https://github.com/org/repo-alpha.git")

            repo2 = Path(td2) / "my_project"
            repo2.mkdir()
            self._run_git(repo2, "init")
            self._run_git(repo2, "config", "user.name", "Test")
            self._run_git(repo2, "config", "user.email", "test@example.com")
            self._run_git(repo2, "config", "remote.origin.url", "https://github.com/org/repo-beta.git")

            meta1 = WorkspaceContinuityEngine.inspect_git_read_only(repo1)

            # Evaluate repo2 against saved meta1
            rep = WorkspaceContinuityEngine.evaluate_continuity(
                session_id="s1",
                saved_cwd=str(repo1),
                current_cwd=str(repo2),
                saved_git_metadata=meta1,
            )
            self.assertEqual(rep.status, WorkspaceContinuityStatus.CONFLICT)


if __name__ == "__main__":
    unittest.main()
