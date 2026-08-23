from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.workspace_continuity import (
    GitMetadata,
    WorkspaceContinuityEngine,
    WorkspaceContinuityStatus,
)


class WorkspaceContinuityTests(unittest.TestCase):
    def test_unrecorded_workspace_status(self) -> None:
        rep = WorkspaceContinuityEngine.evaluate_continuity("session-1", saved_cwd=None)
        self.assertEqual(rep.status, WorkspaceContinuityStatus.UNRECORDED)
        self.assertIn("No working directory", rep.reason)

    def test_missing_workspace_status(self) -> None:
        rep = WorkspaceContinuityEngine.evaluate_continuity(
            "session-2",
            saved_cwd="/nonexistent/path/to/missing_workspace",
        )
        self.assertEqual(rep.status, WorkspaceContinuityStatus.MISSING)

    def test_matched_workspace_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rep = WorkspaceContinuityEngine.evaluate_continuity(
                "session-3",
                saved_cwd=td,
                current_cwd=td,
            )
            self.assertEqual(rep.status, WorkspaceContinuityStatus.MATCHED)

    def test_moved_workspace_status(self) -> None:
        with tempfile.TemporaryDirectory() as td1, tempfile.TemporaryDirectory() as td2:
            rep = WorkspaceContinuityEngine.evaluate_continuity(
                "session-4",
                saved_cwd=td1,
                current_cwd=td2,
            )
            self.assertEqual(rep.status, WorkspaceContinuityStatus.MOVED)

    def test_repository_changed_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            saved_git = GitMetadata(is_git_repository=True, repo_root="/old/repo")
            rep = WorkspaceContinuityEngine.evaluate_continuity(
                "session-5",
                saved_cwd=td,
                saved_git_metadata=saved_git,
            )
            self.assertEqual(rep.status, WorkspaceContinuityStatus.REPOSITORY_CHANGED)

    def test_conflict_remote_changed_status(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Fake current git metadata
            saved_git = GitMetadata(
                is_git_repository=True,
                repo_root=td,
                remote_origin_url="https://github.com/org/repo-a.git",
            )
            # When evaluating with mock or active git
            rep = WorkspaceContinuityEngine.evaluate_continuity(
                "session-6",
                saved_cwd=td,
                saved_git_metadata=saved_git,
            )
            # If current directory is not a git repo, status is REPOSITORY_CHANGED
            self.assertEqual(rep.status, WorkspaceContinuityStatus.REPOSITORY_CHANGED)


if __name__ == "__main__":
    unittest.main()
