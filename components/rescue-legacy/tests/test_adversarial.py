from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from codex_rescue.artifacts import write_rescue
from codex_rescue.gitstate import inspect_git_state
from codex_rescue.verify import verify_rescue


class AdversarialTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
        (repo / "a.txt").write_text("base\n", encoding="utf-8")
        subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
        return repo

    def test_head_change_blocks_continuation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            state = inspect_git_state(repo)
            handoff = {"version": 1, "session": {"source_id": "s", "cwd": str(repo)}, "repository": state.to_dict(), "tool_state": {"unfinished_action": None}, "overall_confidence": "verified"}
            rescue_id, _ = write_rescue(root / ".rescue", handoff, "brief", "prompt")
            (repo / "b.txt").write_text("new\n", encoding="utf-8")
            subprocess.run(["git", "add", "b.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "advance"], cwd=repo, check=True)
            self.assertEqual(verify_rescue(root / ".rescue", rescue_id).status, "STATE_DIVERGED")

    def test_unknown_tool_requires_review_even_when_repo_matches(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            state = inspect_git_state(repo)
            handoff = {"version": 1, "session": {"source_id": "s", "cwd": str(repo)}, "repository": state.to_dict(), "tool_state": {"unfinished_action": {"type": "shell", "confidence": "unknown"}}, "overall_confidence": "unknown"}
            rescue_id, _ = write_rescue(root / ".rescue", handoff, "brief", "prompt")
            self.assertEqual(verify_rescue(root / ".rescue", rescue_id).status, "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()

