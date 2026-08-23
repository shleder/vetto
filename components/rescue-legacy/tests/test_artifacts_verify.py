from __future__ import annotations

import subprocess
import tempfile
import unittest
import hashlib
from pathlib import Path

from codex_rescue.artifacts import load_handoff, write_rescue
from codex_rescue.gitstate import inspect_git_state
from codex_rescue.verify import verify_rescue


class ArtifactVerifyTests(unittest.TestCase):
    def test_verify_detects_later_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            (repo / "a.txt").write_text("a\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            state = inspect_git_state(repo)
            handoff = {
                "version": 1,
                "session": {"source_id": "s", "cwd": str(repo)},
                "repository": state.to_dict(),
                "tool_state": {"unfinished_action": None},
                "overall_confidence": "verified",
            }
            rescue_id, _ = write_rescue(base / ".codex-rescue", handoff, "brief", "continue")
            self.assertEqual(load_handoff(base / ".codex-rescue", rescue_id)["version"], 1)
            self.assertEqual(verify_rescue(base / ".codex-rescue", rescue_id).status, "SAFE_TO_CONTINUE")
            (repo / "a.txt").write_text("changed\n", encoding="utf-8")
            self.assertEqual(verify_rescue(base / ".codex-rescue", rescue_id).status, "STATE_DIVERGED")

    def test_verify_rechecks_saved_source_hash_and_size(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            repo = base / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Test"], cwd=repo, check=True)
            (repo / "a.txt").write_text("a\n", encoding="utf-8")
            subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "base"], cwd=repo, check=True)
            source = base / "rollout.jsonl"
            source.write_bytes(b"original\n")
            source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
            state = inspect_git_state(repo)
            handoff = {
                "version": 1,
                "session": {"source_id": "s", "cwd": str(repo), "source_ref": str(source)},
                "repository": state.to_dict(),
                "transcript": {"hash": source_hash, "size": source.stat().st_size},
                "tool_state": {"unfinished_action": None},
                "overall_confidence": "verified",
            }
            rescue_id, _ = write_rescue(base / ".codex-rescue", handoff, "brief", "continue")
            self.assertEqual(verify_rescue(base / ".codex-rescue", rescue_id).status, "SAFE_TO_CONTINUE")

            source.write_bytes(b"mutated!\n")
            verification = verify_rescue(base / ".codex-rescue", rescue_id)
            self.assertEqual(verification.status, "STATE_DIVERGED")
            self.assertTrue(any("source_sha256" in conflict for conflict in verification.conflicts))

            source.unlink()
            verification = verify_rescue(base / ".codex-rescue", rescue_id)
            self.assertEqual(verification.status, "REVIEW_REQUIRED")
            self.assertTrue(any("source rollout unavailable" in reason for reason in verification.review_reasons))


if __name__ == "__main__":
    unittest.main()
