import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.doctor import doctor_session
from codex_rescue.gitstate import GitStateError


class Alpha5VcsEvidenceTests(unittest.TestCase):
    @staticmethod
    def _session(directory: str, cwd: str) -> Path:
        path = Path(directory) / "rollout.jsonl"
        records = [
            {"type": "session_meta", "payload": {"id": "vcs-alpha5", "cwd": cwd}},
            {"type": "event_msg", "payload": {"type": "user_message", "message": "inspect vcs"}},
        ]
        path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    def _diagnose_git_error(self, message: str):
        with tempfile.TemporaryDirectory() as directory:
            path = self._session(directory, str(Path(directory) / "workspace"))
            with patch(
                "codex_rescue.doctor.inspect_git_state",
                side_effect=GitStateError(message),
            ):
                return doctor_session(path)

    def test_non_git_workspace_is_not_git_divergence(self):
        diagnosis = self._diagnose_git_error("not a git repository")
        self.assertEqual(diagnosis.repository["classification"], "non_git_workspace")
        self.assertEqual(diagnosis.repository["confidence"], "unknown")
        self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)

    def test_unavailable_git_is_not_git_divergence(self):
        diagnosis = self._diagnose_git_error("git executable not found")
        self.assertEqual(diagnosis.repository["classification"], "git_unavailable")
        self.assertEqual(diagnosis.repository["confidence"], "unknown")
        self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)

    def test_inaccessible_repository_is_not_git_divergence(self):
        diagnosis = self._diagnose_git_error("cwd does not exist: /private/repo")
        self.assertEqual(diagnosis.repository["classification"], "inaccessible_repository")
        self.assertEqual(diagnosis.repository["confidence"], "unknown")
        self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)


if __name__ == "__main__":
    unittest.main()
