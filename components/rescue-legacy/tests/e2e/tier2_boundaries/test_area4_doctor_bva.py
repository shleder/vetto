"""Tier 2: Feature Area 4 BVA - Doctor Diagnostics Boundary Value Analysis."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from codex_rescue.doctor import doctor_session
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea4DoctorBVA(unittest.TestCase):
    """Boundary and corner case tests for doctor diagnostics and severity precedence."""

    def test_e2e_t2_doctor_multiple_coexisting_faults(self) -> None:
        """Verify higher severity finding (MALFORMED_RECORD) takes precedence over UNFINISHED_TOOL_CALL."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                valid_prefix = SyntheticRolloutGenerator.create_rollout([
                    SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                    SyntheticRolloutGenerator.make_func_call("call_unfin", "tool", "{}"),
                ])
                malformed_suffix = b'{"type": "broken_line_bad_json...\n'
                p = ws.create_session("multi-fault", content_bytes=valid_prefix + malformed_suffix)

                res = doctor_session(p)
                self.assertEqual(res.status, "MALFORMED_RECORD")
                self.assertIn("MALFORMED_RECORD", res.findings)

    def test_e2e_t2_doctor_missing_session_meta(self) -> None:
        """Verify rollout starting without session_meta header evaluates without crashing."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_user_msg("Direct user prompt"),
                SyntheticRolloutGenerator.make_agent_msg("Direct agent response"),
            ]
            p = ws.create_session("no-meta-001", records=records)

            res = doctor_session(p)
            self.assertIsNotNone(res.status)
            self.assertEqual(res.transcript.valid_record_count, 2)

    def test_e2e_t2_doctor_malformed_json_tool_arguments(self) -> None:
        """Verify unparseable JSON in tool call arguments triggers MALFORMED_RECORD finding."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                records = [
                    SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                    {
                        "type": "response_item",
                        "payload": {
                            "type": "function_call",
                            "call_id": "call_bad_args",
                            "name": "shell_command",
                            "arguments": '{"unclosed_json_key: 123',
                        },
                    },
                    SyntheticRolloutGenerator.make_func_output("call_bad_args", "Done"),
                ]
                p = ws.create_session("bad-args-001", records=records)

                res = doctor_session(p)
                self.assertEqual(res.status, "MALFORMED_RECORD")
                self.assertGreater(len(res.transcript.malformed_tool_arguments), 0)

    def test_e2e_t2_doctor_0byte_file(self) -> None:
        """Verify 0-byte rollout is explicitly incomplete without being treated as corruption."""
        with TempSessionWorkspace() as ws:
            empty_file = ws.create_session("empty-doc", content_bytes=b"")

            res = doctor_session(empty_file)
            self.assertEqual(res.status, "INCOMPLETE_ROLLOUT")
            self.assertIn("INCOMPLETE_ROLLOUT", res.findings)
            self.assertNotIn("MALFORMED_RECORD", res.findings)

    def test_e2e_t2_doctor_git_unavailable_not_diverged(self) -> None:
        """Verify an invalid Git repository remains unknown rather than proving divergence."""
        with TempSessionWorkspace() as ws:
            # Create a broken .git file where git expects a directory or valid gitdir
            corrupt_git_dir = ws.root / "corrupt_git_repo"
            corrupt_git_dir.mkdir(parents=True, exist_ok=True)
            (corrupt_git_dir / ".git").write_bytes(b"INVALID_GIT_METADATA_NOT_A_REPO\n")

            records = [
                SyntheticRolloutGenerator.make_session_meta(cwd=str(corrupt_git_dir)),
                SyntheticRolloutGenerator.make_user_msg("Check repo"),
            ]
            p = ws.create_session("git-dirty-doc", records=records)

            res = doctor_session(p)
            self.assertEqual(res.status, "HEALTHY")
            self.assertNotIn("REPO_STATE_DIVERGED", res.findings)
            self.assertEqual(res.repository.get("confidence"), "unknown")


if __name__ == "__main__":
    unittest.main()
