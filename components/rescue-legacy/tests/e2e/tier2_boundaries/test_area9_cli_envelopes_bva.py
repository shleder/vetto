"""Tier 2: Feature Area 9 BVA - CLI Envelopes & Exit Codes Boundary Value Analysis."""
from __future__ import annotations

import json
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

from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace, run_cli_command


class TestArea9CLIEnvelopesBVA(unittest.TestCase):
    """Boundary and corner case tests for CLI envelopes, argument edge cases, and exit codes."""

    def test_e2e_t2_cli_nonexistent_session_doctor(self) -> None:
        """Verify codex-rescue doctor on nonexistent file exits with non-zero code."""
        code, stdout, stderr = run_cli_command(["doctor", "C:/nonexistent/missing.jsonl"])
        self.assertNotEqual(code, 0)

    def test_e2e_t2_cli_oversized_threshold_flag(self) -> None:
        """Verify --oversized-threshold flag correctly lowers threshold and reports OVERSIZED_PAYLOAD."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                payload_60kb = "A" * (60 * 1024)
                records = [
                    SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "user_message",
                            "message": payload_60kb,
                        },
                    },
                ]
                p = ws.create_session("cli-oversize", records=records)

                code, stdout, stderr = run_cli_command([
                    "doctor", str(p),
                    "--oversized-threshold", "50000",
                    "--json",
                ])
                self.assertEqual(code, 0)
                data = json.loads(stdout)["data"]
                self.assertEqual(data["status"], "OVERSIZED_PAYLOAD")

    def test_e2e_t2_cli_verify_invalid_rescue_root(self) -> None:
        """Verify codex-rescue verify on nonexistent rescue root fails closed with exit code 3."""
        fake_id = "0123456789abcdef01234567"
        code, stdout, stderr = run_cli_command([
            "verify", fake_id,
            "--rescue-root", "C:/nonexistent/rescues",
            "--json",
        ])
        self.assertEqual(code, 3)
        data = json.loads(stdout)["data"]
        self.assertEqual(data["status"], "REVIEW_REQUIRED")

    def test_e2e_t2_cli_sessions_limit_zero(self) -> None:
        """Verify codex-rescue sessions --limit 0 returns empty data list with exit code 0."""
        with TempSessionWorkspace() as ws:
            ws.create_session("sess-1")
            code, stdout, stderr = run_cli_command([
                "sessions",
                "--codex-home", str(ws.root),
                "--limit", "0",
                "--json",
            ])
            self.assertEqual(code, 0)
            data = json.loads(stdout)["data"]
            self.assertEqual(len(data), 0)

    def test_e2e_t2_cli_invalid_subcommand(self) -> None:
        """Verify invalid CLI subcommand returns exit code 2."""
        code, stdout, stderr = run_cli_command(["invalid_cmd_xyz"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
