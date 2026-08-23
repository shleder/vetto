"""Tier 1: Feature Area 9 - Black-Box CLI Envelopes & Exit Codes."""
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


class TestArea9CLIEnvelopesFeatures(unittest.TestCase):
    """End-to-end black-box CLI verification of JSON envelopes and standard exit codes."""

    def test_e2e_t1_cli_sessions_json(self) -> None:
        """Verify codex-rescue sessions --json returns standard schema envelope with exit 0."""
        with TempSessionWorkspace() as ws:
            ws.create_session("cli-sess-1", date_path="2026/08/14")
            ws.create_session("cli-sess-2", date_path="2026/08/14")

            code, stdout, stderr = run_cli_command(["sessions", "--codex-home", str(ws.root), "--json"])
            self.assertEqual(code, 0)
            data = json.loads(stdout)
            self.assertEqual(data.get("schema_version"), 1)
            self.assertIsInstance(data.get("data"), list)
            self.assertEqual(len(data["data"]), 2)

    def test_e2e_t1_cli_doctor_healthy_json(self) -> None:
        """Verify codex-rescue doctor --json returns status HEALTHY with exit 0."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "cli-doc-healthy",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Healthy prompt"),
                        SyntheticRolloutGenerator.make_agent_msg("Done"),
                    ],
                )

                code, stdout, stderr = run_cli_command(["doctor", str(p), "--json"])
                self.assertEqual(code, 0)
                data = json.loads(stdout)
                self.assertEqual(data.get("schema_version"), 1)
                self.assertEqual(data["data"]["status"], "HEALTHY")
                self.assertIn("HEALTHY", data["data"]["findings"])

    def test_e2e_t1_cli_salvage_requires_fork(self) -> None:
        """Verify codex-rescue salvage without --fork fails with exit code 2 and helpful stderr."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("cli-salv-no-fork")

            code, stdout, stderr = run_cli_command(["salvage", str(p)])
            self.assertEqual(code, 2)
            self.assertIn("--fork", stderr)

    def test_e2e_t1_cli_salvage_success_json(self) -> None:
        """Verify codex-rescue salvage --fork --json produces valid rescue artifact with exit 0."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("cli-salv-ok")
            rescue_root = ws.root / "rescues"

            code, stdout, stderr = run_cli_command([
                "salvage", str(p),
                "--fork",
                "--rescue-root", str(rescue_root),
                "--json",
            ])
            self.assertEqual(code, 0)
            data = json.loads(stdout)
            self.assertEqual(data.get("schema_version"), 1)
            self.assertTrue(data["data"]["original_untouched"])
            self.assertTrue(len(data["data"]["rescue_id"]) == 24)

    def test_e2e_t1_cli_verify_exit_codes(self) -> None:
        """Verify codex-rescue verify returns exit 0 on clean state and exit 3 on divergence."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "cli-verify-flow",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Clean check"),
                    ],
                )
                rescue_root = ws.root / "rescues"

                # Salvage clean session
                code, stdout, _ = run_cli_command([
                    "salvage", str(p),
                    "--fork",
                    "--rescue-root", str(rescue_root),
                    "--json",
                ])
                self.assertEqual(code, 0)
                salv_data = json.loads(stdout)["data"]
                rescue_id = salv_data["rescue_id"]

                # Verify clean state -> exit code 0
                v_code, v_stdout, _ = run_cli_command([
                    "verify", rescue_id,
                    "--rescue-root", str(rescue_root),
                    "--json",
                ])
                self.assertEqual(v_code, 0)
                v_data = json.loads(v_stdout)["data"]
                self.assertEqual(v_data["status"], "SAFE_TO_CONTINUE")

                # Mutate repo -> verify fails closed with exit code 3
                git_repo.commit_file("new_commit.txt", "diverge", "Move HEAD")
                v2_code, v2_stdout, _ = run_cli_command([
                    "verify", rescue_id,
                    "--rescue-root", str(rescue_root),
                    "--json",
                ])
                self.assertEqual(v2_code, 3)
                v2_data = json.loads(v2_stdout)["data"]
                self.assertEqual(v2_data["status"], "STATE_DIVERGED")


if __name__ == "__main__":
    unittest.main()
