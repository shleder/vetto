"""Tier 1: Feature Area 6 - Verification & Git State Tracking (P5, P6, P7)."""
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

from codex_rescue.doctor import doctor_session
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from codex_rescue.verify import verify_rescue
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea6VerifyGitFeatures(unittest.TestCase):
    """End-to-end feature tests for verification against repository states and forensic evidence."""

    def test_e2e_t1_verify_clean_matching_repo(self) -> None:
        """Verify verification passes with SAFE_TO_CONTINUE when Git repository state is untouched."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                records = [
                    SyntheticRolloutGenerator.make_session_meta(
                        session_id="verify-clean",
                        cwd=str(git_repo.root),
                    ),
                    SyntheticRolloutGenerator.make_user_msg("Task in git repo"),
                    SyntheticRolloutGenerator.make_agent_msg("Done"),
                ]
                p = ws.create_session("verify-clean", records=records)
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)

                self.assertEqual(verify_res.status, "SAFE_TO_CONTINUE")
                self.assertEqual(len(verify_res.conflicts), 0)
                self.assertEqual(len(verify_res.review_reasons), 0)

    def test_e2e_t1_verify_diverged_head_sha(self) -> None:
        """Verify state divergence detected when HEAD commit moves after salvage."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-diverge-head",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Run commit"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                # Mutate Git HEAD by committing a new file
                git_repo.commit_file("new_feature.py", "print('hello')", "Second commit")

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("head_sha: expected" in c for c in verify_res.conflicts))

    def test_e2e_t1_verify_modified_tracked_file(self) -> None:
        """Verify diff hash divergence detected when a tracked file is modified post-salvage."""
        with MockGitRepo() as git_repo:
            git_repo.commit_file("config.py", "DEBUG = False\n", "Add config")
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-mod-file",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Check config"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                # Modify tracked file without committing
                git_repo.modify_file("config.py", "DEBUG = True\n# Modified after salvage\n")

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("diff_hash: expected" in c for c in verify_res.conflicts))

    def test_e2e_t1_verify_new_untracked_file(self) -> None:
        """Verify new untracked files are detected and cause state divergence."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-untracked",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Clean check"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                # Create unexpected untracked file
                git_repo.untracked_file("scratch.txt", "some temporary notes")

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("diff_hash: expected" in c or "changed_files differ" in c for c in verify_res.conflicts))

    def test_e2e_t1_verify_fail_closed_unknown_confidence(self) -> None:
        """Verify verification fails closed to REVIEW_REQUIRED when handoff contains unknowns (P5, P7)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-unknown-conf",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Unfinished session"),
                        SyntheticRolloutGenerator.make_func_call("call_9", "patch", "{}"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)

                # Since there is an unfinished tool call, overall_confidence is not verified
                self.assertEqual(verify_res.status, "REVIEW_REQUIRED")
                self.assertTrue(len(verify_res.review_reasons) > 0)


if __name__ == "__main__":
    unittest.main()
