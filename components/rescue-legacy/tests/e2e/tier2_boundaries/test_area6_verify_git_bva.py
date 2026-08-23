"""Tier 2: Feature Area 6 BVA - Verification & Git State Boundary Value Analysis."""
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
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from codex_rescue.verify import verify_rescue
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea6VerifyGitBVA(unittest.TestCase):
    """Boundary and corner case tests for verification under advanced Git states and index trust flags."""

    def test_e2e_t2_verify_index_flags_assume_unchanged(self) -> None:
        """Verify git index assume-unchanged flag causes divergence and fail-closed state."""
        with MockGitRepo() as git_repo:
            git_repo.commit_file("config.json", '{"mode": "prod"}', "Add config")
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-assume-unchanged",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Check configuration"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                # Set assume-unchanged flag on tracked file
                git_repo.set_assume_unchanged("config.json")

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("index flags" in c.lower() or "diff_hash" in c.lower() for c in verify_res.conflicts))

    def test_e2e_t2_verify_index_flags_skip_worktree(self) -> None:
        """Verify git index skip-worktree flag causes divergence against saved checkpoint."""
        with MockGitRepo() as git_repo:
            git_repo.commit_file("settings.local", "KEY=123", "Add settings")
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-skip-worktree",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Check settings"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                # Set skip-worktree flag on tracked file
                git_repo.set_skip_worktree("settings.local")

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("index flags" in c.lower() or "diff_hash" in c.lower() for c in verify_res.conflicts))

    def test_e2e_t2_verify_detached_head_matching_sha(self) -> None:
        """Verify repository in detached HEAD state matching saved head_sha yields SAFE_TO_CONTINUE."""
        with MockGitRepo() as git_repo:
            git_repo.detach_head()
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-detached-head",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Check detached head"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "SAFE_TO_CONTINUE")

    def test_e2e_t2_verify_source_rollout_deleted(self) -> None:
        """Verify verification fails closed to REVIEW_REQUIRED if source session is deleted post-salvage."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-deleted-src",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Start task"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                p.unlink()

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "REVIEW_REQUIRED")
                self.assertTrue(any("source rollout unavailable" in r.lower() for r in verify_res.review_reasons))

    def test_e2e_t2_verify_source_rollout_sha_mismatch(self) -> None:
        """Verify verification detects byte modification to source rollout and reports STATE_DIVERGED."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "verify-sha-mismatch",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Start task"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                salvage_res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)

                with open(p, "ab") as f:
                    f.write(b'{"type": "event_msg", "payload": {"message": "appended_post_salvage"}}\n')

                verify_res = verify_rescue(rescue_root, salvage_res.rescue_id)
                self.assertEqual(verify_res.status, "STATE_DIVERGED")
                self.assertTrue(any("source_sha256" in c for c in verify_res.conflicts))


if __name__ == "__main__":
    unittest.main()
