"""Tier 2: Feature Area 5 BVA - Forked Salvage Boundary Value Analysis."""
from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

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
import codex_rescue.salvage as salvage_mod
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea5SalvageBVA(unittest.TestCase):
    """Boundary and corner case tests for salvage artifact generation and immutability."""

    def test_e2e_t2_salvage_mtime_mutation_guard(self) -> None:
        """Verify modifying source file mtime during salvage triggers mutation abort (P1)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "mtime-guard-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Valid start"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                real_inspect = salvage_mod.inspect_git_state

                def _touching_inspect(cwd: str):
                    new_time = time.time() + 100
                    os.utime(p, (new_time, new_time))
                    return real_inspect(cwd)

                with patch.object(salvage_mod, "inspect_git_state", side_effect=_touching_inspect):
                    with self.assertRaises(RuntimeError) as ctx:
                        salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                    self.assertIn("mutated", str(ctx.exception).lower())

    def test_e2e_t2_salvage_secret_scrubbing_continuation(self) -> None:
        """Verify prompt containing API keys is redacted in generated RECOVERY_BRIEF.md (P8)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                secret = "sk-ant-api03-1234567890abcdef1234567890"
                p = ws.create_session(
                    "secret-salvage",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg(f"Authorize with secret {secret}"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                brief_text = Path(res.rescue_dir, "RECOVERY_BRIEF.md").read_text(encoding="utf-8")
                self.assertNotIn(secret, brief_text)

    def test_e2e_t2_salvage_50mb_transcript_bounded_brief(self) -> None:
        """Verify a large transcript produces a bounded RECOVERY_BRIEF.md (< 100KB)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                records = [
                    SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                ]
                for i in range(200):
                    records.append(SyntheticRolloutGenerator.make_user_msg(f"Turn {i} with long description " * 10))
                    records.append(SyntheticRolloutGenerator.make_agent_msg(f"Response {i} with detailed text " * 10))

                p = ws.create_session("large-salvage", records=records)
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                brief_path = Path(res.rescue_dir, "RECOVERY_BRIEF.md")
                self.assertTrue(brief_path.exists())
                self.assertLess(brief_path.stat().st_size, 100 * 1024)

    def test_e2e_t2_salvage_idempotency(self) -> None:
        """Verify salvage is strictly idempotent, producing identical bytes across runs."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "idempotent-salvage",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Test prompt"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)

                root1 = ws.root / "r1"
                root2 = ws.root / "r2"

                res1 = salvage_session(p, parsed, doc.status, doc.findings, root1, fork=True)
                res2 = salvage_session(p, parsed, doc.status, doc.findings, root2, fork=True)

                bytes1 = Path(res1.handoff_path).read_bytes()
                bytes2 = Path(res2.handoff_path).read_bytes()
                self.assertEqual(bytes1, bytes2)
                self.assertEqual(res1.rescue_id, res2.rescue_id)

    def test_e2e_t2_salvage_empty_session_safe(self) -> None:
        """Verify minimal session with header salvages cleanly without crashing."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                records = [
                    SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                ]
                p = ws.create_session("empty-salvage", records=records)
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                self.assertTrue(res.original_untouched)
                self.assertTrue(Path(res.handoff_path).exists())


if __name__ == "__main__":
    unittest.main()
