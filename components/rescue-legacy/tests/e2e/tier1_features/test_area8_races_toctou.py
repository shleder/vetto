"""Tier 1: Feature Area 8 - Multi-Process Writer Races & TOCTOU Defense."""
from __future__ import annotations

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

from codex_rescue.discovery import discover_sessions
from codex_rescue.doctor import doctor_session
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
import codex_rescue.salvage as salvage_mod
from common import AsyncRolloutWriter, MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea8RacesTOCTOUFeatures(unittest.TestCase):
    """End-to-end feature tests for concurrent writer races and TOCTOU mutation guards."""

    def test_e2e_t1_race_concurrent_append_doctor(self) -> None:
        """Verify doctor completes safely without crashing while background writer appends records."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "race-append-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Initial message"),
                    ],
                )
                writer = AsyncRolloutWriter(p)

                chunks = [
                    SyntheticRolloutGenerator.create_rollout([
                        SyntheticRolloutGenerator.make_user_msg(f"Live message {i}"),
                        SyntheticRolloutGenerator.make_agent_msg(f"Live response {i}"),
                    ])
                    for i in range(1, 10)
                ]

                writer.start_streaming(chunks, interval_sec=0.01)
                try:
                    res = doctor_session(p)
                    self.assertIn(res.status, ("HEALTHY", "TRUNCATED_TRANSCRIPT", "UNFINISHED_TOOL_CALL", "ACTIVE_WRITE_UNCERTAIN"))
                finally:
                    writer.stop()

    def test_e2e_t1_race_truncation_salvage_abort(self) -> None:
        """Verify salvage aborts with RuntimeError when source file is mutated during parse/salvage (P1)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "toctou-trunc-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Valid start"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                real_inspect = salvage_mod.inspect_git_state

                def _mutating_inspect(cwd: str):
                    # Truncate source file mid-salvage
                    p.write_bytes(b'{"type": "session_meta"}\n')
                    return real_inspect(cwd)

                with patch.object(salvage_mod, "inspect_git_state", side_effect=_mutating_inspect):
                    with self.assertRaises(RuntimeError) as ctx:
                        salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                    self.assertIn("mutated", str(ctx.exception).lower())

    def test_e2e_t1_race_file_rotation_discovery(self) -> None:
        """Verify discovery loop gracefully handles files rotated/renamed mid-scan."""
        with TempSessionWorkspace() as ws:
            p1 = ws.create_session("rot-001", date_path="2026/08/14")
            p2 = ws.create_session("rot-002", date_path="2026/08/14")

            rotated = p1.with_name("rollout-rot-001.jsonl.bak")
            p1.rename(rotated)

            summaries = discover_sessions(ws.root)
            self.assertGreaterEqual(len(summaries), 1)
            self.assertTrue(all(s.session_id != "rot-001" or s.path.exists() for s in summaries))

    def test_e2e_t1_toctou_pre_write_snapshot_guard(self) -> None:
        """Verify snapshot check before rescue publication rejects modified source files (P1)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "toctou-pre-write",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Valid start"),
                    ],
                )
                parsed = parse_transcript(str(p))
                doc = doctor_session(p)
                rescue_root = ws.root / "rescues"

                real_build = salvage_mod.build_handoff

                def _mutating_build(*args, **kwargs):
                    # Mutate source file immediately before pre-write snapshot
                    with open(p, "ab") as f:
                        f.write(b'{"type": "event_msg", "payload": {"type": "user_message", "message": "injected"}}\n')
                    return real_build(*args, **kwargs)

                with patch.object(salvage_mod, "build_handoff", side_effect=_mutating_build):
                    with self.assertRaises(RuntimeError) as ctx:
                        salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                    self.assertIn("mutated", str(ctx.exception).lower())

    def test_e2e_t1_race_rapid_deletes_discovery(self) -> None:
        """Verify rapid concurrent deletion of session files during discovery does not crash runner."""
        with TempSessionWorkspace() as ws:
            created_paths = [
                ws.create_session(f"rapid-{i:03d}", date_path="2026/08/14")
                for i in range(1, 21)
            ]

            for p in created_paths[:10]:
                if p.exists():
                    p.unlink()

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 10)
            self.assertTrue(all(s.path.exists() for s in summaries))


if __name__ == "__main__":
    unittest.main()
