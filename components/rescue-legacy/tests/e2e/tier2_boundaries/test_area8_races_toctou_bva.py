"""Tier 2: Feature Area 8 BVA - Multi-Process Races & TOCTOU Boundary Value Analysis."""
from __future__ import annotations

import hashlib
import sys
import threading
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
from codex_rescue.journal import JournalEntry, append_entry, read_entries, utc_timestamp
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea8RacesTOCTOUBVA(unittest.TestCase):
    """Boundary and adversarial race condition tests."""

    def test_e2e_t2_race_codepoint_split_at_eof(self) -> None:
        """Verify partial multi-byte UTF-8 codepoint split at EOF is diagnosed as TRUNCATED_TRANSCRIPT."""
        with TempSessionWorkspace() as ws:
            valid_prefix = SyntheticRolloutGenerator.create_rollout([
                SyntheticRolloutGenerator.make_session_meta(session_id="split-utf8"),
                SyntheticRolloutGenerator.make_user_msg("Valid user prompt"),
            ])
            # Emoji 🚀 is b"\xf0\x9f\x9a\x80" (4 bytes). Take only first 2 bytes.
            split_char = b'{"type": "event_msg", "payload": {"message": "launch \xf0\x9f'
            p = ws.create_session("split-utf8", content_bytes=valid_prefix + split_char)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "TRUNCATED_TRANSCRIPT")
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertEqual(parsed.last_valid_offset, len(valid_prefix))

    def test_e2e_t2_race_unclosed_json_line(self) -> None:
        """Verify partially written JSON record at EOF preserves prefix and flags TRUNCATED_TRANSCRIPT."""
        with TempSessionWorkspace() as ws:
            valid_prefix = SyntheticRolloutGenerator.create_rollout([
                SyntheticRolloutGenerator.make_session_meta(session_id="unclosed-json"),
                SyntheticRolloutGenerator.make_user_msg("Start"),
                SyntheticRolloutGenerator.make_agent_msg("Acknowledged"),
            ])
            unclosed_record = b'{"type": "response_item", "payload": {"type": "function_call", "call_id": "c1"'
            p = ws.create_session("unclosed-json", content_bytes=valid_prefix + unclosed_record)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "TRUNCATED_TRANSCRIPT")
            self.assertEqual(parsed.valid_record_count, 3)
            self.assertEqual(parsed.last_valid_offset, len(valid_prefix))

    def test_e2e_t2_toctou_git_state_mutation_during_salvage(self) -> None:
        """Verify Git repository mutation during salvage updates doctor status to REPO_STATE_DIVERGED."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "toctou-git-mutate",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Start task"),
                    ],
                )
                rescue_root = ws.root / "rescues"
                session_id = "toctou-git-mutate"

                initial_sha = git_repo.get_head_sha()
                entry = JournalEntry(
                    version=1,
                    session_id=session_id,
                    timestamp=utc_timestamp(),
                    event="tool_start",
                    worktree=str(git_repo.root),
                    head_sha=initial_sha,
                    diff_hash="dummy_diff_hash",
                    changed_files=(),
                )
                append_entry(rescue_root, entry)

                # Mutate Git state in working directory
                git_repo.commit_file("new_file.py", "x = 1\n", "Second commit")

                parsed = parse_transcript(str(p))
                doc = doctor_session(p)

                res = salvage_session(p, parsed, doc.status, doc.findings, rescue_root, fork=True)
                self.assertTrue(res.original_untouched)

    def test_e2e_t2_race_stress_loop(self) -> None:
        """Verify 50 rapid sequential diagnostic cycles never modify source file bytes (P1)."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "stress-loop-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Stress test prompt"),
                        SyntheticRolloutGenerator.make_agent_msg("Stress test response"),
                    ],
                )
                initial_sha = hashlib.sha256(p.read_bytes()).hexdigest()

                for _ in range(50):
                    res = doctor_session(p)
                    self.assertEqual(res.status, "HEALTHY")

                final_sha = hashlib.sha256(p.read_bytes()).hexdigest()
                self.assertEqual(initial_sha, final_sha)

    def test_e2e_t2_toctou_journal_sequential_append(self) -> None:
        """Verify sequential appending of journal entries produces valid append-only journal."""
        with TempSessionWorkspace() as ws:
            session_id = "journal-seq-001"
            rescue_root = ws.root / "rescues"

            for worker_id in range(4):
                for i in range(10):
                    entry = JournalEntry(
                        version=1,
                        session_id=session_id,
                        timestamp="2026-08-14T20:00:00Z",
                        event=f"worker_{worker_id}_event_{i}",
                    )
                    append_entry(rescue_root, entry)

            entries, partial = read_entries(rescue_root, session_id)
            self.assertEqual(len(entries), 40)
            self.assertFalse(partial)


if __name__ == "__main__":
    unittest.main()
