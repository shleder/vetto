"""Tier 1: Feature Area 1 - Session Discovery & Head/Tail Scan."""
from __future__ import annotations

import sys
import time
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from codex_rescue.discovery import discover_sessions, resolve_latest
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea1DiscoveryFeatures(unittest.TestCase):
    """End-to-end feature tests for session discovery and resolution."""

    def test_e2e_t1_discovery_standard_directory(self) -> None:
        """Verify discovery extracts metadata from standard date-partitioned session tree."""
        with TempSessionWorkspace() as ws:
            base_time = 1700000000.0
            for i in range(1, 6):
                records = [
                    SyntheticRolloutGenerator.make_session_meta(
                        session_id=f"sess-00{i}",
                        cwd=f"C:/projects/repo_{i}",
                    ),
                    SyntheticRolloutGenerator.make_user_msg(f"Task description for session {i}"),
                    SyntheticRolloutGenerator.make_agent_msg(f"Acknowledged session {i}"),
                ]
                ws.create_session(
                    session_id=f"sess-00{i}",
                    records=records,
                    date_path=f"2026/08/1{i}",
                    mtime=base_time + (i * 100),
                )

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 5)
            # Verify sorting: newest mtime first
            self.assertEqual(summaries[0].session_id, "sess-005")
            self.assertEqual(summaries[-1].session_id, "sess-001")
            for s in summaries:
                self.assertIsNotNone(s.cwd)
                self.assertIsNotNone(s.first_prompt)
                self.assertGreater(s.size, 0)
                self.assertEqual(s.status, "healthy")

    def test_e2e_t1_discovery_limit_slicing(self) -> None:
        """Verify limit parameter strictly bounds result size to the N newest sessions."""
        with TempSessionWorkspace() as ws:
            base_time = 1700000000.0
            for i in range(1, 21):
                ws.create_session(
                    session_id=f"sess-{i:03d}",
                    date_path="2026/08/14",
                    mtime=base_time + i,
                )

            summaries_5 = discover_sessions(ws.root, limit=5)
            self.assertEqual(len(summaries_5), 5)
            self.assertEqual(summaries_5[0].session_id, "sess-020")
            self.assertEqual(summaries_5[4].session_id, "sess-016")

            summaries_10 = discover_sessions(ws.root, limit=10)
            self.assertEqual(len(summaries_10), 10)
            self.assertEqual(summaries_10[0].session_id, "sess-020")
            self.assertEqual(summaries_10[9].session_id, "sess-011")

    def test_e2e_t1_discovery_latest_resolution(self) -> None:
        """Verify resolve_latest deterministically returns the single newest session rollout path."""
        with TempSessionWorkspace() as ws:
            base_time = 1700000000.0
            expected_newest: Path | None = None
            for i in range(1, 11):
                p = ws.create_session(
                    session_id=f"sess-{i:03d}",
                    date_path="2026/08/14",
                    mtime=base_time + (i * 50),
                )
                if i == 10:
                    expected_newest = p

            resolved = resolve_latest(ws.root)
            self.assertIsNotNone(resolved)
            self.assertEqual(resolved.resolve(), expected_newest.resolve())

    def test_e2e_t1_discovery_archived_sessions_flag(self) -> None:
        """Verify archived sessions discovery inclusion and accurate flag marking."""
        with TempSessionWorkspace() as ws:
            ws.create_session("active-1", date_path="2026/08/14", archived=False, mtime=100.0)
            ws.create_session("active-2", date_path="2026/08/14", archived=False, mtime=200.0)
            ws.create_session("archived-1", date_path="2026/08/14", archived=True, mtime=300.0)
            ws.create_session("archived-2", date_path="2026/08/14", archived=True, mtime=400.0)

            # Default includes archived
            all_sessions = discover_sessions(ws.root, include_archived=True)
            self.assertEqual(len(all_sessions), 4)
            archived_items = [s for s in all_sessions if s.archived]
            active_items = [s for s in all_sessions if not s.archived]
            self.assertEqual(len(archived_items), 2)
            self.assertEqual(len(active_items), 2)

            # Exclude archived
            active_only = discover_sessions(ws.root, include_archived=False)
            self.assertEqual(len(active_only), 2)
            self.assertTrue(all(not s.archived for s in active_only))

    def test_e2e_t1_discovery_prompt_preview_extraction(self) -> None:
        """Verify initial and last user prompts are extracted from bounded window."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="sess-prompts"),
                SyntheticRolloutGenerator.make_user_msg("First prompt: please fix the bug."),
                SyntheticRolloutGenerator.make_agent_msg("Checking files."),
                SyntheticRolloutGenerator.make_func_call("call_1", "read_file", '{"path": "a.py"}'),
                SyntheticRolloutGenerator.make_func_output("call_1", "content of a.py"),
                SyntheticRolloutGenerator.make_user_msg("Last prompt: now run the test suite."),
                SyntheticRolloutGenerator.make_agent_msg("Running tests."),
            ]
            ws.create_session("sess-prompts", records=records, date_path="2026/08/14")

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 1)
            summary = summaries[0]
            self.assertEqual(summary.first_prompt, "First prompt: please fix the bug.")
            self.assertEqual(summary.last_prompt, "Last prompt: now run the test suite.")
            self.assertEqual(summary.prompt_preview, "Last prompt: now run the test suite.")


if __name__ == "__main__":
    unittest.main()
