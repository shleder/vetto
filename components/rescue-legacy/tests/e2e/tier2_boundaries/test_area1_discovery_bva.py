"""Tier 2: Feature Area 1 BVA - Session Discovery Boundary Value Analysis."""
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

from codex_rescue.discovery import discover_sessions, lightweight_scan, resolve_latest
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea1DiscoveryBVA(unittest.TestCase):
    """Boundary and corner case tests for session discovery and scanner."""

    def test_e2e_t2_discovery_empty_root(self) -> None:
        """Verify discovery on completely empty directory returns empty list without error."""
        with TempSessionWorkspace() as ws:
            summaries = discover_sessions(ws.root)
            self.assertEqual(summaries, [])
            self.assertIsNone(resolve_latest(ws.root))

    def test_e2e_t2_discovery_nonexistent_directory(self) -> None:
        """Verify discovery on nonexistent path returns empty list safely."""
        fake_path = Path("C:/nonexistent/codex_rescue_fake_path_12345")
        summaries = discover_sessions(fake_path)
        self.assertEqual(summaries, [])
        self.assertIsNone(resolve_latest(fake_path))

    def test_e2e_t2_discovery_zero_byte_rollouts(self) -> None:
        """Verify 0-byte rollout file is handled gracefully without offset crashes."""
        with TempSessionWorkspace() as ws:
            empty_file = ws.create_session("empty-001", content_bytes=b"")
            summary = lightweight_scan(empty_file)
            self.assertEqual(summary.size, 0)
            self.assertIn(summary.status, ("healthy", "damaged", "suspicious"))

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 1)
            self.assertEqual(summaries[0].size, 0)

    def test_e2e_t2_discovery_secret_redaction_preview(self) -> None:
        """Verify prompt preview scrubs OpenAI API keys, GitHub tokens, and JWT credentials (P8)."""
        with TempSessionWorkspace() as ws:
            secret_prompt = (
                "Deploy with sk-live-12345678901234567890abcdef and token ghp_abcdef1234567890 "
                "using Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeak"
            )
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="secret-sess"),
                SyntheticRolloutGenerator.make_user_msg(secret_prompt),
            ]
            ws.create_session("secret-sess", records=records)

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 1)
            preview = summaries[0].prompt_preview
            self.assertIsNotNone(preview)
            self.assertNotIn("sk-live-", preview)
            self.assertNotIn("ghp_", preview)
            self.assertNotIn("eyJhbG", preview)
            self.assertTrue("[REDACTED" in preview)

    def test_e2e_t2_discovery_mtime_tie_breaking(self) -> None:
        """Verify deterministic tie-breaking by path when multiple sessions share exact same mtime."""
        with TempSessionWorkspace() as ws:
            fixed_mtime = 1700000000.0
            paths = []
            for name in ("sess-c", "sess-a", "sess-b", "sess-e", "sess-d"):
                p = ws.create_session(name, mtime=fixed_mtime)
                paths.append(p)

            summaries = discover_sessions(ws.root)
            self.assertEqual(len(summaries), 5)
            summary_ids = [s.session_id for s in summaries]
            self.assertEqual(summary_ids, sorted(summary_ids, reverse=True))


if __name__ == "__main__":
    unittest.main()
