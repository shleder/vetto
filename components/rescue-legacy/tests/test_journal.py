from __future__ import annotations

import tempfile
import unittest
import json
from pathlib import Path

from codex_rescue.hooks import HOOK_EVENTS, capture_hook
from codex_rescue.journal import JournalEntry, append_entry, journal_path, read_entries, utc_timestamp


class JournalTests(unittest.TestCase):
    def test_valid_entries_survive_partial_final_checkpoint(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            entry = JournalEntry(version=1, session_id="session/a", timestamp=utc_timestamp(), event="Stop")
            path = append_entry(root, entry)
            with path.open("ab") as stream:
                stream.write(b'{"version":1,"session_id":')
            entries, partial = read_entries(root, "session/a")
            self.assertTrue(partial)
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["event"], "Stop")
            self.assertEqual(path, journal_path(root, "session/a"))

    def test_current_codex_hook_events_are_accepted_and_bounded(self) -> None:
        expected = {
            "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PermissionRequest", "PreCompact", "PostCompact", "Stop",
            "SessionEnd", "SubagentStart", "SubagentStop",
        }
        self.assertEqual(set(HOOK_EVENTS), expected)
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            common = {"session_id": "s", "cwd": td, "tool_use_id": "call-1", "tool_name": "Bash"}
            capture_hook("PreToolUse", root, {**common, "tool_input": {"command": "echo x"}})
            capture_hook("PostToolUse", root, {**common, "tool_input": {"command": "echo x"}, "tool_response": "ok"})
            entries, partial = read_entries(root, "s")
            self.assertFalse(partial)
            self.assertEqual(entries[0]["pending_action"]["tool_use_id"], "call-1")
            self.assertEqual(entries[1]["completed_actions"][0]["tool_use_id"], "call-1")
            self.assertEqual(entries[1]["commands"][0]["tool_name"], "Bash")

    def test_hook_redacts_secrets_and_large_inline_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capture_hook("UserPromptSubmit", root, {
                "session_id": "s", "cwd": td,
                "prompt": "api_key=private-value data:image/png;base64," + "A" * 2000,
            })
            raw = journal_path(root, "s").read_text(encoding="utf-8")
            self.assertNotIn("private-value", raw)
            self.assertNotIn("A" * 100, raw)
            self.assertIn("REDACTED", raw)


if __name__ == "__main__":
    unittest.main()
