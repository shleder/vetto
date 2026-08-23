from __future__ import annotations

import unittest
from types import SimpleNamespace

from codex_rescue.reconstruct import build_handoff


class ReconstructTests(unittest.TestCase):
    def test_model_prose_never_verifies_tests_and_unfinished_stays_unknown(self) -> None:
        parsed = SimpleNamespace(
            events=[
                {"type": "event_msg", "payload": {"type": "user_message", "message": "fix race"}},
                {"type": "response_item", "payload": {"type": "message", "content": "pytest passed"}},
            ],
            session_metadata={"session_id": "s", "cwd": None},
            unfinished_tool_calls=[{"tool_name": "shell", "command": "pytest", "offset": 42}],
            last_valid_offset=100,
            first_invalid_offset=None,
            valid_record_count=2,
            record_types={"event_msg": 1, "response_item": 1},
            oversized_records=[],
            sha256="abc",
            compacted=False,
        )
        handoff = build_handoff("session.jsonl", parsed, None, [], "UNFINISHED_TOOL_CALL", ["UNFINISHED_TOOL_CALL"])
        self.assertEqual(handoff["tests"], [])
        self.assertEqual(handoff["tool_state"]["unfinished_action"]["confidence"], "unknown")
        self.assertEqual(handoff["overall_confidence"], "unknown")

    def test_durable_exit_code_verifies_test(self) -> None:
        parsed = SimpleNamespace(
            events=[{"type": "response_item", "payload": {"type": "function_call_output", "call_id": "t", "output": {"command": "pytest", "exit_code": 0}}}],
            session_metadata={"session_id": "s", "cwd": None}, unfinished_tool_calls=[],
            last_valid_offset=1, first_invalid_offset=None, valid_record_count=1,
            record_types={}, oversized_records=[], sha256="abc", compacted=False,
        )
        handoff = build_handoff("session.jsonl", parsed, None, [], "HEALTHY", ["HEALTHY"])
        self.assertEqual(handoff["tests"][0]["confidence"], "verified")
        self.assertEqual(handoff["tests"][0]["result"], "pass")

    def test_handoff_redacts_secrets_from_prompt_and_tool_output(self) -> None:
        parsed = SimpleNamespace(
            events=[
                {"type": "event_msg", "payload": {"type": "user_message", "message": "use api_key=super-secret-value"}},
                {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "x", "output": "Authorization: Bearer private-token"}},
            ],
            session_metadata={"session_id": "s", "cwd": None}, unfinished_tool_calls=[],
            last_valid_offset=1, first_invalid_offset=None, valid_record_count=2,
            record_types={}, oversized_records=[], sha256="abc", compacted=False,
        )
        handoff = build_handoff("session.jsonl", parsed, None, [], "HEALTHY", ["HEALTHY"])
        serialized = str(handoff)
        self.assertNotIn("super-secret-value", serialized)
        self.assertNotIn("private-token", serialized)
        self.assertIn("REDACTED", serialized)


if __name__ == "__main__":
    unittest.main()
