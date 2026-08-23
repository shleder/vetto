"""Format regression tests for observed Codex rollout envelopes.

These tests intentionally generate tiny, sanitized structural records rather
than copying private rollouts.  They prove parser compatibility with the
locally observed 0.145.0-alpha.18 and 0.147.0 record shapes only; they are not
previous-binary installation, execution, or recovery validation.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.transcript import parse_transcript


def _write_records(path: Path, records: list[dict[str, object]]) -> None:
    """Write a minimal sanitized JSONL envelope for parser regression tests."""

    path.write_bytes(
        b"".join(
            (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
            for record in records
        )
    )


class FormatRegressionTests(unittest.TestCase):
    """Observed-format compatibility, not previous binary validation."""

    def test_observed_0145_alpha18_envelope_is_read(self) -> None:
        """Parse legacy metadata, interrupted call, abort, and compaction records."""

        records: list[dict[str, object]] = [
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": "sanitized-0145-alpha18",
                    "session_id": "sanitized-0145-alpha18",
                    "cwd": "C:/sanitized/repo",
                    "cli_version": "0.145.0-alpha.18",
                },
            },
            {
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "sanitized legacy task"},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "legacy-call-1",
                    "name": "shell_command",
                    "arguments": '{"command":"printf sanitized"}',
                },
            },
            {
                "type": "event_msg",
                "payload": {"type": "turn_aborted", "reason": "interrupted"},
            },
            {
                "type": "compacted",
                "payload": {
                    "message": "sanitized compaction summary",
                    "replacement_history": [],
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "message", "role": "assistant", "content": "sanitized tail"},
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout-sanitized-0145-alpha18.jsonl"
            _write_records(path, records)

            parsed = parse_transcript(path)

        self.assertEqual(parsed.valid_record_count, len(records))
        self.assertEqual(parsed.session_metadata["session_id"], "sanitized-0145-alpha18")
        self.assertEqual(parsed.session_metadata["cli_version"], "0.145.0-alpha.18")
        self.assertEqual(parsed.session_metadata["cwd"], "C:/sanitized/repo")
        self.assertEqual(parsed.record_types["session_meta"], 1)
        self.assertEqual(parsed.record_types["response_item/function_call"], 1)
        self.assertTrue(parsed.compacted)
        self.assertTrue(parsed.compaction_state_loss)
        self.assertGreaterEqual(parsed.operational_events_after_compaction, 1)
        self.assertEqual(len(parsed.unfinished_tool_calls), 1)
        self.assertEqual(parsed.unfinished_tool_calls[0]["call_id"], "legacy-call-1")
        self.assertTrue(
            any(
                event.payload.get("type") == "turn_aborted"
                for event in parsed.events
            )
        )

    def test_observed_0147_tool_call_variants_are_read(self) -> None:
        """Parse current function/custom tool calls and their durable outputs."""

        records: list[dict[str, object]] = [
            {
                "type": "session_meta",
                "payload": {
                    "session_id": "sanitized-0147",
                    "cwd": "C:/sanitized/repo",
                    "cli_version": "0.147.0",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "function-call-1",
                    "name": "shell_command",
                    "arguments": '{"command":"printf sanitized"}',
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call_output",
                    "call_id": "function-call-1",
                    "output": "sanitized output",
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call",
                    "call_id": "custom-call-1",
                    "name": "sanitized_tool",
                    "input": {"value": "sanitized"},
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "custom_tool_call_output",
                    "call_id": "custom-call-1",
                    "output": {"ok": True},
                },
            },
        ]

        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout-sanitized-0147.jsonl"
            _write_records(path, records)

            parsed = parse_transcript(path)

        self.assertEqual(parsed.valid_record_count, len(records))
        self.assertEqual(parsed.session_metadata["cli_version"], "0.147.0")
        self.assertEqual(parsed.record_types["response_item/function_call"], 1)
        self.assertEqual(parsed.record_types["response_item/custom_tool_call"], 1)
        self.assertEqual(parsed.record_types["response_item/function_call_output"], 1)
        self.assertEqual(parsed.record_types["response_item/custom_tool_call_output"], 1)
        self.assertEqual(parsed.unfinished_tool_calls, [])
        self.assertIsNone(parsed.corruption_class)


if __name__ == "__main__":
    unittest.main()
