"""Tier 2: Feature Area 2 BVA - Transcript Parsing Boundary Value Analysis."""
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

from codex_rescue.transcript import MAX_RECORD_BYTES, parse_transcript
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea2TranscriptBVA(unittest.TestCase):
    """Boundary and corner case tests for transcript parsing, encoding, and limits."""

    def test_e2e_t2_transcript_nul_byte_in_line(self) -> None:
        """Verify NUL byte (\\x00) halts stream parsing at valid prefix with MALFORMED_RECORD."""
        with TempSessionWorkspace() as ws:
            valid_part = SyntheticRolloutGenerator.create_rollout([
                SyntheticRolloutGenerator.make_session_meta(session_id="nul-001"),
                SyntheticRolloutGenerator.make_user_msg("Valid prefix message"),
            ])
            corrupted_part = b'{"type": "event_msg", "payload": {"message": "bad \x00 character"}}\n'
            p = ws.create_session("nul-001", content_bytes=valid_part + corrupted_part)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "MALFORMED_RECORD")
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertEqual(parsed.last_valid_offset, len(valid_part))
            self.assertEqual(parsed.first_invalid_offset, len(valid_part))

    def test_e2e_t2_transcript_truncated_tail_no_newline(self) -> None:
        """Verify unclosed JSON line at EOF without newline is classified as TRUNCATED_TRANSCRIPT."""
        with TempSessionWorkspace() as ws:
            valid_part = SyntheticRolloutGenerator.create_rollout([
                SyntheticRolloutGenerator.make_session_meta(session_id="trunc-001"),
                SyntheticRolloutGenerator.make_user_msg("First prompt"),
            ])
            # Truncated partial JSON without closing brace or newline
            partial = b'{"type": "response_item", "payload": {"type": "agent_message", "message": "Incompl'
            p = ws.create_session("trunc-001", content_bytes=valid_part + partial)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "TRUNCATED_TRANSCRIPT")
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertEqual(parsed.last_valid_offset, len(valid_part))

    def test_e2e_t2_transcript_8mb_line_limit(self) -> None:
        """Verify oversized record exceeding 8MB MAX_RECORD_BYTES is drained without memory blowup."""
        with TempSessionWorkspace() as ws:
            # 8.5MB single record
            big_blob = "X" * (8 * 1024 * 1024 + 512 * 1024)
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="8mb-001"),
                {
                    "type": "event_msg",
                    "payload": {
                        "type": "user_message",
                        "message": big_blob,
                    },
                },
            ]
            p = ws.create_session("8mb-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "OVERSIZED_PAYLOAD")
            self.assertGreater(parsed.oversized_record_count, 0)
            self.assertGreater(parsed.source_size, MAX_RECORD_BYTES)

    def test_e2e_t2_transcript_control_chars_in_message(self) -> None:
        """Verify ANSI escape codes and ASCII control sequences in user messages parse cleanly."""
        with TempSessionWorkspace() as ws:
            ansi_msg = "Running \x1b[31;1mERROR\x1b[0m: status code \x1b[32m200\x1b[0m \x07"
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="ansi-001"),
                SyntheticRolloutGenerator.make_user_msg(ansi_msg),
            ]
            p = ws.create_session("ansi-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertIsNone(parsed.corruption_class)

    def test_e2e_t2_transcript_deeply_nested_json(self) -> None:
        """Verify deeply nested JSON structure is safely parsed without unhandled recursion crash."""
        with TempSessionWorkspace() as ws:
            # Build 50 layers of nested dicts
            nested: dict[str, Any] = {"leaf": "deep_value"}
            for i in range(50):
                nested = {f"level_{i}": nested}

            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="nest-001"),
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "call_nested",
                        "name": "process_tree",
                        "arguments": json.dumps(nested),
                    },
                },
                SyntheticRolloutGenerator.make_func_output("call_nested", "Processed tree"),
            ]
            p = ws.create_session("nest-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 3)
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)


if __name__ == "__main__":
    unittest.main()
