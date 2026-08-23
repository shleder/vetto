"""Tier 1: Feature Area 2 - Transcript Parsing & Stream Handling."""
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

from codex_rescue.transcript import parse_transcript
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea2TranscriptFeatures(unittest.TestCase):
    """End-to-end feature tests for stream parsing, encoding, and event retention."""

    def test_e2e_t1_transcript_linear_flow(self) -> None:
        """Verify standard nominal session parse with complete tool call/output lifecycle."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="linear-001"),
                SyntheticRolloutGenerator.make_user_msg("Please run tests"),
                SyntheticRolloutGenerator.make_agent_msg("Running test suite now."),
                SyntheticRolloutGenerator.make_func_call("call_1", "shell_command", '{"cmd": "pytest"}'),
                SyntheticRolloutGenerator.make_func_output("call_1", "5 passed"),
            ]
            p = ws.create_session("linear-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 5)
            self.assertIsNone(parsed.corruption_class)
            self.assertIsNone(parsed.first_invalid_offset)
            self.assertEqual(parsed.unfinished_tool_call_count, 0)
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)
            self.assertTrue(parsed.recoverable_prefix)
            self.assertEqual(parsed.session_metadata.get("session_id"), "linear-001")

    def test_e2e_t1_transcript_mixed_crlf_lf(self) -> None:
        """Verify stream parsing correctly handles mixed Windows CRLF and POSIX LF delimiters."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="crlf-001"),
            ]
            for i in range(1, 10):
                records.append(SyntheticRolloutGenerator.make_user_msg(f"Message {i}"))

            # Alternating CRLF and LF
            buf = bytearray()
            for idx, rec in enumerate(records):
                delim = b"\r\n" if idx % 2 == 0 else b"\n"
                buf.extend(json.dumps(rec).encode("utf-8") + delim)

            p = ws.create_session("crlf-001", content_bytes=bytes(buf))

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 10)
            self.assertIsNone(parsed.corruption_class)
            self.assertEqual(parsed.last_valid_offset, len(buf))

    def test_e2e_t1_transcript_utf8_bom_support(self) -> None:
        """Verify UTF-8 Byte Order Mark (BOM: \\xef\\xbb\\xbf) at byte 0 parses cleanly."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="bom-001"),
                SyntheticRolloutGenerator.make_user_msg("Hello world with BOM"),
            ]
            content = SyntheticRolloutGenerator.create_rollout(records, prepend_bom=True)
            p = ws.create_session("bom-001", content_bytes=content)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertIsNone(parsed.corruption_class)
            self.assertEqual(parsed.session_metadata.get("session_id"), "bom-001")

    def test_e2e_t1_transcript_large_inline_image_detection(self) -> None:
        """Verify oversized record exceeding threshold is classified as OVERSIZED_PAYLOAD."""
        with TempSessionWorkspace() as ws:
            large_b64 = "A" * (600 * 1024)  # 600KB base64
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="img-001"),
                {
                    "type": "response_item",
                    "payload": {
                        "type": "custom_tool_call",
                        "call_id": "img_call_1",
                        "name": "render_view",
                        "arguments": f'{{"image": "data:image/png;base64,{large_b64}"}}',
                    },
                },
                SyntheticRolloutGenerator.make_custom_output("img_call_1", "Rendered successfully"),
            ]
            p = ws.create_session("img-001", records=records)

            # Pass threshold 500KB so 600KB triggers oversized record detection
            parsed = parse_transcript(str(p), oversized_threshold=500_000)
            self.assertGreater(len(parsed.oversized_records), 0)
            self.assertEqual(parsed.corruption_class, "OVERSIZED_PAYLOAD")

    def test_e2e_t1_transcript_compaction_event_parsed(self) -> None:
        """Verify compacted record with valid replacement history sets compacted=True."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="compact-001"),
                SyntheticRolloutGenerator.make_user_msg("Initial instructions"),
                SyntheticRolloutGenerator.make_agent_msg("First phase completed"),
                SyntheticRolloutGenerator.make_compacted(
                    summary="History compacted cleanly",
                    replacement_history=[
                        {"type": "user_message", "message": "Initial summary"},
                        {"type": "agent_message", "message": "Previous steps completed"},
                    ],
                ),
                SyntheticRolloutGenerator.make_user_msg("Next step after compaction"),
            ]
            p = ws.create_session("compact-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertTrue(parsed.compacted)
            self.assertFalse(parsed.compaction_state_loss)
            self.assertEqual(parsed.valid_record_count, 5)


if __name__ == "__main__":
    unittest.main()
