from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.transcript import parse_transcript


class TranscriptTests(unittest.TestCase):
    def test_valid_prefix_and_truncated_tail_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            valid = json.dumps({"type": "event_msg", "payload": {"type": "user_message"}}).encode() + b"\n"
            path.write_bytes(valid + b'{"type":"response_item"')
            result = parse_transcript(path)
            self.assertEqual(result.source_size, path.stat().st_size)
            self.assertEqual(result.last_valid_offset, len(valid))
            self.assertEqual(result.first_invalid_offset, len(valid))
            self.assertEqual(result.corruption_class, "TRUNCATED_TRANSCRIPT")
            self.assertTrue(result.recoverable_prefix)

    def test_oversized_and_unfinished_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            records = [
                {"type": "response_item", "payload": {"type": "input_image", "image_url": "data:image/png;base64," + "A" * 100}},
                {"type": "response_item", "payload": {"type": "function_call", "call_id": "c", "name": "shell_command", "arguments": "{\"command\":\"x\"}"}},
            ]
            path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records))
            result = parse_transcript(path, oversized_threshold=80)
            self.assertGreaterEqual(len(result.oversized_records), 1)
            self.assertEqual(result.unfinished_tool_calls[0]["call_id"], "c")
            self.assertNotIn("image_url", result.events[0].payload)

    def test_normal_inline_image_does_not_damage_session(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            record = {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "content": "data:image/png;base64," + "A" * (40 * 1024),
                },
            }
            path.write_bytes(json.dumps(record).encode() + b"\n")
            result = parse_transcript(path)
            self.assertEqual(result.oversized_records, [])
            self.assertIsNone(result.corruption_class)

    def test_tool_search_output_completes_matching_call(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            records = [
                {"type": "response_item", "payload": {"type": "tool_search_call", "call_id": "s", "name": "search"}},
                {"type": "response_item", "payload": {"type": "tool_search_output", "call_id": "s", "output": "ok"}},
            ]
            path.write_bytes(b"".join(json.dumps(record).encode() + b"\n" for record in records))
            self.assertEqual(parse_transcript(path).unfinished_tool_calls, [])

    def test_keeps_operational_tail_not_first_events(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            records = [
                {"type": "event_msg", "payload": {"type": "agent_message", "message": str(index)}}
                for index in range(20)
            ]
            path.write_bytes(b"".join(json.dumps(r).encode() + b"\n" for r in records))
            result = parse_transcript(path, max_events=5)
            self.assertEqual(len(result.events), 5)
            self.assertEqual(result.events[-1].payload["message"], "19")

    def test_malformed_variants(self) -> None:
        variants = {
            "truncated": (b'{"type":"x"', "TRUNCATED_TRANSCRIPT"),
            "malformed": (b'{not-json}\n', "MALFORMED_RECORD"),
            "embedded_nul": (b'{"type":"x' + bytes((0,)) + b'"}\n', "MALFORMED_RECORD"),
            "bad_args": (json.dumps({"type":"response_item","payload":{"type":"function_call","call_id":"x","name":"shell_command","arguments":"{bad"}}).encode()+b"\n", "MALFORMED_RECORD"),
        }
        with tempfile.TemporaryDirectory() as td:
            for name, (raw, expected) in variants.items():
                path = Path(td) / f"{name}.jsonl"
                path.write_bytes(raw)
                with self.subTest(name=name):
                    if name == "embedded_nul":
                        self.assertIn(bytes((0,)), raw)
                        self.assertIn(bytes((0,)), path.read_bytes())
                    self.assertEqual(parse_transcript(path).corruption_class, expected)

    def test_nul_stops_at_valid_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "s.jsonl"
            prefix = json.dumps({"type": "event_msg", "payload": {"type": "task_started"}}).encode() + b"\n"
            bad = b'{"type":"x' + bytes((0,)) + b'"}\n'
            suffix = json.dumps({"type": "event_msg", "payload": {"type": "task_complete"}}).encode() + b"\n"
            path.write_bytes(prefix + bad + suffix)
            result = parse_transcript(path)
            self.assertEqual(result.valid_record_count, 1)
            self.assertEqual(result.last_valid_offset, len(prefix))
            self.assertEqual(result.first_invalid_offset, len(prefix))


if __name__ == "__main__":
    unittest.main()
