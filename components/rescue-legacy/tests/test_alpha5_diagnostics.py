import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.alpha5 import scan_rollout_alpha5
from codex_rescue.doctor import doctor_session
from codex_rescue.transcript import parse_transcript


class Alpha5DiagnosticsTests(unittest.TestCase):
    @staticmethod
    def _write(directory: str, records: list[dict]) -> Path:
        path = Path(directory) / "rollout.jsonl"
        path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _meta() -> dict:
        return {"type": "session_meta", "payload": {"id": "alpha5-test"}}

    def test_known_current_mcp_begin_no_longer_poisoned(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "mcp_tool_call_begin",
                            "call_id": "mcp-1",
                            "invocation": {"server": "s", "tool": "t"},
                        },
                    },
                ],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)
            self.assertEqual(
                diagnosis.schema_compatibility.recognized_types.get("mcp_tool_call_begin"), 1
            )

    def test_known_dynamic_tool_event_is_compatibility_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {
                        "type": "event_msg",
                        "payload": {"type": "dynamic_tool_call_request", "call_id": "dyn-1"},
                    },
                ],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_unknown_future_operational_type_still_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {
                        "type": "event_msg",
                        "payload": {"type": "future_event_v99", "call_id": "future-1"},
                    },
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)
            self.assertEqual(
                diagnosis.schema_compatibility.unknown_operational_types.get("future_event_v99"), 1
            )

    def test_valid_type_specific_ids(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "response_item", "payload": {"type": "message", "id": "msg_123", "role": "assistant", "content": []}},
                    {"type": "response_item", "payload": {"type": "reasoning", "id": "rs_123", "content": []}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("INVALID_PERSISTED_ITEM_ID", diagnosis.findings)

    def test_invalid_type_specific_id_prevents_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "response_item", "payload": {"type": "message", "id": "rs_wrong", "role": "assistant", "content": []}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("INVALID_PERSISTED_ITEM_ID", diagnosis.findings)
            self.assertNotEqual(diagnosis.status, "HEALTHY")

    def test_missing_optional_id_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "message", "role": "assistant", "content": []}}],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("INVALID_PERSISTED_ITEM_ID", diagnosis.findings)

    def test_legacy_unprefixed_id_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "message", "id": "legacyid", "role": "assistant", "content": []}}],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("INVALID_PERSISTED_ITEM_ID", diagnosis.findings)
            self.assertEqual(diagnosis.alpha5.legacy_unprefixed_id_count, 1)

    def test_future_unknown_type_is_schema_unknown_not_guessed_id_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "future_item_v99", "id": "fi_1"}}],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)
            self.assertNotIn("INVALID_PERSISTED_ITEM_ID", diagnosis.findings)

    def test_call_with_output_is_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "response_item", "payload": {"type": "function_call", "call_id": "c1", "name": "echo", "arguments": "{}"}},
                    {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "c1", "output": "ok"}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("UNFINISHED_TOOL_CALL", diagnosis.findings)

    def test_call_without_output_is_unfinished_not_nonexecution_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "function_call", "call_id": "c1", "name": "echo", "arguments": "{}"}}],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNFINISHED_TOOL_CALL", diagnosis.findings)
            serialized = json.dumps(diagnosis.to_dict()).lower()
            self.assertNotIn("did not execute", serialized)
            self.assertNotIn("not executed", serialized)

    def test_unmatched_output_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "orphan", "output": "ok"}}],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_duplicate_call_identifier_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            call = {"type": "response_item", "payload": {"type": "function_call", "call_id": "dup", "name": "echo", "arguments": "{}"}}
            path = self._write(
                directory,
                [self._meta(), call, call, {"type": "response_item", "payload": {"type": "function_call_output", "call_id": "dup", "output": "ok"}}],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)
            self.assertIn("UNFINISHED_TOOL_CALL", diagnosis.findings)

    def test_malformed_family_correlation_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "response_item", "payload": {"type": "function_call", "call_id": "c1", "name": "echo", "arguments": "{}"}},
                    {"type": "response_item", "payload": {"type": "custom_tool_call_output", "call_id": "c1", "output": "ok"}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_bounded_correlation_overflow_reduces_confidence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "response_item", "payload": {"type": "function_call", "call_id": "c1", "name": "echo", "arguments": "{}"}},
                    {"type": "response_item", "payload": {"type": "function_call", "call_id": "c2", "name": "echo", "arguments": "{}"}},
                ],
            )
            with patch("codex_rescue.transcript.MAX_CORRELATION_STATES", 1):
                parsed = parse_transcript(path)
            self.assertTrue(parsed.correlation_overflow)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")

    def test_explicit_a_b_a_writer_interleave_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "event_msg", "payload": {"type": "user_message", "message": "a", "writer_id": "A"}},
                    {"type": "event_msg", "payload": {"type": "user_message", "message": "b", "writer_id": "B"}},
                    {"type": "event_msg", "payload": {"type": "user_message", "message": "a2", "writer_id": "A"}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("INTERLEAVED_WRITERS", diagnosis.findings)

    def test_normal_subagent_metadata_is_not_writer_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "event_msg", "payload": {"type": "agent_spawned", "agent_id": "sub-1", "parent_thread_id": "root"}},
                    {"type": "event_msg", "payload": {"type": "agent_spawned", "agent_id": "sub-2", "parent_thread_id": "root"}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertNotIn("INTERLEAVED_WRITERS", diagnosis.findings)

    def test_lifecycle_never_claims_historical_start_is_live(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "event_msg", "payload": {"type": "agent_spawned", "agent_id": "sub-1"}}],
            )
            diagnosis = doctor_session(path)
            self.assertEqual(
                diagnosis.alpha5.lifecycle_statement,
                "No terminal marker observed in persisted history; live state is unavailable",
            )
            self.assertNotIn("currently running", json.dumps(diagnosis.to_dict()).lower())

    def test_terminal_lifecycle_marker_is_historical_evidence_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [
                    self._meta(),
                    {"type": "event_msg", "payload": {"type": "agent_spawned", "agent_id": "sub-1"}},
                    {"type": "event_msg", "payload": {"type": "agent_completed", "agent_id": "sub-1", "status": "completed"}},
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("live state is unavailable", diagnosis.alpha5.lifecycle_statement)

    def test_opaque_formats_are_classified_without_exposing_content(self):
        secret_values = ["gAAAA-nativeopaque012345", "ocx1:foreignopaque012345", "zzzzzzzzzzzzzzzzzzzz"]
        with tempfile.TemporaryDirectory() as directory:
            records = [self._meta()]
            for index, value in enumerate(secret_values):
                records.append(
                    {"type": "response_item", "payload": {"type": "reasoning", "id": f"rs_{index}", "encrypted_content": value}}
                )
            path = self._write(directory, records)
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.alpha5.opaque_content_formats.get("legacy_fernet_like"), 1)
            self.assertEqual(diagnosis.alpha5.opaque_content_formats.get("foreign_ocx1"), 1)
            self.assertEqual(diagnosis.alpha5.opaque_content_formats.get("unknown_opaque"), 1)
            serialized = json.dumps(diagnosis.to_dict())
            for value in secret_values:
                self.assertNotIn(value, serialized)

    def test_malformed_opaque_content_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(
                directory,
                [self._meta(), {"type": "response_item", "payload": {"type": "reasoning", "id": "rs_1", "encrypted_content": "x"}}],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_zero_byte_and_header_only_are_incomplete_not_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            empty = Path(directory) / "empty.jsonl"
            empty.write_bytes(b"")
            empty_diagnosis = doctor_session(empty)
            self.assertIn("INCOMPLETE_ROLLOUT", empty_diagnosis.findings)
            self.assertNotIn("MALFORMED_RECORD", empty_diagnosis.findings)

            header = Path(directory) / "header.jsonl"
            header.write_text(json.dumps(self._meta()) + "\n", encoding="utf-8")
            header_diagnosis = doctor_session(header)
            self.assertIn("INCOMPLETE_ROLLOUT", header_diagnosis.findings)

    def test_scan_marks_rollout_changed_during_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write(directory, [self._meta(), {"type": "event_msg", "payload": {"type": "user_message", "message": "ok"}}])
            with patch("codex_rescue.alpha5._stat_signature", side_effect=[(10, 1), (11, 2)]):
                diagnostics = scan_rollout_alpha5(path)
            self.assertTrue(diagnostics.source_changed_during_scan)

    def test_large_record_scan_is_bounded_and_reports_inline_media(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large.jsonl"
            record = {
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "data:image/png;base64," + ("A" * 5000)},
            }
            path.write_text(json.dumps(record) + "\n", encoding="utf-8")
            diagnostics = scan_rollout_alpha5(path, max_record_bytes=128)
            self.assertEqual(diagnostics.bounded_record_overflow_count, 1)
            self.assertEqual(diagnostics.inline_media_indicator_records, 1)
            self.assertGreater(diagnostics.largest_record_bytes, 128)


if __name__ == "__main__":
    unittest.main()
