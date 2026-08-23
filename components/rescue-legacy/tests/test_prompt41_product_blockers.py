import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.doctor import doctor_session
from codex_rescue.gitstate import GitStateError
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from codex_rescue.verify import verify_rescue


class Prompt41ProductBlockerTests(unittest.TestCase):
    @staticmethod
    def _meta(cwd=None):
        payload = {"id": "prompt41-session", "session_id": "prompt41-session"}
        if cwd is not None:
            payload["cwd"] = str(cwd)
        return {"type": "session_meta", "payload": payload}

    @staticmethod
    def _event(kind, **payload):
        return {"type": "event_msg", "payload": {"type": kind, **payload}}

    @staticmethod
    def _call(call_id="call-1", name="echo", **payload):
        return {
            "type": "event_msg",
            "payload": {
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": "{}",
                **payload,
            },
        }

    @staticmethod
    def _output(call_id="call-1"):
        return {
            "type": "event_msg",
            "payload": {
                "type": "function_call_output",
                "call_id": call_id,
                "output": "ok",
            },
        }

    @classmethod
    def _write_session(cls, directory, records):
        path = Path(directory) / "rollout.jsonl"
        path.write_text(
            "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
            encoding="utf-8",
        )
        return path

    def test_valid_mcp_tool_call_end_is_not_unknown_or_unfinished(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [
                    self._meta(),
                    self._event(
                        "mcp_tool_call_end",
                        call_id="mcp-1",
                        status="completed",
                    ),
                ],
            )
            parsed = parse_transcript(path)
            self.assertEqual(parsed.operational_schema_issues, [])
            self.assertEqual(parsed.unfinished_tool_calls, [])
            self.assertIsNone(parsed.corruption_class)
            diagnosis = doctor_session(path)
            self.assertNotIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_completed_tool_call_is_not_unfinished(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [self._meta(), self._call(), self._output()],
            )
            parsed = parse_transcript(path)
            self.assertEqual(parsed.unfinished_tool_calls, [])
            diagnosis = doctor_session(path)
            self.assertNotIn("UNFINISHED_TOOL_CALL", diagnosis.findings)

    def test_mcp_end_does_not_hide_independent_unfinished_call(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [
                    self._meta(),
                    self._event(
                        "mcp_tool_call_end",
                        call_id="mcp-1",
                        status="completed",
                    ),
                    self._call(call_id="unfinished-1", name="wait"),
                ],
            )
            parsed = parse_transcript(path)
            self.assertEqual(len(parsed.operational_schema_issues), 0)
            self.assertEqual([item["call_id"] for item in parsed.unfinished_tool_calls], ["unfinished-1"])
            diagnosis = doctor_session(path)
            self.assertIn("UNFINISHED_TOOL_CALL", diagnosis.findings)

    def test_malformed_unknown_operational_record_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [
                    self._meta(),
                    self._event(
                        "future_event_v99",
                        call_id="future-1",
                        ordinal=1,
                    ),
                ],
            )
            parsed = parse_transcript(path)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")
            self.assertEqual(len(parsed.operational_schema_issues), 1)

    def test_unknown_metadata_on_known_record_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [
                    self._meta(),
                    self._call(future_metadata={"display_hint": "ignored"}),
                    self._output(),
                ],
            )
            parsed = parse_transcript(path)
            self.assertEqual(parsed.operational_schema_issues, [])
            self.assertEqual(parsed.unfinished_tool_calls, [])
            self.assertIsNone(parsed.corruption_class)

    def test_unknown_future_event_before_or_after_healthy_history_is_not_healthy(self):
        cases = (
            [self._meta(), self._event("future_event_v99", call_id="future-before") , self._event("user_message", message="ok")],
            [self._meta(), self._event("user_message", message="ok"), self._event("future_event_v99", call_id="future-after")],
        )
        for records in cases:
            with self.subTest(order=records[1]["payload"]["type"]):
                with tempfile.TemporaryDirectory() as directory:
                    path = self._write_session(directory, records)
                    diagnosis = doctor_session(path)
                    self.assertNotEqual(diagnosis.status, "HEALTHY")
                    self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)

    def test_unknown_future_event_preserves_known_defect(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(
                directory,
                [
                    self._meta(),
                    self._event("future_event_v99", call_id="future-1"),
                    self._call(call_id="unfinished-1", name="wait"),
                ],
            )
            diagnosis = doctor_session(path)
            self.assertIn("UNKNOWN_OPERATIONAL_SCHEMA", diagnosis.findings)
            self.assertIn("UNFINISHED_TOOL_CALL", diagnosis.findings)

    def test_non_git_and_svn_like_workspaces_are_not_git_divergence(self):
        for svn_like in (False, True):
            with self.subTest(svn_like=svn_like), tempfile.TemporaryDirectory() as directory:
                workspace = Path(directory) / "workspace"
                workspace.mkdir()
                if svn_like:
                    (workspace / ".svn").mkdir()
                    (workspace / ".svn" / "entries").write_text("", encoding="utf-8")
                path = self._write_session(directory, [self._meta(workspace), self._event("user_message", message="ok")])
                diagnosis = doctor_session(path)
                self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)
                self.assertEqual(diagnosis.repository.get("confidence"), "unknown")

    def test_nonexistent_repository_is_unknown_not_diverged(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "does-not-exist"
            path = self._write_session(directory, [self._meta(missing), self._event("user_message", message="ok")])
            diagnosis = doctor_session(path)
            self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)
            self.assertEqual(diagnosis.repository.get("confidence"), "unknown")

    def test_git_command_error_is_unknown_not_diverged(self):
        with tempfile.TemporaryDirectory() as directory:
            path = self._write_session(directory, [self._meta(Path(directory)), self._event("user_message", message="ok")])
            with patch(
                "codex_rescue.doctor.inspect_git_state",
                side_effect=GitStateError("git executable unavailable"),
            ):
                diagnosis = doctor_session(path)
            self.assertNotIn("REPO_STATE_DIVERGED", diagnosis.findings)
            self.assertEqual(diagnosis.repository.get("confidence"), "unknown")

    def test_verify_unavailable_repository_is_review_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workspace = root / "workspace"
            workspace.mkdir()
            source = self._write_session(
                root,
                [self._meta(workspace), self._event("user_message", message="ok")],
            )
            parsed = parse_transcript(source)
            diagnosis = doctor_session(source)
            rescue = salvage_session(
                source,
                parsed,
                diagnosis.status,
                diagnosis.findings,
                root / "rescues",
                fork=True,
            )
            with patch(
                "codex_rescue.verify.inspect_git_state",
                side_effect=GitStateError("git repository unavailable"),
            ):
                verification = verify_rescue(root / "rescues", rescue.rescue_id)
            self.assertEqual(verification.status, "REVIEW_REQUIRED")
            self.assertTrue(verification.review_reasons)
            self.assertEqual(verification.conflicts, ())


if __name__ == "__main__":
    unittest.main()
