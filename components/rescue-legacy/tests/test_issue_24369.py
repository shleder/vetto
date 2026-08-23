from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.doctor import doctor_session
from codex_rescue.fixtures import materialize_fixture_git_repo
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import CORRUPTED_TOOL_NAME_SENTINEL, parse_transcript
from codex_rescue.verify import verify_rescue


ROOT = Path(__file__).resolve().parents[1]
REPO_FIXTURE = ROOT / "fixtures" / "oversized_payload"


def _write_sanitized_issue_24369_rollout(path: Path, cwd: Path, name: str, session_id: str) -> None:
    """Write only the public corruption boundary with synthetic data."""

    records = [
        {
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "session_id": session_id,
                "cwd": str(cwd),
                "cli_version": "0.133.0",
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "name": name,
                "call_id": f"call-{session_id}",
                "arguments": "{}",
            },
        },
    ]
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n" for record in records),
        encoding="utf-8",
    )


def _artifact_bytes(root: Path) -> list[tuple[Path, bytes]]:
    return [
        (path, path.read_bytes())
        for path in sorted(root.rglob("*"))
        if path.is_file()
    ]


class Issue24369RegressionTests(unittest.TestCase):
    def test_adversarial_corrupted_name_never_leaks_from_recovery_artifacts(self) -> None:
        raw_name = "safe_prefix" + "\x00\n\t\x01"
        controls = [0, 1, 9, 10]
        expected_hash = hashlib.sha256(raw_name.encode("utf-8", "surrogatepass")).hexdigest()

        with tempfile.TemporaryDirectory() as td:
            session = Path(td) / "rollout-issue-24369-adversarial.jsonl"
            with materialize_fixture_git_repo(REPO_FIXTURE) as repo:
                _write_sanitized_issue_24369_rollout(
                    session,
                    repo,
                    raw_name,
                    "issue-24369-adversarial",
                )
                source_before = session.read_bytes()
                source_hash_before = hashlib.sha256(source_before).hexdigest()

                parsed = parse_transcript(session)
                self.assertEqual(parsed.corruption_class, "CORRUPTED_TOOL_CALL")
                self.assertEqual(parsed.corrupted_tool_calls[0]["name_length"], len(raw_name))
                self.assertEqual(parsed.corrupted_tool_calls[0]["control_codepoints"], controls)
                self.assertEqual(parsed.corrupted_tool_calls[0]["control_character_count"], len(controls))
                self.assertEqual(parsed.corrupted_tool_calls[0]["name_sha256"], expected_hash)
                self.assertEqual(parsed.unfinished_tool_call_count, 1)
                self.assertEqual(parsed.unfinished_tool_calls[0]["tool_name"], CORRUPTED_TOOL_NAME_SENTINEL)
                self.assertEqual(parsed.events[-1].payload["name"], CORRUPTED_TOOL_NAME_SENTINEL)

                doctor = doctor_session(session)
                self.assertEqual(doctor.status, "CORRUPTED_TOOL_CALL")
                self.assertEqual(doctor.findings, ["CORRUPTED_TOOL_CALL", "UNFINISHED_TOOL_CALL"])
                doctor_serialized = json.dumps(doctor.to_dict(), ensure_ascii=False, sort_keys=True)
                self._assert_no_raw_name(doctor_serialized, raw_name)
                self.assertEqual(session.read_bytes(), source_before)

                with tempfile.TemporaryDirectory() as rescue_td:
                    rescue_root = Path(rescue_td)
                    salvage = salvage_session(
                        session,
                        doctor.transcript,
                        doctor.status,
                        doctor.findings,
                        rescue_root,
                        True,
                    )
                    self.assertTrue(salvage.original_untouched)
                    self.assertEqual(salvage.source_sha256_before, source_hash_before)
                    self.assertEqual(salvage.source_sha256_after, source_hash_before)

                    handoff_path = Path(salvage.handoff_path)
                    handoff = json.loads(handoff_path.read_text(encoding="utf-8"))
                    self.assertEqual(
                        handoff["tool_state"]["unfinished_action"]["type"],
                        CORRUPTED_TOOL_NAME_SENTINEL,
                    )
                    self.assertEqual(
                        handoff["transcript"]["corrupted_tool_calls"][0]["name_sha256"],
                        expected_hash,
                    )
                    self.assertEqual(
                        handoff["transcript"]["corrupted_tool_calls"][0]["control_codepoints"],
                        controls,
                    )

                    brief = (handoff_path.parent / "RECOVERY_BRIEF.md").read_text(encoding="utf-8")
                    verify = verify_rescue(rescue_root, salvage.rescue_id)
                    verify_serialized = json.dumps(verify.to_dict(), ensure_ascii=False, sort_keys=True)
                    salvage_serialized = json.dumps(salvage.to_dict(), ensure_ascii=False, sort_keys=True)

                    for text in (salvage_serialized, json.dumps(handoff, ensure_ascii=False, sort_keys=True), brief, verify_serialized):
                        self._assert_no_raw_name(text, raw_name)
                    for path, data in _artifact_bytes(handoff_path.parent):
                        self._assert_no_raw_name(data.decode("utf-8"), raw_name)
                        self.assertNotIn(b"\x00", data)
                        self.assertNotIn(b"\x01", data)
                        self.assertNotIn(b"\t", data)

                    self.assertEqual(verify.status, "REVIEW_REQUIRED")
                    self.assertIn("corrupted tool-call metadata requires review", verify.review_reasons)
                    self.assertIn("unfinished action requires inspection before replay", verify.review_reasons)

                self.assertEqual(session.read_bytes(), source_before)
                self.assertEqual(hashlib.sha256(session.read_bytes()).hexdigest(), source_hash_before)

    def test_name_made_only_of_controls_is_replaced_by_sentinel(self) -> None:
        raw_name = "\x00\n\t\x01"
        with tempfile.TemporaryDirectory() as td:
            session = Path(td) / "rollout-issue-24369-controls.jsonl"
            with materialize_fixture_git_repo(REPO_FIXTURE) as repo:
                _write_sanitized_issue_24369_rollout(session, repo, raw_name, "issue-24369-controls")
                parsed = parse_transcript(session)
                self.assertEqual(parsed.corruption_class, "CORRUPTED_TOOL_CALL")
                self.assertEqual(parsed.corrupted_tool_calls[0]["name_length"], 4)
                self.assertEqual(parsed.corrupted_tool_calls[0]["control_codepoints"], [0, 1, 9, 10])
                self.assertEqual(parsed.unfinished_tool_calls[0]["tool_name"], CORRUPTED_TOOL_NAME_SENTINEL)
                self.assertEqual(parsed.events[-1].payload["name"], CORRUPTED_TOOL_NAME_SENTINEL)

    def test_valid_tool_name_remains_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session = Path(td) / "rollout-issue-24369-valid.jsonl"
            with materialize_fixture_git_repo(REPO_FIXTURE) as repo:
                _write_sanitized_issue_24369_rollout(session, repo, "apply_patch", "issue-24369-valid")
                parsed = parse_transcript(session)
                self.assertIsNone(parsed.corruption_class)
                self.assertEqual(parsed.corrupted_tool_calls, [])
                self.assertEqual(parsed.unfinished_tool_calls[0]["tool_name"], "apply_patch")
                self.assertEqual(parsed.events[-1].payload["name"], "apply_patch")

    def _assert_no_raw_name(self, text: str, raw_name: str) -> None:
        self.assertNotIn(raw_name, text)
        self.assertNotIn("safe_prefix" + "\x00", text)
        self.assertNotIn("safe_prefix" + "\n", text)
        self.assertNotIn("safe_prefix" + "\t", text)
        self.assertNotIn("safe_prefix" + "\x01", text)


if __name__ == "__main__":
    unittest.main()
