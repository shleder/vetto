from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.doctor import doctor_session
from codex_rescue.fixtures import materialize_fixture_git_repo
from codex_rescue.salvage import salvage_session
from codex_rescue.transcript import parse_transcript
from codex_rescue.verify import verify_rescue


ROOT = Path(__file__).resolve().parents[1]
REPO_FIXTURE = ROOT / "fixtures" / "oversized_payload"


def _write_sanitized_issue_37719_rollout(path: Path, cwd: Path) -> None:
    """Write only the public structural boundary, with synthetic image data."""

    images = [
        {
            "type": "image_url",
            "image_url": "data:image/png;base64," + ("A" * 1_100_000),
        }
        for _ in range(8)
    ]
    records = [
        {
            "type": "session_meta",
            "payload": {
                "id": "issue-37719-sanitized",
                "session_id": "issue-37719-sanitized",
                "cwd": str(cwd),
                "cli_version": "0.147.0",
            },
        },
        {
            "type": "event_msg",
            "payload": {
                "type": "user_message",
                "message": "sanitized oversized-output probe",
            },
        },
        {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call-37719-sanitized",
                "output": {"content": images},
            },
        },
    ]
    path.write_text(
        "".join(json.dumps(record, separators=(",", ":")) + "\n" for record in records),
        encoding="utf-8",
    )


class Issue37719RegressionTests(unittest.TestCase):
    def test_large_custom_output_is_bounded_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session = Path(td) / "rollout-issue-37719-sanitized.jsonl"
            _write_sanitized_issue_37719_rollout(
                session,
                (REPO_FIXTURE / "repo_actual").resolve(),
            )
            source_before = session.read_bytes()

            with tempfile.TemporaryDirectory() as rescue_td:
                with materialize_fixture_git_repo(REPO_FIXTURE):
                    parsed = parse_transcript(session)
                    self.assertGreater(parsed.source_size, 8 * 1024 * 1024)
                    self.assertEqual(parsed.corruption_class, "OVERSIZED_PAYLOAD")
                    self.assertEqual(parsed.oversized_record_count, 1)
                    self.assertEqual(parsed.valid_record_count, 2)

                    doctor = doctor_session(session)
                    self.assertEqual(doctor.status, "OVERSIZED_PAYLOAD")
                    self.assertIn("OVERSIZED_PAYLOAD", doctor.findings)

                    salvage = salvage_session(
                        session,
                        doctor.transcript,
                        doctor.status,
                        doctor.findings,
                        Path(rescue_td),
                        True,
                    )
                    self.assertTrue(salvage.original_untouched)
                    verification = verify_rescue(Path(rescue_td), salvage.rescue_id)
                    self.assertEqual(verification.status, "REVIEW_REQUIRED")
                    self.assertTrue(verification.review_reasons)

            self.assertEqual(session.read_bytes(), source_before)


if __name__ == "__main__":
    unittest.main()
