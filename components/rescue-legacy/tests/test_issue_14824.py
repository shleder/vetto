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
FIXTURE = ROOT / "fixtures" / "issue_14824_orphaned_tool_output"


class Issue14824RegressionTests(unittest.TestCase):
    def test_public_orphaned_wait_is_diagnosed_and_kept_fail_closed(self) -> None:
        metadata = json.loads((FIXTURE / "metadata.json").read_text(encoding="utf-8"))
        self.assertTrue(metadata["derived_from_public_evidence"])
        self.assertFalse(metadata["created_from_real_rollout"])
        session = next((FIXTURE / "source_session").glob("*.jsonl"))
        parsed = parse_transcript(session)
        self.assertEqual(parsed.session_metadata["cli_version"], "0.147.0")
        self.assertIsNone(parsed.corruption_class)
        self.assertEqual(parsed.unfinished_tool_call_count, 1)
        self.assertEqual(parsed.unfinished_tool_calls[0]["call_id"], "call-14824-orphaned-wait")

        source_before = session.read_bytes()
        with tempfile.TemporaryDirectory() as td:
            rescue_root = Path(td) / "rescue"
            with materialize_fixture_git_repo(FIXTURE):
                doctor = doctor_session(session)
                self.assertEqual(doctor.status, "UNFINISHED_TOOL_CALL")
                salvage = salvage_session(
                    session,
                    doctor.transcript,
                    doctor.status,
                    doctor.findings,
                    rescue_root,
                    True,
                )
                self.assertTrue(salvage.original_untouched)
                verification = verify_rescue(rescue_root, salvage.rescue_id)

            self.assertEqual(verification.status, "REVIEW_REQUIRED")
            self.assertIn("unfinished action requires inspection before replay", verification.review_reasons)
        self.assertEqual(session.read_bytes(), source_before)

    def test_fixture_contract_matches_expected_statuses(self) -> None:
        expected = json.loads((FIXTURE / "expected.json").read_text(encoding="utf-8"))
        self.assertEqual(expected, {"doctor": "UNFINISHED_TOOL_CALL", "verify": "REVIEW_REQUIRED"})


if __name__ == "__main__":
    unittest.main()
