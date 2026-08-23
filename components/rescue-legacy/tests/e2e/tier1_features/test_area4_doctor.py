"""Tier 1: Feature Area 4 - Doctor Failure Classification Hierarchy."""
from __future__ import annotations

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

from codex_rescue.doctor import SEVERITY, doctor_session
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea4DoctorFeatures(unittest.TestCase):
    """End-to-end feature tests for diagnostic evaluation and severity hierarchy ordering."""

    def test_e2e_t1_doctor_severity_hierarchy_ordering(self) -> None:
        """Verify strict ordering index of all recognized severity status strings."""
        expected_order = [
            "UNKNOWN_CORRUPTION",
            "CORRUPTED_TOOL_CALL",
            "MALFORMED_RECORD",
            "TRUNCATED_TRANSCRIPT",
            "OVERSIZED_PAYLOAD",
            "VALID_BUT_OVERSIZED",
            "INTERLEAVED_WRITERS",
            "INVALID_PERSISTED_ITEM_ID",
            "UNKNOWN_OPERATIONAL_SCHEMA",
            "PROJECTION_STATE_UNKNOWN",
            "WEDGED_PROJECTION",
            "PERSISTED_PAGINATED_ORDINAL_REUSE",
            "ORDINAL_ANALYSIS_INCOMPLETE",
            "ACTIVE_WRITE_UNCERTAIN",
            "INCOMPLETE_ROLLOUT",
            "UNFINISHED_TOOL_CALL",
            "COMPACTION_STATE_LOSS",
            "REPO_STATE_DIVERGED",
            "SUBAGENT_HISTORY_BOUNDARY_SUSPECT",
            "THREAD_NAME_METADATA_DIVERGED",
            "INTERRUPTED_INPUT_NOT_DURABLE",
            "WORKSPACE_CONTEXT_MISMATCH",
            "THREAD_IDENTITY_CONFLICT",
            "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE",
            "HEALTHY",
        ]
        self.assertEqual(list(SEVERITY), expected_order)
        for i in range(len(expected_order) - 1):
            sev_high = expected_order[i]
            sev_low = expected_order[i + 1]
            self.assertLess(SEVERITY.index(sev_high), SEVERITY.index(sev_low))

    def test_e2e_t1_doctor_diagnose_unfinished_tool_call(self) -> None:
        """Verify an unclosed tool call produces UNFINISHED_TOOL_CALL diagnostic status."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="unfin-001"),
                SyntheticRolloutGenerator.make_user_msg("Edit file"),
                SyntheticRolloutGenerator.make_func_call("call_unclosed", "apply_patch", '{"patch": "..."}'),
            ]
            p = ws.create_session("unfin-001", records=records)

            result = doctor_session(p)
            self.assertEqual(result.status, "UNFINISHED_TOOL_CALL")
            self.assertIn("UNFINISHED_TOOL_CALL", result.findings)

    def test_e2e_t1_doctor_diagnose_compaction_loss(self) -> None:
        """Verify compaction with empty replacement history produces COMPACTION_STATE_LOSS."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="compact-loss-001"),
                SyntheticRolloutGenerator.make_user_msg("Task start"),
                SyntheticRolloutGenerator.make_func_call("call_1", "step", "{}"),
                SyntheticRolloutGenerator.make_func_output("call_1", "done"),
                SyntheticRolloutGenerator.make_compacted(
                    summary="Lossy summary",
                    replacement_history=[],  # Empty replacement history after operational events
                ),
            ]
            p = ws.create_session("compact-loss-001", records=records)

            result = doctor_session(p)
            self.assertEqual(result.status, "COMPACTION_STATE_LOSS")
            self.assertIn("COMPACTION_STATE_LOSS", result.findings)

    def test_e2e_t1_doctor_diagnose_malformed_record(self) -> None:
        """Verify invalid JSON syntax produces MALFORMED_RECORD status."""
        with TempSessionWorkspace() as ws:
            valid_meta = SyntheticRolloutGenerator.create_rollout([
                SyntheticRolloutGenerator.make_session_meta(session_id="malform-001"),
                SyntheticRolloutGenerator.make_user_msg("Valid user prompt"),
            ])
            malformed_line = b'{"type": "response_item", "payload": {unclosed_json...\n'
            p = ws.create_session("malform-001", content_bytes=valid_meta + malformed_line)

            result = doctor_session(p)
            self.assertEqual(result.status, "MALFORMED_RECORD")
            self.assertIn("MALFORMED_RECORD", result.findings)

    def test_e2e_t1_doctor_diagnose_healthy(self) -> None:
        """Verify complete session in clean Git repo evaluates to HEALTHY status."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                records = [
                    SyntheticRolloutGenerator.make_session_meta(
                        session_id="healthy-001",
                        cwd=str(git_repo.root),
                    ),
                    SyntheticRolloutGenerator.make_user_msg("Run check"),
                    SyntheticRolloutGenerator.make_agent_msg("Checked"),
                    SyntheticRolloutGenerator.make_func_call("call_h", "echo", '{"msg": "hi"}'),
                    SyntheticRolloutGenerator.make_func_output("call_h", "hi"),
                ]
                p = ws.create_session("healthy-001", records=records)

                result = doctor_session(p)
                self.assertEqual(result.status, "HEALTHY")
                self.assertEqual(result.findings, ["HEALTHY"])
                self.assertIsNotNone(result.repository.get("head_sha"))


if __name__ == "__main__":
    unittest.main()
