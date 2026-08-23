"""Tier 2: Feature Area 3 BVA - Tool Correlation Boundary Value Analysis."""
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

from codex_rescue.transcript import CORRUPTED_TOOL_NAME_SENTINEL, MAX_CORRELATION_STATES, parse_transcript
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea3ToolCorrelationBVA(unittest.TestCase):
    """Boundary and adversarial corner case tests for tool correlation state machine."""

    def test_e2e_t2_correlation_orphaned_output(self) -> None:
        """Verify tool output without preceding call is marked as correlation ambiguity."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="orphan-001"),
                SyntheticRolloutGenerator.make_func_output("call_nonexistent", "Output from uncalled tool"),
            ]
            p = ws.create_session("orphan-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertGreater(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")

    def test_e2e_t2_correlation_duplicate_call_id(self) -> None:
        """Verify two tool calls with identical call_id are flagged as correlation ambiguity."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="dup-call-001"),
                SyntheticRolloutGenerator.make_func_call("call_shared_id", "tool_a", "{}"),
                SyntheticRolloutGenerator.make_func_call("call_shared_id", "tool_b", "{}"),
                SyntheticRolloutGenerator.make_func_output("call_shared_id", "Output for one of them"),
            ]
            p = ws.create_session("dup-call-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertGreater(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")

    def test_e2e_t2_correlation_cross_family_mismatch(self) -> None:
        """Verify function_call paired with custom_tool_call_output is rejected as family mismatch."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="mismatch-001"),
                SyntheticRolloutGenerator.make_func_call("mismatch_id", "tool_func", "{}"),
                SyntheticRolloutGenerator.make_custom_output("mismatch_id", "Custom tool output"),
            ]
            p = ws.create_session("mismatch-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertGreater(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")

    def test_e2e_t2_correlation_all_control_chars_tool_name(self) -> None:
        """Verify tool name composed entirely of control characters is sanitized to sentinel (P4)."""
        with TempSessionWorkspace() as ws:
            all_ctrl_name = "\x01\x02\x03\x1f\x7f"
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="all-ctrl-001"),
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "call_ctrl",
                        "name": all_ctrl_name,
                        "arguments": "{}",
                    },
                },
                SyntheticRolloutGenerator.make_func_output("call_ctrl", "done"),
            ]
            p = ws.create_session("all-ctrl-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.corruption_class, "CORRUPTED_TOOL_CALL")
            self.assertEqual(len(parsed.corrupted_tool_calls), 1)
            evidence = parsed.corrupted_tool_calls[0]
            self.assertEqual(evidence["name_length"], len(all_ctrl_name))
            self.assertIn(1, evidence["control_codepoints"])
            self.assertIn(0x7F, evidence["control_codepoints"])

    def test_e2e_t2_correlation_max_states_overflow(self) -> None:
        """Verify 1025 unfinished calls trigger correlation_overflow without unbounded memory."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="overflow-001"),
            ]
            # Exceed MAX_CORRELATION_STATES (1024)
            for i in range(1025):
                records.append(SyntheticRolloutGenerator.make_func_call(f"over_{i:04d}", "tool", "{}"))

            p = ws.create_session("overflow-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertTrue(parsed.correlation_overflow)
            self.assertEqual(parsed.corruption_class, "UNKNOWN_OPERATIONAL_SCHEMA")


if __name__ == "__main__":
    unittest.main()
