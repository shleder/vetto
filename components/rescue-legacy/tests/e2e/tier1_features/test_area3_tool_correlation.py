"""Tier 1: Feature Area 3 - Tool Correlation & Sentinel Sanitization."""
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

from codex_rescue.transcript import CORRUPTED_TOOL_NAME_SENTINEL, parse_transcript
from common import SyntheticRolloutGenerator, TempSessionWorkspace


class TestArea3ToolCorrelationFeatures(unittest.TestCase):
    """End-to-end feature tests for tool call/output pairing and sentinel sanitization."""

    def test_e2e_t1_correlation_function_call_success(self) -> None:
        """Verify 1:1 function_call and function_call_output correlation retires cleanly."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="func-001"),
                SyntheticRolloutGenerator.make_func_call("call_abc", "shell_command", '{"cmd": "git status"}'),
                SyntheticRolloutGenerator.make_func_output("call_abc", "On branch main, clean"),
            ]
            p = ws.create_session("func-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)
            self.assertEqual(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(len(parsed.corrupted_tool_calls), 0)
            self.assertEqual(parsed.unfinished_tool_call_count, 0)

    def test_e2e_t1_correlation_custom_tool_success(self) -> None:
        """Verify custom_tool_call and custom_tool_call_output correlate across distinct IDs."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="cust-001"),
                SyntheticRolloutGenerator.make_custom_call("cust_123", "custom_linter", '{"target": "all"}'),
                SyntheticRolloutGenerator.make_custom_output("cust_123", "Lint 100% clean"),
            ]
            p = ws.create_session("cust-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)
            self.assertEqual(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(parsed.unfinished_tool_call_count, 0)

    def test_e2e_t1_correlation_tool_search_success(self) -> None:
        """Verify tool_search_call pairs with tool_search_output."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="search-001"),
                SyntheticRolloutGenerator.make_search_call("srch_999", "def calculate_total"),
                SyntheticRolloutGenerator.make_search_output("srch_999", "found in src/math.py:42"),
            ]
            p = ws.create_session("search-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)
            self.assertEqual(len(parsed.correlation_ambiguities), 0)

    def test_e2e_t1_sentinel_sanitization_control_chars(self) -> None:
        """Verify control characters in tool names are sanitized to sentinel without guessing (P4)."""
        with TempSessionWorkspace() as ws:
            # Control character \x1b (ESC) and \x07 (BEL) in tool name
            corrupted_name = "apply\x1b\x07_patch"
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="sentinel-001"),
                {
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "call_corrupted",
                        "name": corrupted_name,
                        "arguments": '{"file": "app.py"}',
                    },
                },
                SyntheticRolloutGenerator.make_func_output("call_corrupted", "Applied"),
            ]
            p = ws.create_session("sentinel-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(len(parsed.corrupted_tool_calls), 1)
            self.assertEqual(parsed.corruption_class, "CORRUPTED_TOOL_CALL")

            # Check that the event payload replaced name with sentinel
            call_events = [
                e for e in parsed.events
                if isinstance(e.payload, dict) and e.payload.get("type") == "function_call"
            ]
            self.assertEqual(len(call_events), 1)
            self.assertEqual(call_events[0].payload.get("name"), CORRUPTED_TOOL_NAME_SENTINEL)

    def test_e2e_t1_correlation_immediate_retirement(self) -> None:
        """Verify large sequence of completed tool calls are retired, preserving O(1) active state."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="retire-001"),
            ]
            for i in range(1, 51):
                cid = f"call_{i:04d}"
                records.append(SyntheticRolloutGenerator.make_func_call(cid, "echo", f'{{"msg": {i}}}'))
                records.append(SyntheticRolloutGenerator.make_func_output(cid, f"result {i}"))

            p = ws.create_session("retire-001", records=records)

            parsed = parse_transcript(str(p))
            self.assertEqual(parsed.valid_record_count, 101)  # 1 meta + 50*2
            self.assertEqual(len(parsed.unfinished_tool_calls), 0)
            self.assertEqual(len(parsed.correlation_ambiguities), 0)
            self.assertEqual(parsed.unfinished_tool_call_count, 0)
            self.assertFalse(parsed.correlation_overflow)


if __name__ == "__main__":
    unittest.main()
