from __future__ import annotations

import json
import unittest
from pathlib import Path

from codex_rescue.transcript import parse_transcript


ROOT = Path(__file__).resolve().parents[1]


class RealCorpusTests(unittest.TestCase):
    def test_sanitized_interrupted_case_preserves_unfinished_call(self) -> None:
        case = ROOT / "real-corpus" / "current-controlled-1"
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        parsed = parse_transcript(case / "session" / "rollout-sanitized.jsonl")
        self.assertTrue(metadata["created_from_real_codex"])
        self.assertEqual(metadata["failure_class"], "interrupted_tool_call")
        self.assertIsNone(parsed.corruption_class)
        self.assertEqual(parsed.valid_record_count, 24)
        self.assertEqual(len(parsed.unfinished_tool_calls), 1)

    def test_controlled_corrupt_copy_has_expected_truncated_prefix(self) -> None:
        case = ROOT / "real-corpus" / "current-corrupt-1"
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        sessions = list((case / "session").glob("*.jsonl"))
        self.assertEqual(len(sessions), 1)
        parsed = parse_transcript(sessions[0])
        self.assertTrue(metadata["created_from_real_codex"])
        self.assertTrue(metadata["private_validation_copy"]["corruption_induced_on_copy"])
        self.assertEqual(parsed.corruption_class, "TRUNCATED_TRANSCRIPT")
        self.assertEqual(parsed.first_invalid_offset, metadata["published_sanitized_fixture"]["first_invalid_offset"])


if __name__ == "__main__":
    unittest.main()
