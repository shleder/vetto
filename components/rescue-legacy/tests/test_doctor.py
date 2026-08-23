from __future__ import annotations

import unittest
from pathlib import Path

from codex_rescue.doctor import doctor_session


class DoctorTests(unittest.TestCase):
    def test_fixture_primary_classes(self) -> None:
        root = Path(__file__).parents[1] / "fixtures"
        expected = {
            "kill_apply_patch": "UNFINISHED_TOOL_CALL",
            "kill_shell_before_result": "UNFINISHED_TOOL_CALL",
            "oversized_payload": "OVERSIZED_PAYLOAD",
            "malformed_jsonl": "MALFORMED_RECORD",
            "lost_tail_after_compaction": "COMPACTION_STATE_LOSS",
        }
        for name, status in expected.items():
            session = next((root / name / "source_session").glob("*.jsonl"))
            with self.subTest(name=name):
                self.assertEqual(doctor_session(session).status, status)


if __name__ == "__main__":
    unittest.main()
