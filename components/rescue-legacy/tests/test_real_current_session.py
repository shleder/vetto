from __future__ import annotations

import os
import unittest
from pathlib import Path

from codex_rescue.transcript import parse_transcript


class RealCurrentSessionTests(unittest.TestCase):
    def test_streams_current_session_when_supplied(self) -> None:
        value = os.environ.get("CODEX_RESCUE_REAL_SESSION")
        if not value:
            self.skipTest("CODEX_RESCUE_REAL_SESSION not supplied")
        path = Path(value)
        before = path.read_bytes()
        parsed = parse_transcript(path)
        after = path.read_bytes()
        self.assertEqual(before, after)
        self.assertGreater(parsed.valid_record_count, 0)
        self.assertEqual(parsed.sha256, __import__("hashlib").sha256(before).hexdigest())


if __name__ == "__main__":
    unittest.main()

