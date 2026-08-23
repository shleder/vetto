import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from codex_rescue.doctor import doctor_session
from codex_rescue.projection import inspect_projection_parity
from codex_rescue.transcript import parse_transcript


class Alpha5ProjectionParityTests(unittest.TestCase):
    THREAD_ID = "019fffff-1111-7111-8111-111111111111"

    @staticmethod
    def _write_paginated(root: Path, ordinals: list[int]) -> tuple[Path, list[int]]:
        session_dir = root / "sessions" / "2026" / "08" / "17"
        session_dir.mkdir(parents=True, exist_ok=True)
        path = session_dir / f"rollout-2026-08-17T00-00-00-{Alpha5ProjectionParityTests.THREAD_ID}.jsonl"
        records = []
        for index, ordinal in enumerate(ordinals):
            if index == 0:
                records.append(
                    {
                        "type": "session_meta",
                        "ordinal": ordinal,
                        "payload": {
                            "id": Alpha5ProjectionParityTests.THREAD_ID,
                            "session_id": Alpha5ProjectionParityTests.THREAD_ID,
                            "history_mode": "paginated",
                        },
                    }
                )
            else:
                records.append(
                    {
                        "type": "event_msg",
                        "ordinal": ordinal,
                        "payload": {"type": "user_message", "message": f"message-{ordinal}"},
                    }
                )
        offsets = [0]
        with path.open("wb") as stream:
            for record in records:
                line = (json.dumps(record, separators=(",", ":")) + "\n").encode()
                stream.write(line)
                offsets.append(stream.tell())
        return path, offsets

    @staticmethod
    def _projection_db(root: Path, next_offset: int, next_ordinal: int) -> Path:
        db_path = root / "thread_history_1.sqlite"
        connection = sqlite3.connect(db_path)
        try:
            connection.execute(
                "CREATE TABLE thread_history_projection_state ("
                "thread_id TEXT PRIMARY KEY, "
                "next_rollout_byte_offset INTEGER NOT NULL, "
                "next_rollout_ordinal INTEGER NOT NULL)"
            )
            connection.execute(
                "INSERT INTO thread_history_projection_state VALUES (?, ?, ?)",
                (Alpha5ProjectionParityTests.THREAD_ID, next_offset, next_ordinal),
            )
            connection.commit()
        finally:
            connection.close()
        return db_path

    def test_canonical_ahead_of_projection_is_wedged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 1, 2])
            self._projection_db(root, offsets[2], 2)
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "wedged")
            self.assertIn("WEDGED_PROJECTION", diagnosis.findings)
            self.assertNotEqual(diagnosis.status, "HEALTHY")

    def test_exact_boundary_is_not_a_defect(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 1, 2])
            self._projection_db(root, offsets[-1], 3)
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "exact")
            self.assertEqual(diagnosis.projection.boundary_ordinal, 2)
            self.assertNotIn("WEDGED_PROJECTION", diagnosis.findings)
            self.assertNotIn("PROJECTION_STATE_UNKNOWN", diagnosis.findings)

    def test_eof_byte_boundary_with_stale_ordinal_is_unknown_not_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 1, 2])
            self._projection_db(root, offsets[-1], 2)
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "unknown")
            self.assertIn("next ordinal disagrees", diagnosis.projection.reason)
            self.assertIn("PROJECTION_STATE_UNKNOWN", diagnosis.findings)
            self.assertNotEqual(diagnosis.status, "HEALTHY")

    def test_missing_projection_db_is_not_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self._write_paginated(root, [0, 1])
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "not_applicable")
            self.assertNotIn("WEDGED_PROJECTION", diagnosis.findings)
            self.assertNotIn("PROJECTION_STATE_UNKNOWN", diagnosis.findings)

    def test_malformed_projection_db_fails_closed_without_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _ = self._write_paginated(root, [0, 1])
            (root / "state_5.sqlite").write_bytes(b"not a sqlite database")
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "unknown")
            self.assertIn("PROJECTION_STATE_UNKNOWN", diagnosis.findings)

    def test_replayed_boundary_ordinal_is_detected_conservatively(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 1, 2])
            self._projection_db(root, offsets[1], 2)
            report = inspect_projection_parity(path, parse_transcript(path))
            self.assertEqual(report.status, "wedged")
            self.assertEqual(report.boundary_ordinal, 1)
            self.assertEqual(report.next_boundary_ordinal, 2)

    def test_field_reported_n_to_n_plus_one_cursor_is_wedged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 2, 3])
            self._projection_db(root, offsets[1], 1)
            report = inspect_projection_parity(path, parse_transcript(path))
            self.assertEqual(report.status, "wedged")
            self.assertEqual(report.boundary_ordinal, 2)
            self.assertEqual(report.confidence, "strong")

    def test_mid_record_cursor_is_unknown_not_corruption_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, offsets = self._write_paginated(root, [0, 1])
            self._projection_db(root, offsets[1] + 3, 1)
            report = inspect_projection_parity(path, parse_transcript(path))
            self.assertEqual(report.status, "unknown")
            self.assertIn("not aligned", report.reason)

    def test_legacy_session_is_compatible(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.jsonl"
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": "legacy"}}) + "\n"
                + json.dumps({"type": "event_msg", "payload": {"type": "user_message", "message": "ok"}}) + "\n",
                encoding="utf-8",
            )
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.projection.status, "not_applicable")
            self.assertNotIn("WEDGED_PROJECTION", diagnosis.findings)

    def test_existing_healthy_shape_remains_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "healthy.jsonl"
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": "healthy"}}) + "\n"
                + json.dumps({"type": "event_msg", "payload": {"type": "user_message", "message": "ok"}}) + "\n",
                encoding="utf-8",
            )
            diagnosis = doctor_session(path)
            self.assertEqual(diagnosis.status, "HEALTHY")
            self.assertEqual(diagnosis.findings, ["HEALTHY"])


if __name__ == "__main__":
    unittest.main()
