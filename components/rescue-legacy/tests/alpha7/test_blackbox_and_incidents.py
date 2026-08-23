from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from codex_rescue.alpha7.blackbox.fingerprint import FingerprintEngine
from codex_rescue.alpha7.blackbox.incident import IncidentEngine
from codex_rescue.alpha7.blackbox.recorder import BlackBoxRecorder, EventType
from codex_rescue.alpha7.blackbox.reproducer import ReproducerEngine


class BlackBoxAndIncidentsTests(unittest.TestCase):
    def test_recorder_records_events_and_snapshots(self):
        with tempfile.TemporaryDirectory() as td:
            chome = Path(td)
            sdir = chome / "sessions"
            sdir.mkdir()
            (sdir / "s1.jsonl").write_text('{"turn":1}\n', encoding="utf-8")

            recorder = BlackBoxRecorder(storage_dir=chome / "blackbox")
            evt = recorder.record_event(
                EventType.ROLLOUT_CREATED, session_id="s1", path=str(sdir / "s1.jsonl")
            )
            self.assertEqual(evt.event_type, EventType.ROLLOUT_CREATED)
            self.assertEqual(len(recorder.events), 1)

            snap1 = recorder.create_snapshot(chome)
            self.assertEqual(snap1.total_sessions_count, 1)

            # Modify state
            (sdir / "s2.jsonl").write_text('{"turn":2}\n', encoding="utf-8")
            snap2 = recorder.create_snapshot(chome)
            diff = recorder.compare_snapshots(snap1, snap2)
            self.assertEqual(len(diff["added_sessions"]), 1)
            self.assertEqual(diff["total_divergences"], 1)

    def test_incident_engine_identifies_first_bad_state_and_causal_chain(self):
        recorder = BlackBoxRecorder()
        e1 = recorder.record_event(EventType.THREAD_CREATED, session_id="s1")
        e2 = recorder.record_event(EventType.ROLLOUT_CREATED, session_id="s1")
        e3 = recorder.record_event(
            EventType.PROJECTION_CURSOR_STOPPED,
            session_id="s1",
            details={"error": "Cursor locked at offset 4096"},
        )

        engine = IncidentEngine()
        inc = engine.analyze_events("inc_001", [e1, e2, e3])
        self.assertEqual(inc.anomalies_count, 1)
        self.assertEqual(inc.first_known_bad_time, e3.timestamp)
        self.assertEqual(inc.last_known_good_time, e2.timestamp)

        categories = [c.category for c in inc.causal_chain]
        self.assertIn("OBSERVED", categories)
        self.assertIn("INFERRED", categories)
        self.assertIn("UNKNOWN", categories)

    def test_fingerprint_engine_generates_stable_hash_and_matches_patterns(self):
        fp = FingerprintEngine.generate_fingerprint(
            findings=["UNINDEXED_IN_SQLITE"],
            surface_states={"cli": "VISIBLE", "desktop": "HIDDEN"},
        )
        self.assertTrue(fp.fingerprint_id.startswith("CR7-"))
        self.assertEqual(fp.known_match, "UNINDEXED_DESKTOP_THREAD")
        self.assertEqual(fp.confidence, "HIGH")

    def test_reproducer_creates_synthetic_defect_minimizes_and_replays(self):
        rep = ReproducerEngine.create_reproducer(
            finding="WEDGED_PROJECTION", total_records=50, inject_defect_at=25
        )
        self.assertEqual(rep.total_records, 50)
        self.assertTrue(rep.records[25].is_malformed)

        # Minimize
        min_rep = ReproducerEngine.minimize_reproducer(rep)
        self.assertLessEqual(min_rep.total_records, 5)

        # Replay
        replay_res = ReproducerEngine.replay(min_rep)
        self.assertEqual(replay_res["status"], "PASS")
        self.assertEqual(replay_res["triggered_finding"], "WEDGED_PROJECTION")


if __name__ == "__main__":
    unittest.main()
