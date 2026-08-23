from __future__ import annotations

import unittest

from codex_rescue.alpha7.blackbox.incident import IncidentEngine
from codex_rescue.alpha7.blackbox.recorder import BlackBoxRecorder, EventType


class BlackboxIncidentNegativesTests(unittest.TestCase):
    def test_anomaly_without_rollout_scan_yields_unknown_canonical_status(self) -> None:
        recorder = BlackBoxRecorder()
        e1 = recorder.record_event(EventType.PROJECTION_CURSOR_STOPPED, session_id="t1", details={"error": "Hang"})
        engine = IncidentEngine()
        report = engine.analyze_events("inc-1", [e1])
        self.assertEqual(report.canonical_rollout_status, "UNKNOWN")
        self.assertEqual(report.confidence, "LOW")
        self.assertFalse(report.is_safe_shareable)

    def test_privacy_validation_not_run_leaves_shareable_false(self) -> None:
        recorder = BlackBoxRecorder()
        e1 = recorder.record_event(EventType.ROLLOUT_CREATED, session_id="t2", details={"source": "OBSERVED"})
        engine = IncidentEngine()
        report = engine.analyze_events("inc-2", [e1], validate_privacy=False)
        self.assertFalse(report.is_safe_shareable)

    def test_proven_rollout_status_propagates(self) -> None:
        recorder = BlackBoxRecorder()
        e1 = recorder.record_event(EventType.ROLLOUT_CREATED, session_id="t3", details={"source": "OBSERVED"})
        e2 = recorder.record_event(EventType.ROLLOUT_APPENDED, session_id="t3", details={"source": "OBSERVED"})
        engine = IncidentEngine()
        report = engine.analyze_events("inc-3", [e1, e2], rollout_status="HEALTHY", validate_privacy=True)
        self.assertEqual(report.canonical_rollout_status, "HEALTHY")
        self.assertEqual(report.confidence, "HIGH")
        self.assertTrue(report.is_safe_shareable)

    def test_missing_events_yields_unknown_confidence(self) -> None:
        engine = IncidentEngine()
        report = engine.analyze_events("inc-4", [])
        self.assertEqual(report.confidence, "UNKNOWN")
        self.assertEqual(report.events_count, 0)
        self.assertFalse(report.is_safe_shareable)


if __name__ == "__main__":
    unittest.main()
