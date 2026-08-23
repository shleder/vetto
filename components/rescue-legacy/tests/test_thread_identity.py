from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.discovery import lightweight_scan
from codex_rescue.discovery_alpha5 import _thread_id_from_path
from codex_rescue.evidence import collect_session_evidence
from codex_rescue.thread_identity import (
    THREAD_IDENTITY_CONSISTENT,
    THREAD_IDENTITY_FILENAME,
    THREAD_IDENTITY_SESSION_META,
    THREAD_IDENTITY_UNKNOWN,
    parse_rollout_filename,
    resolve_thread_identity,
)

THREAD = "019abcde-1111-7222-8333-444444444444"
OTHER = "019abcde-1111-7222-8333-555555555555"
ROLLOUT = "029abcde-aaaa-7bbb-8ccc-dddddddddddd"
NORMAL = f"rollout-2026-08-19T12-34-56-{THREAD}.jsonl"
REVERT = f"rollout-2026-08-19T12-34-56-{THREAD}_{ROLLOUT}.jsonl"


class ThreadIdentityTests(unittest.TestCase):
    def test_normal_filename_extracts_thread_id(self) -> None:
        parsed = parse_rollout_filename(NORMAL)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.thread_id, THREAD)
        self.assertEqual(parsed.rollout_id, THREAD)

    def test_revert_filename_keeps_first_logical_thread_id(self) -> None:
        parsed = parse_rollout_filename(REVERT)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.thread_id, THREAD)
        self.assertEqual(parsed.rollout_id, ROLLOUT)
        self.assertNotEqual(parsed.thread_id, parsed.rollout_id)

    def test_metadata_agrees_with_filename(self) -> None:
        result = resolve_thread_identity(NORMAL, session_meta={"id": THREAD})
        self.assertEqual(result.thread_id, THREAD)
        self.assertEqual(result.source, THREAD_IDENTITY_SESSION_META)
        self.assertEqual(result.confidence, THREAD_IDENTITY_CONSISTENT)
        self.assertFalse(result.conflict)

    def test_metadata_conflict_fails_closed(self) -> None:
        result = resolve_thread_identity(NORMAL, session_meta={"id": OTHER})
        self.assertIsNone(result.thread_id)
        self.assertEqual(result.source, THREAD_IDENTITY_UNKNOWN)
        self.assertTrue(result.conflict)
        self.assertEqual(result.filename_thread_id, THREAD)
        self.assertEqual(result.metadata_thread_id, OTHER)

    def test_malformed_filename_is_unknown(self) -> None:
        self.assertIsNone(parse_rollout_filename(f"rollout-not-a-time-{THREAD}.jsonl"))
        self.assertIsNone(resolve_thread_identity(f"rollout-not-a-time-{THREAD}.jsonl").thread_id)

    def test_arbitrary_filename_does_not_fabricate_path_stem_identity(self) -> None:
        result = resolve_thread_identity("parent.jsonl")
        self.assertIsNone(result.thread_id)
        self.assertEqual(result.source, THREAD_IDENTITY_UNKNOWN)

    def test_archived_nested_path_uses_same_logical_id(self) -> None:
        result = resolve_thread_identity(
            f"/home/alice/.codex/archived_sessions/2026/08/19/{REVERT}"
        )
        self.assertEqual(result.thread_id, THREAD)
        self.assertEqual(result.filename_rollout_id, ROLLOUT)
        self.assertEqual(result.source, THREAD_IDENTITY_FILENAME)

    def test_windows_path_uses_same_logical_id(self) -> None:
        result = resolve_thread_identity(
            rf"C:\\Users\\Alice\\.codex\\sessions\\2026\\08\\19\\{NORMAL}"
        )
        self.assertEqual(result.thread_id, THREAD)

    def test_current_session_meta_id_wins_over_distinct_session_id(self) -> None:
        result = resolve_thread_identity(NORMAL, session_meta={"session_id": OTHER, "id": THREAD})
        self.assertEqual(result.thread_id, THREAD)
        self.assertEqual(result.metadata_field, "id")
        self.assertEqual(result.metadata_session_id, OTHER)

    def test_invalid_authoritative_metadata_does_not_fall_back_to_filename(self) -> None:
        result = resolve_thread_identity(NORMAL, session_meta={"id": "not-a-thread-id"})
        self.assertIsNone(result.thread_id)
        self.assertTrue(result.conflict)
        self.assertEqual(result.filename_thread_id, THREAD)

    def test_collect_session_evidence_uses_current_meta_id_not_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / NORMAL
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"session_id": OTHER, "id": THREAD}}) + "\n",
                encoding="utf-8",
            )
            evidence = collect_session_evidence(path)
            self.assertEqual(evidence.session_id, THREAD)
            self.assertEqual(evidence.thread_identity.confidence, THREAD_IDENTITY_CONSISTENT)

    def test_collect_session_evidence_conflict_is_explicit_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / NORMAL
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": OTHER}}) + "\n",
                encoding="utf-8",
            )
            evidence = collect_session_evidence(path)
            self.assertIsNone(evidence.session_id)
            self.assertTrue(evidence.thread_identity.conflict)
            self.assertIn("THREAD_IDENTITY_CONFLICT", evidence.findings)

    def test_collect_session_evidence_arbitrary_name_has_no_fabricated_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "parent.jsonl"
            path.write_text(json.dumps({"type": "turn_started"}) + "\n", encoding="utf-8")
            evidence = collect_session_evidence(path)
            self.assertIsNone(evidence.session_id)
            self.assertEqual(evidence.thread_identity.source, THREAD_IDENTITY_UNKNOWN)

    def test_alpha5_discovery_uses_canonical_filename_parser(self) -> None:
        self.assertEqual(_thread_id_from_path(Path(NORMAL)), THREAD)
        self.assertEqual(_thread_id_from_path(Path(REVERT)), THREAD)
        self.assertIsNone(_thread_id_from_path(Path(f"rollout-arbitrary-{THREAD}.jsonl")))

    def test_bounded_discovery_uses_thread_id_not_distinct_session_id(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / NORMAL
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"session_id": OTHER, "id": THREAD}}) + "\n",
                encoding="utf-8",
            )
            summary = lightweight_scan(path)
            self.assertEqual(summary.session_id, THREAD)
            self.assertEqual(summary.thread_identity.confidence, THREAD_IDENTITY_CONSISTENT)
            self.assertEqual(summary.to_dict()["thread_identity"]["metadata_session_id"], OTHER)

    def test_bounded_discovery_conflict_is_suspicious_and_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / NORMAL
            path.write_text(
                json.dumps({"type": "session_meta", "payload": {"id": OTHER}}) + "\n",
                encoding="utf-8",
            )
            summary = lightweight_scan(path)
            self.assertIsNone(summary.session_id)
            self.assertEqual(summary.status, "suspicious")
            self.assertTrue(summary.thread_identity.conflict)


if __name__ == "__main__":
    unittest.main()
