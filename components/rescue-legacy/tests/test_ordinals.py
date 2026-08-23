from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import codex_rescue.transcript as transcript_module
from codex_rescue.discovery import lightweight_scan
from codex_rescue.doctor import doctor_session
from codex_rescue.salvage import salvage_session
from codex_rescue.verify import verify_rescue


TS = "2026-08-15T00:00:00.000Z"


def _session_meta(*, history_mode: str | None = "paginated", cwd: str | None = None) -> dict[str, object]:
    payload: dict[str, object] = {
        "session_id": "00000000-0000-0000-0000-000000000001",
        "id": "00000000-0000-0000-0000-000000000001",
        "timestamp": TS,
        "cwd": "C:/sanitized",
        "originator": "codex",
        "cli_version": "0.147.0",
        "source": "cli",
        "model_provider": "openai",
        "base_instructions": None,
        "selected_capability_roots": [],
    }
    if cwd is not None:
        payload["cwd"] = cwd
    if history_mode is not None:
        payload["history_mode"] = history_mode
    return {"timestamp": TS, "ordinal": 0, "type": "session_meta", "payload": payload}


def _event(ordinal: int, kind: str, **payload: object) -> dict[str, object]:
    return {
        "timestamp": TS,
        "ordinal": ordinal,
        "type": "event_msg",
        "payload": {"type": kind, **payload},
    }


def _token_count(ordinal: int) -> dict[str, object]:
    # This is the public Codex rollout shape covered by rollout/src/tests.rs.
    return _event(
        ordinal,
        "token_count",
        info=None,
        rate_limits={
            "limit_id": None,
            "limit_name": None,
            "primary": {"used_percent": 0.0, "window_minutes": 60, "resets_at": 1_800_000_000},
            "secondary": {"used_percent": 12.5, "window_minutes": 10_080, "resets_at": 1_800_100_000},
            "credits": None,
            "individual_limit": None,
            "spend_control_reached": None,
            "plan_type": None,
            "rate_limit_reached_type": None,
        },
    )


def _thread_settings_applied(ordinal: int) -> dict[str, object]:
    return _event(
        ordinal,
        "thread_settings_applied",
        thread_settings={
            "model": "gpt-5",
            "model_provider_id": "openai",
            "approval_policy": "on-request",
            "approvals_reviewer": "user",
            "permission_profile": {
                "type": "managed",
                "file_system": {"type": "restricted", "entries": []},
                "network": "restricted",
            },
            "cwd": "C:/sanitized",
            "collaboration_mode": {
                "mode": "default",
                "settings": {
                    "model": "gpt-5",
                    "reasoning_effort": None,
                    "developer_instructions": None,
                },
            },
        },
    )


def _task_started(ordinal: int) -> dict[str, object]:
    return _event(
        ordinal,
        "task_started",
        turn_id="turn-ordinal-fixture",
        model_context_window=None,
        collaboration_mode_kind="default",
    )


def _task_complete(ordinal: int) -> dict[str, object]:
    return _event(
        ordinal,
        "task_complete",
        turn_id="turn-ordinal-fixture",
        last_agent_message=None,
    )


def _legacy_task_started() -> dict[str, object]:
    record = _task_started(0)
    record.pop("ordinal")
    return record


def _write(path: Path, records: list[dict[str, object] | bytes]) -> None:
    chunks: list[bytes] = []
    for record in records:
        if isinstance(record, bytes):
            chunks.append(record)
        else:
            chunks.append((json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8"))
    path.write_bytes(b"".join(chunks))


class OrdinalDiagnosticsTests(unittest.TestCase):
    def _run(self, records: list[dict[str, object] | bytes]):
        td = tempfile.TemporaryDirectory()
        path = Path(td.name) / "rollout-ordinal.jsonl"
        default_repo = Path(td.name) / "repo"
        default_repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=default_repo, check=True)
        subprocess.run(["git", "config", "user.email", "ordinal@example.invalid"], cwd=default_repo, check=True)
        subprocess.run(["git", "config", "user.name", "Ordinal Test"], cwd=default_repo, check=True)
        (default_repo / "fixture.txt").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "add", "fixture.txt"], cwd=default_repo, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=default_repo, check=True)
        normalized: list[dict[str, object] | bytes] = []
        for record in records:
            if isinstance(record, dict) and record.get("type") == "session_meta":
                record = dict(record)
                payload = dict(record.get("payload", {}))
                if payload.get("cwd") == "C:/sanitized":
                    payload["cwd"] = str(default_repo)
                record["payload"] = payload
            normalized.append(record)
        _write(path, normalized)
        self.addCleanup(td.cleanup)
        return path, doctor_session(path)

    def test_monotonic_paginated_ordinals_are_healthy(self) -> None:
        _, result = self._run([_session_meta(), _task_started(1), _task_complete(2)])
        self.assertEqual(result.status, "HEALTHY")
        self.assertEqual(result.transcript.ordinal_mode, "paginated")
        self.assertEqual(result.transcript.ordinal_reuse, [])

    def test_real_style_persisted_paginated_ordinal_reuse_is_detected(self) -> None:
        path, result = self._run([_session_meta(), _token_count(51_563), _thread_settings_applied(51_563), _task_started(51_564)])
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")
        self.assertIn("PERSISTED_PAGINATED_ORDINAL_REUSE", result.findings)
        self.assertEqual(result.transcript.ordinal_reuse_count, 1)
        self.assertEqual(result.transcript.ordinal_reuse[0]["ordinal"], 51_563)
        self.assertEqual(result.transcript.ordinal_reuse[0]["duplicate_offset"], len(path.read_bytes().splitlines(keepends=True)[0]) + len(path.read_bytes().splitlines(keepends=True)[1]))

    def test_persisted_paginated_ordinal_reuse_same_and_different_record_types(self) -> None:
        _, same_type = self._run([_session_meta(), _token_count(7), _token_count(7)])
        _, different_type = self._run([_session_meta(), _token_count(7), _thread_settings_applied(7)])
        self.assertEqual(same_type.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")
        self.assertEqual(different_type.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")

    def test_regression_and_multiple_persisted_paginated_boundaries_are_detected(self) -> None:
        _, result = self._run([_session_meta(), _task_started(7), _task_complete(8), _task_started(7)])
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")
        self.assertEqual(result.transcript.ordinal_reuse_count, 1)

        records: list[dict[str, object]] = [_session_meta()]
        for index in range(200):
            ordinal = 100 + index * 3
            records.extend([_token_count(ordinal), _thread_settings_applied(ordinal), _task_started(ordinal + 1)])
        _, long_result = self._run(records)
        self.assertEqual(long_result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")
        self.assertEqual(long_result.transcript.ordinal_reuse_count, 200)
        self.assertLessEqual(len(long_result.transcript.ordinal_reuse), 128)

    def test_gaps_are_not_promoted_to_reuse(self) -> None:
        _, result = self._run([_session_meta(), _task_started(7), _task_complete(9)])
        self.assertEqual(result.status, "HEALTHY")
        self.assertEqual(result.transcript.ordinal_reuse, [])

    def test_legacy_or_unknown_mode_is_not_reinterpreted_as_paginated(self) -> None:
        legacy = [_session_meta(history_mode="legacy"), _legacy_task_started(), _legacy_task_started()]
        _, legacy_result = self._run(legacy)
        self.assertEqual(legacy_result.status, "HEALTHY")
        self.assertEqual(legacy_result.transcript.ordinal_mode, "legacy")

        _, unknown_result = self._run([_session_meta(history_mode="future"), _task_started(7), _task_started(7)])
        self.assertEqual(unknown_result.status, "UNKNOWN_OPERATIONAL_SCHEMA")
        self.assertEqual(unknown_result.transcript.ordinal_reuse, [])

    def test_nonzero_start_and_child_history_base_are_not_gaps_or_reuse(self) -> None:
        child = _session_meta()
        child_payload = dict(child["payload"])
        child_payload.update(
            {
                "history_base": {
                    "thread_id": "00000000-0000-0000-0000-000000000002",
                    "end_ordinal_exclusive": 100,
                    "end_byte_offset": 4096,
                },
                "subagent_history_start_ordinal": 100,
            }
        )
        child["payload"] = child_payload
        child["ordinal"] = 100
        _, result = self._run([child, _task_started(101), _task_complete(103)])
        self.assertEqual(result.status, "HEALTHY")
        self.assertEqual(result.transcript.ordinal_reuse, [])

    def test_malformed_ordinal_values_are_unknown_not_reuse(self) -> None:
        invalid_records: list[dict[str, object]] = []
        for value in (None, "7", -1, True, 1 << 64):
            record = dict(_task_started(7))
            if value is None:
                record.pop("ordinal")
            else:
                record["ordinal"] = value  # type: ignore[assignment]
            invalid_records.append(record)
        _, result = self._run([_session_meta(), *invalid_records])
        self.assertEqual(result.status, "UNKNOWN_OPERATIONAL_SCHEMA")
        self.assertEqual(result.transcript.ordinal_reuse, [])
        self.assertFalse(result.transcript.ordinal_tracking_overflow)
        self.assertTrue(result.transcript.operational_schema_issues)

    def test_u64_maximum_duplicate_is_reuse(self) -> None:
        maximum = (1 << 64) - 1
        _, result = self._run([_session_meta(), _task_started(maximum), _task_complete(maximum)])
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")
        self.assertEqual(result.transcript.ordinal_reuse_count, 1)

    def test_bounded_tracking_overflow_is_incomplete_and_blocks_safe_handoff(self) -> None:
        records: list[dict[str, object]] = [_session_meta()]
        records.extend(_task_started(value) for value in range(1, 12))
        # Ordinal 9 is repeated after the bounded map has overflowed.  The
        # detector must not claim a duplicate it can no longer prove, and the
        # handoff must remain review-required because absence is unknown.
        records.extend([_task_started(10), _task_started(9)])
        with patch.object(transcript_module, "MAX_ORDINAL_STATES", 8):
            path, result = self._run(records)
        self.assertEqual(result.status, "ORDINAL_ANALYSIS_INCOMPLETE")
        self.assertIn("ORDINAL_ANALYSIS_INCOMPLETE", result.findings)
        self.assertNotIn("PERSISTED_PAGINATED_ORDINAL_REUSE", result.findings)
        self.assertEqual(result.transcript.ordinal_reuse, [])
        self.assertTrue(result.transcript.ordinal_tracking_overflow)
        before = hashlib.sha256(path.read_bytes()).hexdigest()
        with tempfile.TemporaryDirectory() as rescue_td:
            salvage = salvage_session(path, result.transcript, result.status, result.findings, Path(rescue_td), True)
            verification = verify_rescue(Path(rescue_td), salvage.rescue_id)
            self.assertEqual(verification.status, "REVIEW_REQUIRED")
            self.assertTrue(any("bounded persisted paginated ordinal scan" in reason for reason in verification.review_reasons))
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_proven_duplicate_before_overflow_is_reuse_and_incomplete(self) -> None:
        records: list[dict[str, object]] = [_session_meta(), _task_started(1), _task_started(1)]
        records.extend(_task_started(value) for value in range(2, 12))
        with patch.object(transcript_module, "MAX_ORDINAL_STATES", 8):
            _, result = self._run(records)
        self.assertIn("PERSISTED_PAGINATED_ORDINAL_REUSE", result.findings)
        self.assertIn("ORDINAL_ANALYSIS_INCOMPLETE", result.findings)
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")

    def test_overflow_followed_by_adjacent_duplicate_is_still_reuse(self) -> None:
        records: list[dict[str, object]] = [_session_meta()]
        records.extend(_task_started(value) for value in range(1, 11))
        records.extend([_task_started(10), _task_started(11)])
        with patch.object(transcript_module, "MAX_ORDINAL_STATES", 8):
            _, result = self._run(records)
        self.assertIn("PERSISTED_PAGINATED_ORDINAL_REUSE", result.findings)
        self.assertIn("ORDINAL_ANALYSIS_INCOMPLETE", result.findings)
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")

    def test_compaction_does_not_reset_persisted_paginated_ordinal_semantics(self) -> None:
        compacted = {
            "timestamp": TS,
            "ordinal": 5,
            "type": "compacted",
            "payload": {
                "message": "sanitized",
                "replacement_history": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "sanitized"}],
                    }
                ],
            },
        }
        _, result = self._run([_session_meta(), compacted, _task_started(6), _token_count(7), _thread_settings_applied(7), _task_started(8)])
        self.assertEqual(result.status, "PERSISTED_PAGINATED_ORDINAL_REUSE")

    def test_malformed_or_incomplete_tail_is_not_parsed_as_ordinal_evidence(self) -> None:
        records = [_session_meta(), _task_started(7), b'{"timestamp":"bad"\n', _task_started(7)]
        _, result = self._run(records)
        self.assertEqual(result.status, "MALFORMED_RECORD")
        self.assertEqual(result.transcript.ordinal_reuse, [])

        _, active = self._run([_session_meta(), _task_started(7), b'{"timestamp":"2026-08-15T00:00:00Z","ordinal":7,"type":"event_msg"'])
        self.assertIn(active.status, {"TRUNCATED_TRANSCRIPT", "MALFORMED_RECORD"})
        self.assertEqual(active.transcript.ordinal_reuse, [])

    def test_malformed_record_after_reuse_keeps_both_findings(self) -> None:
        records = [_session_meta(), _token_count(7), _thread_settings_applied(7), b"not-json\n"]
        _, result = self._run(records)
        self.assertEqual(result.status, "MALFORMED_RECORD")
        self.assertIn("MALFORMED_RECORD", result.findings)
        self.assertIn("PERSISTED_PAGINATED_ORDINAL_REUSE", result.findings)

    def test_non_ordinal_repetition_is_ignored(self) -> None:
        _, result = self._run([_session_meta(), _token_count(7), _token_count(8)])
        self.assertEqual(result.status, "HEALTHY")
        self.assertEqual(result.transcript.ordinal_reuse, [])

    def test_persisted_paginated_ordinal_reuse_propagates_to_review(self) -> None:
        with tempfile.TemporaryDirectory() as repo_td:
            repo = Path(repo_td)
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.email", "ordinal@example.invalid"], cwd=repo, check=True)
            subprocess.run(["git", "config", "user.name", "Ordinal Test"], cwd=repo, check=True)
            (repo / "tracked.txt").write_text("fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True)
            path, result = self._run([_session_meta(cwd=str(repo)), _token_count(7), _thread_settings_applied(7), _task_started(8)])
            before = hashlib.sha256(path.read_bytes()).hexdigest()
            with tempfile.TemporaryDirectory() as rescue_td:
                salvage = salvage_session(path, result.transcript, result.status, result.findings, Path(rescue_td), True)
                handoff = json.loads(Path(salvage.handoff_path).read_text(encoding="utf-8"))
                self.assertEqual(handoff["overall_confidence"], "unknown")
                self.assertEqual(handoff["transcript"]["ordinal_reuse_count"], 1)
                verification = verify_rescue(Path(rescue_td), salvage.rescue_id)
                self.assertEqual(verification.status, "REVIEW_REQUIRED")
                self.assertTrue(any("persisted paginated ordinal reuse" in reason for reason in verification.review_reasons))
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), before)

    def test_lightweight_scan_remains_bounded_and_does_not_claim_full_invariant(self) -> None:
        path, _ = self._run([_session_meta(), _token_count(7), _thread_settings_applied(7), _task_started(8)])
        summary = lightweight_scan(path)
        self.assertEqual(summary.status, "healthy")


if __name__ == "__main__":
    unittest.main()
