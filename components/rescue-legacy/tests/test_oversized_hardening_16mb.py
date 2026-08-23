from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from codex_rescue.apply_plan import apply_recovery_plan
from codex_rescue.doctor import doctor_session
from codex_rescue.doctor_batch import run_doctor_all, run_doctor_changed
from codex_rescue.evidence import collect_session_evidence
from codex_rescue.plan import generate_recovery_plan
from codex_rescue.schema_inspector import inspect_schemas
from codex_rescue.storage import analyze_storage
from codex_rescue.timeline import build_timeline
from codex_rescue.transcript import MAX_RECORD_BYTES, parse_transcript


def _create_synthetic_16mb_record(session_dir: Path, variant: str = "valid") -> Path:
    """Create synthetic, privacy-safe JSONL test rollout with records > 16 MiB."""
    session_file = session_dir / f"rollout-{variant}-16mb.jsonl"
    meta = {
        "type": "session_meta",
        "payload": {
            "id": f"test-{variant}-16mb",
            "session_id": f"test-{variant}-16mb",
            "cwd": str(session_dir),
            "cli_version": "0.147.0",
        },
    }
    user_turn = {
        "type": "event_msg",
        "payload": {
            "type": "user_message",
            "message": "synthetic oversized record test probe",
        },
    }

    head_lines = [
        json.dumps(meta, separators=(",", ":")) + "\n",
        json.dumps(user_turn, separators=(",", ":")) + "\n",
    ]

    # Target 18 MiB (> 16 MiB bounded threshold)
    large_payload_chunk = "A" * (18 * 1024 * 1024)

    if variant == "valid":
        large_record = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call-oversized-16mb",
                "output": {
                    "content": [
                        {
                            "type": "image_url",
                            "image_url": "data:image/png;base64," + large_payload_chunk,
                        }
                    ]
                },
            },
        }
        tail_bytes = json.dumps(large_record, separators=(",", ":")).encode("utf-8") + b"\n"
    elif variant == "malformed":
        # Over 16 MiB line with embedded NUL byte and invalid JSON structure
        tail_bytes = (
            b'{"type":"response_item","payload":{"data":"'
            + large_payload_chunk.encode("ascii")
            + b'\x00--corrupted--'
            + b'"}}\n'
        )
    elif variant == "truncated":
        # Over 16 MiB line cut off at EOF with no trailing newline
        large_record = {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": "call-oversized-truncated",
                "output": {"content": large_payload_chunk},
            },
        }
        tail_bytes = json.dumps(large_record, separators=(",", ":")).encode("utf-8")  # No trailing newline!
    else:
        raise ValueError(f"Unknown variant: {variant}")

    with session_file.open("wb") as f:
        for line in head_lines:
            f.write(line.encode("utf-8"))
        f.write(tail_bytes)

    return session_file


class Oversized16MBHardeningTests(unittest.TestCase):
    def test_max_record_bytes_constant(self) -> None:
        self.assertEqual(MAX_RECORD_BYTES, 8 * 1024 * 1024)

    def test_valid_but_oversized_16mb_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = _create_synthetic_16mb_record(Path(td), variant="valid")
            file_bytes = session_path.read_bytes()
            expected_sha = hashlib.sha256(file_bytes).hexdigest()

            self.assertGreater(len(file_bytes), 18 * 1024 * 1024)

            parsed = parse_transcript(session_path)
            self.assertEqual(parsed.source_size, len(file_bytes))
            self.assertEqual(parsed.sha256, expected_sha)
            self.assertEqual(parsed.corruption_class, "OVERSIZED_PAYLOAD")
            self.assertEqual(parsed.oversized_record_count, 1)
            self.assertEqual(parsed.valid_record_count, 2)
            self.assertEqual(len(parsed.oversized_records), 1)
            self.assertEqual(parsed.oversized_records[0]["classification"], "VALID_BUT_OVERSIZED")
            self.assertGreater(parsed.oversized_records[0]["byte_length"], 18 * 1024 * 1024)

            doctor = doctor_session(session_path)
            self.assertEqual(doctor.status, "OVERSIZED_PAYLOAD")
            self.assertIn("OVERSIZED_PAYLOAD", doctor.findings)
            self.assertIn("VALID_BUT_OVERSIZED", doctor.findings)
            self.assertNotEqual(doctor.status, "HEALTHY")

            ev = collect_session_evidence(session_path)
            self.assertEqual(ev.status, "OVERSIZED")
            self.assertIn("VALID_BUT_OVERSIZED", ev.findings)
            self.assertIn("OVERSIZED_PAYLOAD", ev.findings)
            self.assertIn("OVERSIZED_RECORD", ev.findings)
            self.assertNotEqual(ev.status, "HEALTHY")

            timeline = build_timeline(session_path)
            self.assertGreater(timeline.total_events, 2)
            self.assertEqual(timeline.events[-1].event_type, "oversized_record_boundary")
            self.assertEqual(timeline.events[-1].details.get("classification"), "VALID_BUT_OVERSIZED")

    def test_malformed_oversized_16mb_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = _create_synthetic_16mb_record(Path(td), variant="malformed")
            file_bytes = session_path.read_bytes()

            parsed = parse_transcript(session_path)
            self.assertEqual(parsed.corruption_class, "MALFORMED_RECORD")
            self.assertEqual(parsed.oversized_record_count, 1)
            self.assertEqual(parsed.oversized_records[0]["classification"], "MALFORMED")

            doctor = doctor_session(session_path)
            self.assertEqual(doctor.status, "MALFORMED_RECORD")
            self.assertIn("MALFORMED_RECORD", doctor.findings)
            self.assertNotEqual(doctor.status, "HEALTHY")

            ev = collect_session_evidence(session_path)
            self.assertEqual(ev.status, "CORRUPT")
            self.assertIn("MALFORMED_JSONL", ev.findings)
            self.assertNotEqual(ev.status, "HEALTHY")

    def test_truncated_oversized_16mb_record(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = _create_synthetic_16mb_record(Path(td), variant="truncated")
            file_bytes = session_path.read_bytes()

            parsed = parse_transcript(session_path)
            self.assertEqual(parsed.corruption_class, "TRUNCATED_TRANSCRIPT")
            self.assertEqual(parsed.oversized_record_count, 1)
            self.assertEqual(parsed.oversized_records[0]["classification"], "TRUNCATED")

            doctor = doctor_session(session_path)
            self.assertEqual(doctor.status, "TRUNCATED_TRANSCRIPT")
            self.assertIn("TRUNCATED_TRANSCRIPT", doctor.findings)
            self.assertNotEqual(doctor.status, "HEALTHY")

            ev = collect_session_evidence(session_path)
            self.assertEqual(ev.status, "CORRUPT")
            self.assertIn("TRUNCATED_JSONL", ev.findings)
            self.assertFalse(ev.rollout.has_trailing_newline)
            self.assertTrue(ev.rollout.is_truncated)
            self.assertNotEqual(ev.status, "HEALTHY")

    def test_plan_and_apply_refuse_mutation_on_16mb_oversized_source(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            session_path = _create_synthetic_16mb_record(Path(td), variant="valid")
            plan = generate_recovery_plan(session_path)
            self.assertFalse(plan.is_applicable)
            self.assertIsNotNone(plan.refusal_reason)
            self.assertIn("INCOMPLETE_OR_OVERSIZED_SOURCE", plan.refusal_reason or "")

            apply_res = apply_recovery_plan(plan)
            self.assertFalse(apply_res.plan_applied)
            self.assertIn("MANDATORY_SAFETY_REFUSAL", apply_res.refusal_reason or "")

            # If an adversary manually sets IS_APPLICABLE to True, apply_recovery_plan must still refuse!
            tampered_plan = plan.to_dict()
            tampered_plan["IS_APPLICABLE"] = True
            tampered_plan.pop("REFUSAL_REASON", None)

            apply_res_tampered = apply_recovery_plan(tampered_plan)
            self.assertFalse(apply_res_tampered.plan_applied)
            self.assertIn("INCOMPLETE_OR_OVERSIZED_SOURCE", apply_res_tampered.refusal_reason or "")

    def test_storage_analysis_detects_16mb_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sessions_dir = home / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            _create_synthetic_16mb_record(sessions_dir, variant="valid")

            report = analyze_storage(codex_home=home)
            self.assertEqual(report.total_sessions, 1)
            self.assertEqual(report.size_buckets["> 16 MB"], 1)
            self.assertTrue(any("oversized record" in ind.lower() for ind in report.anomalous_growth_indicators))

    def test_schema_inspector_does_not_silently_drop_16mb_records(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sessions_dir = home / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            _create_synthetic_16mb_record(sessions_dir, variant="valid")

            report = inspect_schemas(codex_home=home)
            self.assertEqual(report.status, "PARTIALLY_UNSUPPORTED")
            self.assertTrue(any("oversized" in s.lower() for s in report.opaque_or_unsupported_sections))
            self.assertTrue(any("oversized" in w.lower() for w in report.compatibility_warnings))

    def test_batch_doctor_categorization_for_16mb_sessions(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            sessions_dir = home / "sessions"
            sessions_dir.mkdir(parents=True, exist_ok=True)
            _create_synthetic_16mb_record(sessions_dir, variant="valid")

            summary = run_doctor_all(codex_home=home)
            self.assertEqual(summary.sessions_scanned, 1)
            self.assertEqual(summary.healthy, 0)
            self.assertEqual(summary.warnings_findings, 1)

            # Test cached pass with run_doctor_changed
            cache_file = home / ".cache_doctor.json"
            changed_summary = run_doctor_changed(codex_home=home, cache_path=cache_file)
            self.assertEqual(changed_summary.sessions_scanned, 1)
            self.assertEqual(changed_summary.healthy, 0)
            self.assertEqual(changed_summary.warnings_findings, 1)


if __name__ == "__main__":
    unittest.main()
