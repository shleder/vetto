from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.cli import main


def _write_session(home: Path) -> Path:
    session = home / "sessions" / "2026" / "08" / "12" / "rollout-2026-08-12T00-00-00-case.jsonl"
    session.parent.mkdir(parents=True)
    records = [
        {"type": "session_meta", "payload": {"id": "case", "session_id": "case", "cwd": str(home)}},
        {"type": "event_msg", "payload": {"type": "user_message", "message": "fix bounded thing"}},
    ]
    session.write_text("".join(json.dumps(item) + "\n" for item in records), encoding="utf-8")
    return session


class CliMvpTests(unittest.TestCase):
    def test_sessions_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            _write_session(home)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["sessions", "--codex-home", str(home), "--json"]), 0)
            envelope = json.loads(output.getvalue())
            self.assertEqual(envelope["schema_version"], 1)
            self.assertEqual(envelope["data"][0]["session_id"], "case")

    def test_sessions_help_explains_bounded_default_window(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                main(["sessions", "--help"])
        self.assertEqual(raised.exception.code, 0)
        rendered = " ".join(output.getvalue().split())
        self.assertIn("bounded listing window", rendered)
        self.assertIn("default: 20", rendered)
        self.assertIn("older known session", rendered)
        self.assertIn("does not prove a rollout is undiscoverable", rendered)

    def test_doctor_latest_json_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            _write_session(home)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["doctor", "--latest", "--codex-home", str(home), "--json"]), 0)
            envelope = json.loads(output.getvalue())
            self.assertEqual(envelope["schema_version"], 1)
            self.assertIn("status", envelope["data"])

    def test_doctor_defaults_to_concise_human_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            session = _write_session(home)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(main(["doctor", str(session)]), 0)
            rendered = output.getvalue()
            self.assertIn("Doctor:", rendered)
            self.assertNotIn('"schema_version"', rendered)

    def test_doctor_healthy_human_output_is_narrowly_scoped_without_json_change(self) -> None:
        healthy = {
            "session": "/tmp/rollout.jsonl",
            "status": "HEALTHY",
            "findings": ["HEALTHY"],
            "repository": {"cwd": None, "confidence": "unknown"},
        }
        human_output = io.StringIO()
        with patch("codex_rescue.cli._doctor", return_value=healthy):
            with contextlib.redirect_stdout(human_output):
                self.assertEqual(main(["doctor", "rollout.jsonl"]), 0)
        rendered = human_output.getvalue()
        self.assertIn("Doctor: HEALTHY", rendered)
        self.assertIn(
            "HEALTHY means Codex Rescue found no recognized structural/persistence issue in the analyzed rollout. "
            "It does not validate Codex Desktop sidebar/index/Remote metadata, prove semantic completeness, "
            "or rule out every upstream Codex failure mode.",
            rendered,
        )

        json_output = io.StringIO()
        with patch("codex_rescue.cli._doctor", return_value=healthy):
            with contextlib.redirect_stdout(json_output):
                self.assertEqual(main(["doctor", "rollout.jsonl", "--json"]), 0)
        envelope = json.loads(json_output.getvalue())
        self.assertEqual(envelope["schema_version"], 1)
        self.assertEqual(envelope["data"], healthy)

    def test_version_flag_is_available(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit) as raised:
                main(["--version"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("codex-rescue", output.getvalue())

    def test_salvage_accepts_oversized_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = Path(td)
            session = _write_session(home)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([
                    "salvage", str(session), "--fork", "--rescue-root", str(home / "rescue"),
                    "--oversized-threshold", "2048", "--json",
                ])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output.getvalue())["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
