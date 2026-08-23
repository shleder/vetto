from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from codex_rescue.artifacts import load_handoff
from codex_rescue.doctor import doctor_session
from codex_rescue.salvage import salvage_session
from codex_rescue.verify import verify_rescue


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


class SafetyMvpTests(unittest.TestCase):
    def _repo(self, root: Path) -> Path:
        repo = root / "repo"
        repo.mkdir()
        _git(repo, "init", "-q")
        _git(repo, "config", "user.email", "safety@example.com")
        _git(repo, "config", "user.name", "Safety Test")
        (repo / "app.txt").write_text("base\n", encoding="utf-8")
        _git(repo, "add", "app.txt")
        _git(repo, "commit", "-qm", "base")
        return repo

    def _session(
        self,
        root: Path,
        repo: Path,
        *payloads: dict[str, Any],
    ) -> Path:
        session = root / "rollout-safety.jsonl"
        records = [
            {
                "timestamp": "2026-08-12T00:00:00Z",
                "type": "session_meta",
                "payload": {
                    "id": "safety-session",
                    "session_id": "safety-session",
                    "cwd": str(repo),
                    "cli_version": "0.147.0",
                },
            },
            {
                "timestamp": "2026-08-12T00:00:01Z",
                "type": "event_msg",
                "payload": {"type": "user_message", "message": "safety test"},
            },
        ]
        records.extend(payloads)
        session.write_bytes(
            b"".join(
                (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
                for record in records
            )
        )
        return session

    def _salvage(self, session: Path, root: Path):
        doctor = doctor_session(session)
        return salvage_session(
            session,
            doctor.transcript,
            doctor.status,
            doctor.findings,
            root,
            True,
        )

    def test_doctor_does_not_modify_source_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            session = self._session(root, repo)

            before = _sha256(session)
            result = doctor_session(session)

            self.assertEqual(result.status, "HEALTHY")
            self.assertEqual(_sha256(session), before)
            self.assertEqual(result.transcript.sha256, before)

    def test_salvage_does_not_modify_source_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            session = self._session(root, repo)
            rescue_root = root / "rescue"

            before = _sha256(session)
            result = self._salvage(session, rescue_root)

            self.assertTrue(result.original_untouched)
            self.assertEqual(_sha256(session), before)
            self.assertTrue(Path(result.handoff_path).is_file())

    def test_verify_is_read_only_for_source_and_handoff(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            session = self._session(root, repo)
            result = self._salvage(session, root / "rescue")
            handoff = Path(result.handoff_path)
            source_before = session.read_bytes()
            handoff_before = handoff.read_bytes()

            self.assertEqual(verify_rescue(root / "rescue", result.rescue_id).status, "SAFE_TO_CONTINUE")
            self.assertEqual(session.read_bytes(), source_before)
            self.assertEqual(handoff.read_bytes(), handoff_before)

    def test_repo_newer_than_saved_state_blocks_verification(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            session = self._session(root, repo)
            result = self._salvage(session, root / "rescue")

            (repo / "app.txt").write_text("newer repository state\n", encoding="utf-8")
            _git(repo, "add", "app.txt")
            _git(repo, "commit", "-qm", "advance after salvage")

            verification = verify_rescue(root / "rescue", result.rescue_id)
            self.assertEqual(verification.status, "STATE_DIVERGED")
            self.assertTrue(any("head_sha" in conflict for conflict in verification.conflicts))

    def test_multiple_unfinished_calls_are_all_represented_as_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            repo = self._repo(root)
            session = self._session(
                root,
                repo,
                {
                    "timestamp": "2026-08-12T00:00:02Z",
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "call-one",
                        "name": "shell_command",
                        "arguments": json.dumps({"command": "echo-one"}),
                    },
                },
                {
                    "timestamp": "2026-08-12T00:00:03Z",
                    "type": "response_item",
                    "payload": {
                        "type": "function_call",
                        "call_id": "call-two",
                        "name": "shell_command",
                        "arguments": json.dumps({"command": "echo-two"}),
                    },
                },
            )

            doctor = doctor_session(session)
            self.assertEqual(doctor.status, "UNFINISHED_TOOL_CALL")
            self.assertEqual(
                {item["call_id"] for item in doctor.transcript.unfinished_tool_calls},
                {"call-one", "call-two"},
            )

            result = salvage_session(
                session,
                doctor.transcript,
                doctor.status,
                doctor.findings,
                root / "rescue",
                True,
            )
            handoff = load_handoff(root / "rescue", result.rescue_id)
            serialized = json.dumps(handoff, ensure_ascii=False, sort_keys=True)

            self.assertIn("call-one", serialized)
            self.assertIn("call-two", serialized)
            self.assertEqual(handoff["tool_state"].get("confidence"), "unknown")


if __name__ == "__main__":
    unittest.main()
