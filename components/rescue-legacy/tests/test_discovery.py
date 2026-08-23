from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from codex_rescue.discovery import (
    discover_sessions,
    lightweight_scan,
    resolve_latest,
)


def _record(record_type: str, payload: dict[str, object]) -> bytes:
    return (json.dumps({"type": record_type, "payload": payload}) + "\n").encode()


def _rollout(
    session_id: str,
    cwd: str,
    first_prompt: str,
    last_prompt: str | None = None,
    *,
    unfinished: bool = False,
) -> bytes:
    records = [
        _record("session_meta", {"session_id": session_id, "cwd": cwd}),
        _record("event_msg", {"type": "user_message", "message": first_prompt}),
    ]
    if last_prompt is not None:
        records.append(_record("event_msg", {"type": "user_message", "message": last_prompt}))
    if unfinished:
        records.append(
            _record(
                "response_item",
                {"type": "function_call", "call_id": "call-1", "name": "shell_command", "arguments": "{\"command\":\"echo hi\"}"},
            )
        )
    else:
        records.append(
            _record(
                "response_item",
                {"type": "function_call", "call_id": "call-1", "name": "shell_command", "arguments": "{\"command\":\"echo hi\"}"},
            )
        )
        records.append(
            _record(
                "response_item",
                {"type": "function_call_output", "call_id": "call-1", "output": "hi"},
            )
        )
    return b"".join(records)


class DiscoveryTests(unittest.TestCase):
    def _home(self, root: Path) -> Path:
        sessions = root / "sessions" / "2026" / "08" / "12"
        sessions.mkdir(parents=True)
        return root

    def test_discovers_recent_rollouts_sorted_by_mtime_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            old = home / "sessions" / "2026" / "08" / "12" / "rollout-old.jsonl"
            new = home / "sessions" / "2026" / "08" / "12" / "rollout-new.jsonl"
            old.write_bytes(_rollout("old-id", r"C:\work\old", "old task"))
            new.write_bytes(_rollout("new-id", r"C:\work\new", "first task", "latest task"))
            now = time.time()
            os.utime(old, (now - 30, now - 30))
            os.utime(new, (now, now))

            found = discover_sessions(home)

            self.assertEqual([item.session_id for item in found], ["new-id", "old-id"])
            self.assertEqual(found[0].cwd, r"C:\work\new")
            self.assertEqual(found[0].repo, "new")
            self.assertEqual(found[0].first_prompt, "first task")
            self.assertEqual(found[0].last_prompt, "latest task")
            self.assertEqual(found[0].status, "healthy")
            self.assertIsNone(found[0].reason)

    def test_env_codex_home_and_resolve_latest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            path = home / "sessions" / "2026" / "08" / "12" / "rollout-latest.jsonl"
            path.write_bytes(_rollout("latest-id", r"C:\repo\app", "task"))
            with patch.dict(os.environ, {"CODEX_HOME": str(home)}, clear=False):
                self.assertEqual(resolve_latest(), path.resolve())
                self.assertEqual(discover_sessions()[0].path, path.resolve())

    def test_tail_classifies_unfinished_call_without_full_parse(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout-broken.jsonl"
            path.write_bytes(_rollout("broken-id", r"C:\repo\broken", "start", unfinished=True))

            result = lightweight_scan(path)

            self.assertEqual(result.session_id, "broken-id")
            self.assertEqual(result.status, "suspicious")
            self.assertEqual(result.reason, "unfinished tool call")

    def test_malformed_tail_is_damaged_and_source_is_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout-damaged.jsonl"
            raw = _rollout("damaged-id", r"C:\repo\damaged", "start") + b'{"type":"response_item"'
            path.write_bytes(raw)
            before = path.read_bytes()

            result = lightweight_scan(path)

            self.assertEqual(result.status, "damaged")
            self.assertEqual(result.reason, "malformed tail")
            self.assertEqual(path.read_bytes(), before)

    def test_scans_bounded_head_and_tail_for_large_rollout(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "rollout-large.jsonl"
            prefix = _record("session_meta", {"session_id": "large-id", "cwd": r"C:\repo\large"})
            prefix += _record("event_msg", {"type": "user_message", "message": "first"})
            filler = _record("event_msg", {"type": "agent_message", "message": "x" * 100})
            path.write_bytes(prefix + filler * 5000 + _record("event_msg", {"type": "user_message", "message": "last"}))

            original_open = Path.open
            reads: list[int] = []

            def tracked_open(self: Path, *args: object, **kwargs: object):
                stream = original_open(self, *args, **kwargs)
                original_read = stream.read

                def tracked_read(size: int = -1, *read_args: object, **read_kwargs: object):
                    if size != -1:
                        reads.append(size)
                    return original_read(size, *read_args, **read_kwargs)

                stream.read = tracked_read  # type: ignore[method-assign]
                return stream

            with patch("codex_rescue.discovery.Path.open", tracked_open):
                result = lightweight_scan(path, head_bytes=256, tail_bytes=256)

            self.assertEqual(result.session_id, "large-id")
            self.assertEqual(result.first_prompt, "first")
            self.assertEqual(result.last_prompt, "last")
            self.assertTrue(reads)
            self.assertLessEqual(max(reads), 256)

    def test_limit_is_applied_after_recency_sort(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            home = self._home(Path(td))
            base = home / "sessions" / "2026" / "08" / "12"
            for index in range(3):
                path = base / f"rollout-{index}.jsonl"
                path.write_bytes(_rollout(str(index), r"C:\repo", f"task {index}"))
                os.utime(path, (index, index))
            found = discover_sessions(home, limit=2)
            self.assertEqual([item.session_id for item in found], ["2", "1"])


if __name__ == "__main__":
    unittest.main()
