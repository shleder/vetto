from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class JournalEntry:
    version: int
    session_id: str
    timestamp: str
    event: str
    cwd: str | None = None
    worktree: str | None = None
    base_sha: str | None = None
    head_sha: str | None = None
    diff_hash: str | None = None
    changed_files: tuple[str, ...] = ()
    last_user_prompt: str | None = None
    completed_actions: tuple[dict[str, Any], ...] = ()
    pending_action: dict[str, Any] | None = None
    commands: tuple[dict[str, Any], ...] = ()
    tests: tuple[dict[str, Any], ...] = ()
    transcript_offset: int | None = None
    transcript_hash: str | None = None


def _safe_id(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:24]


def journal_path(root: str | Path, session_id: str) -> Path:
    return Path(root) / "journal" / f"{_safe_id(session_id)}.jsonl"


def append_entry(root: str | Path, entry: JournalEntry) -> Path:
    path = journal_path(root, entry.session_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(asdict(entry), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    data = (payload + "\n").encode("utf-8")
    fd = os.open(path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        written = 0
        while written < len(data):
            written += os.write(fd, data[written:])
        os.fsync(fd)
    finally:
        os.close(fd)
    return path


def read_entries(root: str | Path, session_id: str) -> tuple[list[dict[str, Any]], bool]:
    path = journal_path(root, session_id)
    if not path.exists():
        return [], False
    entries: list[dict[str, Any]] = []
    partial_tail = False
    with path.open("rb") as stream:
        for line in stream:
            if not line.endswith(b"\n"):
                partial_tail = True
                break
            try:
                item = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                partial_tail = True
                break
            if isinstance(item, dict):
                entries.append(item)
            else:
                partial_tail = True
                break
    return entries, partial_tail


def utc_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
