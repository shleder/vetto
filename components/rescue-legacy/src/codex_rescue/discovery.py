"""Read-only, bounded discovery of Codex rollout files.

The full transcript parser is intentionally not used here.  Discovery is the
cheap first step in the CLI flow: enumerate recent rollouts, inspect only a
small prefix and suffix, and expose enough metadata for a user to choose a
session.  A later ``doctor``/``salvage`` invocation can perform the complete
parse once a path has been selected.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from .thread_identity import ThreadIdentityEvidence, resolve_thread_identity


DEFAULT_HEAD_BYTES = 64 * 1024
DEFAULT_TAIL_BYTES = 128 * 1024
DEFAULT_PROMPT_LIMIT = 240
DEFAULT_LIMIT = 20

_ROLLOUT_NAME = "rollout-*.jsonl"
_CALL_TYPES = {"function_call", "custom_tool_call", "tool_search_call"}
_OUTPUT_TYPES = {"function_call_output", "custom_tool_call_output", "tool_search_output"}
_SECRET_PATTERNS = (
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\b(?:rk|pk)-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{8,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bnpm_[A-Za-z0-9_-]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@"), r"\1[REDACTED_USER]:[REDACTED_SECRET]@"),
    (re.compile(r'''(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)[^\s,;"'}]+'''), r"\1[REDACTED_SECRET]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL), "[REDACTED_SECRET]"),
    (re.compile(r"\bAKIA[0-9A-Z]{12,}\b"), "[REDACTED_SECRET]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/-]{16,}"), "Bearer [REDACTED_SECRET]"),
)


@dataclass(frozen=True)
class SessionSummary:
    """Bounded metadata and health hint for one rollout file."""

    path: Path
    session_id: str | None
    cwd: str | None
    repo: str | None
    first_prompt: str | None
    last_prompt: str | None
    status: str
    reason: str | None
    mtime: float
    size: int
    archived: bool = False
    thread_identity: ThreadIdentityEvidence | None = None

    @property
    def rollout_path(self) -> Path:
        return self.path

    @property
    def id(self) -> str | None:
        return self.session_id

    @property
    def first_user_prompt(self) -> str | None:
        return self.first_prompt

    @property
    def last_user_prompt(self) -> str | None:
        return self.last_prompt

    @property
    def prompt_preview(self) -> str | None:
        return self.last_prompt or self.first_prompt

    @property
    def modified_at(self) -> str:
        return datetime.fromtimestamp(self.mtime, tz=timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "rollout_path": str(self.path),
            "session_id": self.session_id,
            "thread_identity": self.thread_identity.to_dict() if self.thread_identity else None,
            "cwd": self.cwd,
            "repo": self.repo,
            "first_prompt": self.first_prompt,
            "last_prompt": self.last_prompt,
            "first_user_prompt": self.first_prompt,
            "last_user_prompt": self.last_prompt,
            "prompt_preview": self.prompt_preview,
            "status": self.status,
            "reason": self.reason,
            "mtime": self.mtime,
            "modified_at": self.modified_at,
            "size": self.size,
            "archived": self.archived,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self.to_dict().get(key, default)


@dataclass(frozen=True)
class _Window:
    data: bytes
    offset: int
    total_size: int
    starts_at_line_boundary: bool


@dataclass(frozen=True)
class _Scan:
    records: tuple[dict[str, Any], ...]
    malformed: bool = False
    prompts: tuple[str, ...] = ()


def codex_home_path(codex_home: str | os.PathLike[str] | None = None) -> Path:
    raw = codex_home
    if raw is None:
        raw = os.environ.get("CODEX_HOME")
    if raw:
        return Path(os.path.expandvars(os.path.expanduser(os.fspath(raw)))).resolve()
    return (Path.home() / ".codex").resolve()


def _rollout_paths(root: Path, include_archived: bool) -> list[Path]:
    search_roots: list[tuple[Path, bool]] = []
    sessions = root / "sessions"
    if sessions.is_dir():
        search_roots.append((sessions, False))
    if root.name.lower() == "sessions" and root.is_dir():
        search_roots.append((root, False))
    if include_archived:
        archived = root / "archived_sessions"
        if archived.is_dir():
            search_roots.append((archived, True))
        if root.name.lower() == "archived_sessions" and root.is_dir():
            search_roots.append((root, True))

    found: dict[Path, bool] = {}
    for base, is_archived in search_roots:
        try:
            candidates = base.rglob(_ROLLOUT_NAME)
        except OSError:
            continue
        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
                resolved = candidate.resolve()
                found[resolved] = found.get(resolved, is_archived) or is_archived
            except OSError:
                continue
    return sorted(found, key=lambda path: str(path))


def _read_windows(path: Path, head_bytes: int, tail_bytes: int) -> tuple[_Window, _Window]:
    stat = path.stat()
    size = max(0, int(stat.st_size))
    head_limit = max(1, int(head_bytes))
    tail_limit = max(1, int(tail_bytes))
    with path.open("rb") as stream:
        head = stream.read(head_limit)
        tail_offset = max(0, size - tail_limit)
        stream.seek(tail_offset)
        tail = stream.read(tail_limit)
        if tail_offset:
            stream.seek(tail_offset - 1)
            previous = stream.read(1)
            starts_at_boundary = previous == b"\n"
        else:
            starts_at_boundary = True
    return (
        _Window(head, 0, size, True),
        _Window(tail, tail_offset, size, starts_at_boundary),
    )


def _iter_lines(window: _Window, *, tail: bool) -> Iterator[bytes]:
    parts = window.data.splitlines(keepends=True)
    for index, raw in enumerate(parts):
        if not raw:
            continue
        complete = raw.endswith((b"\n", b"\r"))
        if tail and index == 0 and window.offset and not window.starts_at_line_boundary:
            continue
        if (
            not tail
            and index == len(parts) - 1
            and window.offset + len(window.data) < window.total_size
            and not complete
        ):
            continue
        yield raw.rstrip(b"\r\n")


def _text(value: Any, limit: int = DEFAULT_PROMPT_LIMIT) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        text = value
    elif isinstance(value, (list, tuple)):
        pieces: list[str] = []
        for item in value:
            if isinstance(item, dict):
                piece = item.get("text") or item.get("content") or item.get("message")
            else:
                piece = item
            if piece is not None:
                pieces.append(str(piece))
        text = " ".join(pieces)
    elif isinstance(value, dict):
        text = str(value.get("text") or value.get("message") or value.get("content") or "")
    else:
        text = str(value)
    text = re.sub(r"\s+", " ", text).strip()
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    text = re.sub(r"data:[^;\s]+;base64,[A-Za-z0-9+/=]+", "[REDACTED_INLINE_PAYLOAD]", text)
    if not text:
        return None
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _payload(record: dict[str, Any]) -> dict[str, Any]:
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else {}


def _prompt(record: dict[str, Any], limit: int) -> str | None:
    payload = _payload(record)
    kind = payload.get("type") or record.get("type")
    role = payload.get("role") or record.get("role")
    if kind not in {"user_message", "user_prompt", "user_input"} and role != "user":
        return None
    value = payload.get("message")
    if value is None:
        value = payload.get("text", payload.get("content"))
    if value is None:
        value = record.get("message", record.get("text", record.get("content")))
    return _text(value, limit)


def _scan_window(window: _Window, *, tail: bool, prompt_limit: int) -> _Scan:
    records: list[dict[str, Any]] = []
    prompts: list[str] = []
    malformed = False
    for raw in _iter_lines(window, tail=tail):
        if not raw:
            continue
        if b"\x00" in raw:
            malformed = True
            continue
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            malformed = True
            continue
        if not isinstance(value, dict):
            malformed = True
            continue
        records.append(value)
        prompt = _prompt(value, prompt_limit)
        if prompt:
            prompts.append(prompt)
    return _Scan(tuple(records), malformed, tuple(prompts))


def _metadata(
    records: tuple[dict[str, Any], ...],
    path: Path,
) -> tuple[str | None, str | None, str | None, ThreadIdentityEvidence]:
    session_meta: dict[str, Any] | None = None
    cwd: str | None = None
    repo: str | None = None
    for record in records:
        payload = _payload(record)
        if record.get("type") == "session_meta" and session_meta is None:
            session_meta = dict(payload)
        if record.get("type") == "session_meta" or payload.get("cwd"):
            cwd = cwd or _string(payload.get("cwd") or payload.get("worktree") or payload.get("workspace"))
            value = payload.get("repo") or payload.get("repo_name") or payload.get("repository") or payload.get("project")
            if isinstance(value, dict):
                value = value.get("name") or value.get("path")
            repo = repo or _string(value)
        cwd = cwd or _string(record.get("cwd"))
    identity = resolve_thread_identity(path, session_meta=session_meta)
    if repo is None and cwd:
        repo = ntpath.basename(cwd.rstrip("\\/")) or None
    return identity.thread_id, cwd, repo, identity


def _string(value: Any) -> str | None:
    if value is None:
        return None
    value = str(value).strip()
    return value or None


def _tail_findings(records: tuple[dict[str, Any], ...]) -> bool:
    calls: dict[str, str] = {}
    completed: set[str] = set()
    for record in records:
        payload = _payload(record)
        kind = payload.get("type") or record.get("type")
        if kind in _CALL_TYPES:
            call_id = _string(payload.get("call_id") or payload.get("id") or record.get("call_id"))
            if call_id:
                calls[call_id] = _string(payload.get("name")) or "tool call"
        elif kind in _OUTPUT_TYPES:
            call_id = _string(payload.get("call_id") or payload.get("id") or record.get("call_id"))
            if call_id:
                completed.add(call_id)
    return any(call_id not in completed for call_id in calls)


def lightweight_scan(
    path: str | os.PathLike[str],
    *,
    head_bytes: int = DEFAULT_HEAD_BYTES,
    tail_bytes: int = DEFAULT_TAIL_BYTES,
    prompt_limit: int = DEFAULT_PROMPT_LIMIT,
    archived: bool | None = None,
) -> SessionSummary:
    source = Path(path).expanduser().resolve()
    stat = source.stat()
    head_window, tail_window = _read_windows(source, head_bytes, tail_bytes)
    head = _scan_window(head_window, tail=False, prompt_limit=prompt_limit)
    tail = _scan_window(tail_window, tail=True, prompt_limit=prompt_limit)
    records = head.records + tail.records
    session_id, cwd, repo, thread_identity = _metadata(records, source)
    prompts = head.prompts + tail.prompts
    malformed_tail = tail.malformed
    unfinished = _tail_findings(tail.records)
    if malformed_tail:
        status = "damaged"
        reason = "malformed tail"
        if unfinished:
            reason += "; unfinished tool call"
    elif unfinished:
        status = "suspicious"
        reason = "unfinished tool call"
    else:
        status = "healthy"
        reason = None
    if thread_identity.conflict:
        if status == "healthy":
            status = "suspicious"
            reason = "thread identity conflict"
        elif reason:
            reason += "; thread identity conflict"
    if archived is None:
        archived = "archived_sessions" in {part.lower() for part in source.parts}
    return SessionSummary(
        path=source,
        session_id=session_id,
        cwd=cwd,
        repo=repo,
        first_prompt=prompts[0] if prompts else None,
        last_prompt=prompts[-1] if prompts else None,
        status=status,
        reason=reason,
        mtime=stat.st_mtime,
        size=stat.st_size,
        archived=bool(archived),
        thread_identity=thread_identity,
    )


def discover_sessions(
    codex_home: str | os.PathLike[str] | None = None,
    *,
    limit: int | None = DEFAULT_LIMIT,
    include_archived: bool = True,
    head_bytes: int = DEFAULT_HEAD_BYTES,
    tail_bytes: int = DEFAULT_TAIL_BYTES,
    prompt_limit: int = DEFAULT_PROMPT_LIMIT,
) -> list[SessionSummary]:
    root = codex_home_path(codex_home)
    candidates: list[tuple[float, int, Path, bool]] = []
    for path in _rollout_paths(root, include_archived):
        try:
            stat = path.stat()
        except OSError:
            continue
        archived = "archived_sessions" in {part.lower() for part in path.parts}
        candidates.append((stat.st_mtime, stat.st_size, path, archived))
    candidates.sort(key=lambda item: (item[0], str(item[2])), reverse=True)
    if limit is not None:
        candidates = candidates[: max(0, int(limit))]
    results: list[SessionSummary] = []
    for _, _, path, archived in candidates:
        try:
            results.append(
                lightweight_scan(
                    path,
                    head_bytes=head_bytes,
                    tail_bytes=tail_bytes,
                    prompt_limit=prompt_limit,
                    archived=archived,
                )
            )
        except (OSError, ValueError):
            continue
    return results


def resolve_latest(
    codex_home: str | os.PathLike[str] | None = None,
    *,
    include_archived: bool = True,
) -> Path | None:
    root = codex_home_path(codex_home)
    candidates: list[tuple[float, Path]] = []
    for path in _rollout_paths(root, include_archived):
        try:
            candidates.append((path.stat().st_mtime, path))
        except OSError:
            continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], str(item[1])))[1]


__all__ = [
    "DEFAULT_HEAD_BYTES",
    "DEFAULT_TAIL_BYTES",
    "DEFAULT_PROMPT_LIMIT",
    "DEFAULT_LIMIT",
    "SessionSummary",
    "codex_home_path",
    "discover_sessions",
    "lightweight_scan",
    "resolve_latest",
]
