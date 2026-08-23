from __future__ import annotations

import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .redact import sanitize_path
from .thread_identity import (
    THREAD_IDENTITY_CONFLICT,
    ThreadIdentityEvidence,
    resolve_thread_identity,
)
from .transcript import _read_line_bounded, MAX_RECORD_BYTES


@dataclass
class RolloutMetrics:
    total_lines: int = 0
    total_bytes: int = 0
    records_by_type: dict[str, int] = field(default_factory=dict)
    turn_count: int = 0
    tool_call_count: int = 0
    tool_output_count: int = 0
    compaction_count: int = 0
    inline_image_bytes: int = 0
    inline_image_count: int = 0
    tool_output_bytes: int = 0
    last_ordinal: int | None = None
    last_timestamp: str | None = None
    has_trailing_newline: bool = True
    is_truncated: bool = False
    subagent_ids: list[str] = field(default_factory=list)
    parent_id: str | None = None
    unknown_record_kinds: list[str] = field(default_factory=list)
    lifecycle_events: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class SqliteMetrics:
    present: bool = False
    db_path: str | None = None
    thread_found: bool = False
    thread_id: str | None = None
    thread_title: str | None = None
    item_count: int = 0
    projection_cursor: int | None = None
    history_mode: str | None = None
    integrity_ok: bool = True
    schema_version: int | None = None


@dataclass
class WriterMetrics:
    lock_present: bool = False
    lock_path: str | None = None
    pid: int | None = None
    is_alive: bool | None = None
    runtime_surface: str | None = None
    lock_age_seconds: float | None = None


@dataclass
class WorkspaceMetrics:
    saved_cwd: str | None = None
    saved_repo: str | None = None
    path_family: str = "unknown"
    accessible: bool = False
    repo_accessible: bool = False
    translated_path: str | None = None


@dataclass
class SessionEvidence:
    session_id: str | None
    session_path: str
    thread_identity: ThreadIdentityEvidence = field(default_factory=ThreadIdentityEvidence)
    is_archived: bool = False
    mtime: float = 0.0
    size_bytes: int = 0
    rollout: RolloutMetrics = field(default_factory=RolloutMetrics)
    sqlite: SqliteMetrics = field(default_factory=SqliteMetrics)
    writer: WriterMetrics = field(default_factory=WriterMetrics)
    workspace: WorkspaceMetrics = field(default_factory=WorkspaceMetrics)
    findings: list[str] = field(default_factory=list)
    status: str = "HEALTHY"
    confidence: str = "HIGH"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def detect_path_family(p: str) -> str:
    if not p:
        return "unknown"
    if p.startswith("/mnt/") and len(p) > 6 and p[6] == "/":
        return "wsl"
    if len(p) >= 2 and p[1] == ":" and (p[0].isalpha()):
        return "windows"
    if p.startswith("/"):
        return "posix"
    return "unknown"


def translate_path(p: str) -> str | None:
    fam = detect_path_family(p)
    if fam == "wsl":
        drive = p[5].upper()
        rest = p[6:].replace("/", "\\")
        return f"{drive}:{rest}"
    elif fam == "windows":
        drive = p[0].lower()
        rest = p[2:].replace("\\", "/")
        return f"/mnt/{drive}{rest}"
    return None


def is_pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                exit_code = wintypes.DWORD()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    is_active = (exit_code.value == 259)  # STILL_ACTIVE = 259
                    kernel32.CloseHandle(handle)
                    return is_active
                kernel32.CloseHandle(handle)
                return True
            return False
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except Exception:
        return False


def collect_session_evidence(
    session_path: Path | str,
    codex_home: Path | str | None = None,
    max_scan_lines: int = 100_000,
) -> SessionEvidence:
    path = Path(session_path).resolve()
    initial_identity = resolve_thread_identity(path)
    is_archived = "archived_sessions" in str(path) or "archive" in path.parts

    mtime = 0.0
    size_bytes = 0
    if path.exists():
        stat = path.stat()
        mtime = stat.st_mtime
        size_bytes = stat.st_size

    evidence = SessionEvidence(
        session_id=initial_identity.thread_id,
        session_path=str(path),
        thread_identity=initial_identity,
        is_archived=is_archived,
        mtime=mtime,
        size_bytes=size_bytes,
    )

    session_meta: dict[str, Any] | None = None

    if path.exists() and size_bytes > 0:
        try:
            with open(path, "rb") as f:
                lines = 0
                while lines < max_scan_lines:
                    line_bytes, oversized, total_len = _read_line_bounded(f, MAX_RECORD_BYTES)
                    if not line_bytes:
                        break
                    lines += 1
                    evidence.rollout.total_lines += 1
                    evidence.rollout.total_bytes += total_len
                    complete_line = line_bytes.endswith(b"\n")
                    if not complete_line:
                        evidence.rollout.has_trailing_newline = False
                        evidence.rollout.is_truncated = True

                    has_nul = b"\x00" in line_bytes
                    if oversized:
                        if has_nul:
                            if "MALFORMED_JSONL" not in evidence.findings:
                                evidence.findings.append("MALFORMED_JSONL")
                        elif not complete_line:
                            if "TRUNCATED_JSONL" not in evidence.findings:
                                evidence.findings.append("TRUNCATED_JSONL")
                        else:
                            if "VALID_BUT_OVERSIZED" not in evidence.findings:
                                evidence.findings.append("VALID_BUT_OVERSIZED")
                            if "OVERSIZED_PAYLOAD" not in evidence.findings:
                                evidence.findings.append("OVERSIZED_PAYLOAD")
                        if "OVERSIZED_RECORD" not in evidence.findings:
                            evidence.findings.append("OVERSIZED_RECORD")
                        continue

                    if has_nul:
                        if "MALFORMED_JSONL" not in evidence.findings:
                            evidence.findings.append("MALFORMED_JSONL")
                        continue

                    try:
                        record = json.loads(line_bytes.decode("utf-8", errors="ignore"))
                    except Exception:
                        if not complete_line:
                            if "TRUNCATED_JSONL" not in evidence.findings:
                                evidence.findings.append("TRUNCATED_JSONL")
                        else:
                            if "MALFORMED_JSONL" not in evidence.findings:
                                evidence.findings.append("MALFORMED_JSONL")
                        continue

                    payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
                    if record.get("type") == "session_meta" and session_meta is None:
                        session_meta = dict(payload)
                        parent = payload.get("parent_thread_id")
                        if parent not in (None, "") and not evidence.rollout.parent_id:
                            evidence.rollout.parent_id = str(parent)

                    rtype = record.get("type") or record.get("event") or "unknown"
                    evidence.rollout.records_by_type[rtype] = evidence.rollout.records_by_type.get(rtype, 0) + 1

                    ord_val = record.get("ordinal") or record.get("seq") or record.get("idx")
                    if isinstance(ord_val, int):
                        evidence.rollout.last_ordinal = ord_val
                    ts = record.get("timestamp") or record.get("created_at") or record.get("time")
                    if ts and isinstance(ts, str):
                        evidence.rollout.last_timestamp = ts

                    if rtype in ("turn_started", "user_message", "turn"):
                        evidence.rollout.turn_count += 1
                        evidence.rollout.lifecycle_events.append({
                            "event": "turn_started",
                            "ordinal": evidence.rollout.last_ordinal,
                            "timestamp": ts,
                        })
                    elif rtype in ("tool_call", "function_call", "call"):
                        evidence.rollout.tool_call_count += 1
                    elif rtype in ("tool_output", "function_call_output", "result"):
                        evidence.rollout.tool_output_count += 1
                        payload_str = str(record.get("output") or record.get("content") or "")
                        evidence.rollout.tool_output_bytes += len(payload_str)
                    elif rtype in ("compaction", "context_compaction"):
                        evidence.rollout.compaction_count += 1
                        evidence.rollout.lifecycle_events.append({
                            "event": "compaction",
                            "ordinal": evidence.rollout.last_ordinal,
                            "timestamp": ts,
                        })
                    elif rtype in ("task_complete", "task_completed", "turn_complete"):
                        evidence.rollout.lifecycle_events.append({
                            "event": "task_complete",
                            "ordinal": evidence.rollout.last_ordinal,
                            "timestamp": ts,
                        })

                    rec_str = line_bytes.decode("utf-8", errors="ignore")
                    if "data:image/" in rec_str:
                        evidence.rollout.inline_image_count += 1
                        evidence.rollout.inline_image_bytes += len(rec_str)

                    if total_len > 1_000_000:
                        if "OVERSIZED_PAYLOAD" not in evidence.findings:
                            evidence.findings.append("OVERSIZED_PAYLOAD")
                        if "VALID_BUT_OVERSIZED" not in evidence.findings:
                            evidence.findings.append("VALID_BUT_OVERSIZED")

                    parent = record.get("parent_session_id") or record.get("parent_id")
                    if parent and not evidence.rollout.parent_id:
                        evidence.rollout.parent_id = str(parent)
                    subagent = record.get("subagent_id") or record.get("child_session_id")
                    if subagent and str(subagent) not in evidence.rollout.subagent_ids:
                        evidence.rollout.subagent_ids.append(str(subagent))

                    cwd = record.get("cwd") or record.get("working_directory") or record.get("workspace")
                    if not cwd and record.get("type") == "session_meta":
                        cwd = payload.get("cwd")
                    if cwd and not evidence.workspace.saved_cwd:
                        evidence.workspace.saved_cwd = str(cwd)
                        evidence.workspace.path_family = detect_path_family(str(cwd))
                        evidence.workspace.accessible = Path(str(cwd)).exists() if evidence.workspace.path_family == "posix" else False
                        evidence.workspace.translated_path = translate_path(str(cwd))
                    repo = record.get("repo") or record.get("repository")
                    if repo and not evidence.workspace.saved_repo:
                        evidence.workspace.saved_repo = str(repo)

                if lines >= max_scan_lines:
                    evidence.rollout.is_truncated = True
                    if "INCOMPLETE_SCAN" not in evidence.findings:
                        evidence.findings.append("INCOMPLETE_SCAN")
        except Exception:
            if "SCAN_READ_ERROR" not in evidence.findings:
                evidence.findings.append("SCAN_READ_ERROR")

    evidence.thread_identity = resolve_thread_identity(path, session_meta=session_meta)
    evidence.session_id = evidence.thread_identity.thread_id
    if evidence.thread_identity.conflict and THREAD_IDENTITY_CONFLICT not in evidence.findings:
        evidence.findings.append(THREAD_IDENTITY_CONFLICT)

    lock_candidates = [
        path.with_suffix(".lock"),
        path.parent / f"{path.name}.lock",
    ]
    if evidence.session_id:
        lock_candidates.append(path.parent / f"{evidence.session_id}.lock")
    seen_locks: set[Path] = set()
    for lc in lock_candidates:
        if lc in seen_locks:
            continue
        seen_locks.add(lc)
        if lc.exists():
            evidence.writer.lock_present = True
            evidence.writer.lock_path = str(lc)
            try:
                lstat = lc.stat()
                evidence.writer.lock_age_seconds = round(time.time() - lstat.st_mtime, 2)
                content = lc.read_text(encoding="utf-8", errors="ignore").strip()
                if content.isdigit():
                    pid = int(content)
                    evidence.writer.pid = pid
                    evidence.writer.is_alive = is_pid_alive(pid)
                    evidence.writer.runtime_surface = "cli" if evidence.writer.is_alive else "stale_lock"
            except Exception:
                pass
            break

    chome = Path(codex_home).resolve() if codex_home else path.parent.parent
    db_candidates = [
        chome / "state.db",
        chome / "codex.db",
        chome / "threads.db",
        path.parent / "state.db",
    ]
    for db in db_candidates:
        if db.exists():
            evidence.sqlite.present = True
            evidence.sqlite.db_path = str(db)
            try:
                conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True, timeout=1.0)
                try:
                    cur = conn.cursor()
                    cur.execute("PRAGMA integrity_check")
                    row = cur.fetchone()
                    evidence.sqlite.integrity_ok = bool(row and row[0] == "ok")
                    cur.execute("PRAGMA user_version")
                    uv = cur.fetchone()
                    if uv:
                        evidence.sqlite.schema_version = uv[0]

                    if evidence.session_id:
                        for tbl in ("threads", "sessions", "conversations"):
                            cur.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{tbl}'")
                            if cur.fetchone():
                                cur.execute(
                                    f"SELECT * FROM {tbl} WHERE id=? OR id LIKE ? LIMIT 1",
                                    (evidence.session_id, f"%{evidence.session_id}%"),
                                )
                                trow = cur.fetchone()
                                if trow:
                                    evidence.sqlite.thread_found = True
                                    evidence.sqlite.thread_id = str(trow[0])
                                    break
                finally:
                    conn.close()
            except Exception:
                evidence.sqlite.integrity_ok = False
            break

    if "SCAN_READ_ERROR" in evidence.findings:
        evidence.status = "UNREADABLE"
        evidence.confidence = "LOW"
    elif "MALFORMED_JSONL" in evidence.findings:
        evidence.status = "CORRUPT"
        evidence.confidence = "HIGH"
    elif "TRUNCATED_JSONL" in evidence.findings:
        evidence.status = "CORRUPT"
        evidence.confidence = "HIGH"
    elif "OVERSIZED_RECORD" in evidence.findings or "OVERSIZED_PAYLOAD" in evidence.findings or "VALID_BUT_OVERSIZED" in evidence.findings:
        evidence.status = "OVERSIZED"
        evidence.confidence = "HIGH"
    elif "INCOMPLETE_SCAN" in evidence.findings:
        evidence.status = "INCOMPLETE"
        evidence.confidence = "MEDIUM"
    elif evidence.writer.lock_present and evidence.writer.is_alive:
        evidence.status = "ACTIVE_WRITER"
        evidence.confidence = "HIGH"
    elif evidence.findings:
        evidence.status = "WARNINGS"
        evidence.confidence = "HIGH"
    else:
        evidence.status = "HEALTHY"
        evidence.confidence = "HIGH"

    return evidence
