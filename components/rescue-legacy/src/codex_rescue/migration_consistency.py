from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .alpha5 import _connect_read_only, _quote_identifier
from .transcript import MAX_RECORD_BYTES, ParseResult, _read_line_bounded


MAX_INDEX_LINES = 100_000
MAX_INDEX_LINE_BYTES = 256 * 1024
MAX_STATE_DB_CANDIDATES = 16
_STATE_DB_RE = re.compile(r"^state_(\d+)\.sqlite$")


@dataclass
class MigrationConsistencyReport:
    status: str = "not_applicable"
    findings: list[str] = field(default_factory=list)
    thread_id: str | None = None
    head_ordinal: int | None = None
    subagent_history_start_ordinal: int | None = None
    valid_record_count: int = 0
    subagent_boundary_suspect: bool = False
    boundary_reason: str | None = None
    session_index_name_present: bool | None = None
    session_index_name_length: int | None = None
    sqlite_name_present: bool | None = None
    sqlite_history_mode: str | None = None
    name_metadata_diverged: bool = False
    name_reason: str | None = None
    state_db: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "findings": self.findings,
            "thread_id": self.thread_id,
            "head_ordinal": self.head_ordinal,
            "subagent_history_start_ordinal": self.subagent_history_start_ordinal,
            "valid_record_count": self.valid_record_count,
            "subagent_boundary_suspect": self.subagent_boundary_suspect,
            "boundary_reason": self.boundary_reason,
            "session_index_name_present": self.session_index_name_present,
            "session_index_name_length": self.session_index_name_length,
            "sqlite_name_present": self.sqlite_name_present,
            "sqlite_history_mode": self.sqlite_history_mode,
            "name_metadata_diverged": self.name_metadata_diverged,
            "name_reason": self.name_reason,
            "state_db": self.state_db,
        }


def _codex_home(source: Path) -> Path | None:
    for parent in source.parents:
        if parent.name.lower() in {"sessions", "archived_sessions"}:
            return parent.parent
    return None


def _thread_id(parsed: ParseResult, source: Path) -> str | None:
    for key in ("session_id", "id"):
        value = parsed.session_metadata.get(key)
        if value not in (None, ""):
            return str(value)
    match = re.search(
        r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        source.name,
    )
    return match.group(1) if match else None


def _head_session_meta(source: Path) -> tuple[dict[str, Any], int | None]:
    try:
        with source.open("rb") as stream:
            line, oversized, _ = _read_line_bounded(
                stream, max_bytes=MAX_RECORD_BYTES, digest=None
            )
    except OSError:
        return {}, None
    if not line or oversized:
        return {}, None
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return {}, None
    if not isinstance(record, dict) or record.get("type") != "session_meta":
        return {}, None
    raw_ordinal = record.get("ordinal")
    head_ordinal = (
        raw_ordinal
        if isinstance(raw_ordinal, int) and not isinstance(raw_ordinal, bool) and raw_ordinal >= 0
        else None
    )
    payload = record.get("payload")
    return (payload if isinstance(payload, dict) else {}), head_ordinal


def _read_index_name(root: Path, thread_id: str) -> tuple[bool | None, int | None]:
    index = root / "session_index.jsonl"
    if not index.is_file():
        return None, None
    matched_name_length: int | None = None
    try:
        with index.open("rb") as stream:
            for _ in range(MAX_INDEX_LINES):
                line, oversized, _ = _read_line_bounded(
                    stream, max_bytes=MAX_INDEX_LINE_BYTES, digest=None
                )
                if not line:
                    break
                if oversized:
                    continue
                try:
                    record = json.loads(line)
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(record, dict):
                    continue
                if str(record.get("id") or "") != thread_id:
                    continue
                raw_name = record.get("thread_name")
                if isinstance(raw_name, str) and raw_name.strip():
                    matched_name_length = len(raw_name.strip())
    except OSError:
        return None, None
    if matched_name_length is None:
        return False, None
    return True, matched_name_length


def _state_db_candidates(root: Path) -> list[Path]:
    ranked: list[tuple[int, Path]] = []
    try:
        candidates = list(root.glob("state_*.sqlite"))
    except OSError:
        return []
    for path in candidates:
        if not path.is_file():
            continue
        match = _STATE_DB_RE.match(path.name)
        if match:
            ranked.append((int(match.group(1)), path.resolve()))
    ranked.sort(key=lambda item: item[0], reverse=True)
    return [path for _, path in ranked[:MAX_STATE_DB_CANDIDATES]]


def _read_state_name(
    root: Path,
    thread_id: str,
) -> tuple[bool | None, str | None, str | None]:
    for db_path in _state_db_candidates(root):
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect_read_only(db_path)
            tables = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table'"
                )
            }
            if "threads" not in tables:
                continue
            columns = {
                str(row[1])
                for row in connection.execute('PRAGMA table_info("threads")')
            }
            id_column = next(
                (name for name in ("id", "thread_id", "session_id") if name in columns),
                None,
            )
            if id_column is None:
                continue
            name_column = "name" if "name" in columns else None
            history_column = "history_mode" if "history_mode" in columns else None
            if name_column is None and history_column is None:
                continue
            expressions = [
                _quote_identifier(name_column) if name_column else "NULL",
                _quote_identifier(history_column) if history_column else "NULL",
            ]
            sql = (
                "SELECT " + ", ".join(expressions)
                + f" FROM \"threads\" WHERE {_quote_identifier(id_column)} = ? LIMIT 1"
            )
            row = connection.execute(sql, (thread_id,)).fetchone()
            if row is None:
                continue
            name_present = bool(isinstance(row[0], str) and row[0].strip()) if name_column else None
            history_mode = str(row[1]) if row[1] not in (None, "") else None
            return name_present, history_mode, str(db_path)
        except sqlite3.DatabaseError:
            continue
        finally:
            if connection is not None:
                connection.close()
    return None, None, None


def inspect_migration_consistency(
    path: str | Path,
    parsed: ParseResult,
) -> MigrationConsistencyReport:
    """Read-only checks for field-reported rollout-migration presentation gaps.

    These checks diagnose derived metadata/projection inconsistencies only. They
    never rewrite SessionMeta, session_index.jsonl, SQLite state, or the rollout.
    """

    source = Path(path).expanduser().resolve()
    report = MigrationConsistencyReport(valid_record_count=parsed.valid_record_count)
    report.thread_id = _thread_id(parsed, source)
    head, head_ordinal = _head_session_meta(source)
    report.head_ordinal = head_ordinal

    boundary = head.get("subagent_history_start_ordinal")
    if isinstance(boundary, int) and not isinstance(boundary, bool) and boundary >= 0:
        report.subagent_history_start_ordinal = boundary
        if (
            parsed.ordinal_mode == "paginated"
            and not parsed.ordinal_tracking_overflow
            and head_ordinal == 0
            and parsed.valid_record_count > 1
            and boundary == parsed.valid_record_count
        ):
            report.subagent_boundary_suspect = True
            report.boundary_reason = (
                "subagent history boundary equals the end-of-file ordinal in a zero-based paginated rollout; "
                "raw history may exist while derived thread presentation is empty"
            )
            report.findings.append("SUBAGENT_HISTORY_BOUNDARY_SUSPECT")

    root = _codex_home(source)
    if root is not None and report.thread_id:
        index_present, index_length = _read_index_name(root, report.thread_id)
        sqlite_present, history_mode, state_db = _read_state_name(root, report.thread_id)
        report.session_index_name_present = index_present
        report.session_index_name_length = index_length
        report.sqlite_name_present = sqlite_present
        report.sqlite_history_mode = history_mode
        report.state_db = state_db
        if (
            index_present is True
            and sqlite_present is False
            and isinstance(history_mode, str)
            and history_mode.lower() == "paginated"
        ):
            report.name_metadata_diverged = True
            report.name_reason = (
                "session_index has a non-empty legacy thread name while paginated SQLite metadata has no name"
            )
            report.findings.append("THREAD_NAME_METADATA_DIVERGED")

    if report.findings:
        report.status = "suspect"
    elif report.subagent_history_start_ordinal is not None or report.session_index_name_present is not None:
        report.status = "checked"
    return report


__all__ = ["MigrationConsistencyReport", "inspect_migration_consistency"]
