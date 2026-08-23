from __future__ import annotations

import json
import re
import sqlite3
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .transcript import MAX_RECORD_BYTES, ParseResult, _read_line_bounded


MAX_ALPHA5_FINDINGS = 128
MAX_WRITER_TRANSITIONS = 64
MAX_SQLITE_CANDIDATES = 32
MAX_PROJECTION_RECORD_BYTES = 1024 * 1024

# Current upstream codex protocol ResponseItem::id_prefix() values.  Persisted
# legacy IDs without a prefix remain readable upstream and are deliberately not
# rejected here.  Alpha5 only treats a *prefixed but type-incompatible* ID as
# strong evidence, which is the replay failure class seen in field reports.
RESPONSE_ITEM_ID_PREFIXES: dict[str, str] = {
    "additional_tools": "at",
    "message": "msg",
    "agent_message": "amsg",
    "reasoning": "rs",
    "local_shell_call": "lsh",
    "function_call": "fc",
    "tool_search_call": "tsc",
    "function_call_output": "fco",
    "custom_tool_call": "ctc",
    "custom_tool_call_output": "ctco",
    "tool_search_output": "tso",
    "web_search_call": "ws",
    "image_generation_call": "ig",
    "compaction": "cmp",
    "context_compaction": "cmp",
}

_START_LIFECYCLE_TYPES = {
    "task_started",
    "turn_started",
    "agent_started",
    "agent_spawned",
    "thread_started",
}
_TERMINAL_LIFECYCLE_TYPES = {
    "task_complete",
    "task_completed",
    "turn_complete",
    "turn_completed",
    "turn_aborted",
    "turn_failed",
    "turn_interrupted",
    "agent_complete",
    "agent_completed",
    "agent_closed",
    "thread_closed",
}
_WRITER_KEYS = ("writer_id", "app_server_id", "process_id", "writer_pid")
_UUID_RE = re.compile(
    r"(?i)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
)


@dataclass
class Alpha5RolloutDiagnostics:
    largest_record_bytes: int = 0
    scanned_record_count: int = 0
    bounded_record_overflow_count: int = 0
    inline_media_indicator_records: int = 0
    compaction_record_count: int = 0
    typed_id_violation_count: int = 0
    typed_id_violations: list[dict[str, Any]] = field(default_factory=list)
    legacy_unprefixed_id_count: int = 0
    opaque_content_formats: Counter[str] = field(default_factory=Counter)
    malformed_opaque_field_count: int = 0
    lifecycle_start_markers: int = 0
    lifecycle_terminal_markers: int = 0
    lifecycle_statement: str = "No persisted lifecycle marker observed"
    writer_transition_count: int = 0
    interleaved_writer_evidence: list[dict[str, Any]] = field(default_factory=list)
    source_changed_during_scan: bool = False
    empty_rollout: bool = False
    header_only_rollout: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "largest_record_bytes": self.largest_record_bytes,
            "scanned_record_count": self.scanned_record_count,
            "bounded_record_overflow_count": self.bounded_record_overflow_count,
            "inline_media_indicator_records": self.inline_media_indicator_records,
            "compaction_record_count": self.compaction_record_count,
            "typed_id_violation_count": self.typed_id_violation_count,
            "typed_id_violations": self.typed_id_violations,
            "legacy_unprefixed_id_count": self.legacy_unprefixed_id_count,
            "opaque_content_formats": dict(self.opaque_content_formats),
            "malformed_opaque_field_count": self.malformed_opaque_field_count,
            "lifecycle_start_markers": self.lifecycle_start_markers,
            "lifecycle_terminal_markers": self.lifecycle_terminal_markers,
            "lifecycle_statement": self.lifecycle_statement,
            "writer_transition_count": self.writer_transition_count,
            "interleaved_writer_evidence": self.interleaved_writer_evidence,
            "source_changed_during_scan": self.source_changed_during_scan,
            "empty_rollout": self.empty_rollout,
            "header_only_rollout": self.header_only_rollout,
        }


@dataclass
class ProjectionReport:
    status: str
    reason: str
    thread_id: str | None = None
    db_path: str | None = None
    table: str | None = None
    next_rollout_byte_offset: int | None = None
    next_rollout_ordinal: int | None = None
    canonical_size: int | None = None
    boundary_ordinal: int | None = None
    next_boundary_ordinal: int | None = None
    confidence: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "thread_id": self.thread_id,
            "db_path": self.db_path,
            "table": self.table,
            "next_rollout_byte_offset": self.next_rollout_byte_offset,
            "next_rollout_ordinal": self.next_rollout_ordinal,
            "canonical_size": self.canonical_size,
            "boundary_ordinal": self.boundary_ordinal,
            "next_boundary_ordinal": self.next_boundary_ordinal,
            "confidence": self.confidence,
        }


def _stat_signature(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return int(stat.st_size), int(stat.st_mtime_ns)


def _record_payload(record: dict[str, Any]) -> dict[str, Any]:
    payload = record.get("payload")
    return payload if isinstance(payload, dict) else {}


def _writer_identity(record: dict[str, Any], payload: dict[str, Any]) -> str | None:
    for key in _WRITER_KEYS:
        value = payload.get(key, record.get(key))
        if value not in (None, ""):
            return f"{key}:{value}"
    return None


def _classify_opaque(value: Any) -> str:
    if value is None:
        return "explicit_null"
    if not isinstance(value, str):
        return "malformed_non_string"
    if value.startswith("ocx1:"):
        # Field evidence identifies this as a foreign/proxy marker, not a
        # native OpenAI envelope.  Do not attempt to decode it.
        return "foreign_ocx1"
    if value.startswith("gAAAA"):
        # Historical native/relay persisted reasoning observed in OpenAI Codex
        # failures.  This is format recognition only, never a decryption or an
        # account/key diagnosis.
        return "legacy_fernet_like"
    if len(value) >= 16:
        return "unknown_opaque"
    return "malformed_short_string"


def _check_typed_id(
    payload: dict[str, Any],
    offset: int,
    result: Alpha5RolloutDiagnostics,
) -> None:
    kind = payload.get("type")
    expected = RESPONSE_ITEM_ID_PREFIXES.get(str(kind)) if isinstance(kind, str) else None
    if expected is None or "id" not in payload or payload.get("id") is None:
        return
    raw_id = payload.get("id")
    if not isinstance(raw_id, str) or not raw_id:
        result.typed_id_violation_count += 1
        if len(result.typed_id_violations) < MAX_ALPHA5_FINDINGS:
            result.typed_id_violations.append(
                {
                    "offset": offset,
                    "payload_type": kind,
                    "expected_prefix": expected,
                    "observed_prefix": None,
                    "reason": "persisted response item id is not a non-empty string",
                }
            )
        return
    if "_" not in raw_id:
        # Upstream deliberately deserializes old unprefixed IDs for legacy
        # compatibility and clears them before replay.  Do not poison history.
        result.legacy_unprefixed_id_count += 1
        return
    prefix, suffix = raw_id.split("_", 1)
    if prefix == expected and suffix:
        return
    result.typed_id_violation_count += 1
    if len(result.typed_id_violations) < MAX_ALPHA5_FINDINGS:
        result.typed_id_violations.append(
            {
                "offset": offset,
                "payload_type": kind,
                "expected_prefix": expected,
                "observed_prefix": prefix or None,
                "reason": "persisted response item id prefix does not match its concrete type",
            }
        )


def scan_rollout_alpha5(
    path: str | Path,
    *,
    max_record_bytes: int = MAX_RECORD_BYTES,
) -> Alpha5RolloutDiagnostics:
    """Perform an additional linear, bounded Alpha5 scan without retaining payloads.

    This pass intentionally keeps only aggregate counters and small structural
    findings.  It never base64-decodes media or retains encrypted/opaque text.
    """

    source = Path(path).expanduser().resolve()
    before = _stat_signature(source)
    result = Alpha5RolloutDiagnostics(empty_rollout=before[0] == 0)
    offset = 0
    first_outer_type: str | None = None
    writer_transitions: list[tuple[str, int]] = []
    last_writer: str | None = None

    with source.open("rb") as stream:
        while True:
            start = offset
            line, oversized, consumed = _read_line_bounded(
                stream, max_bytes=max_record_bytes, digest=None
            )
            if not line:
                break
            offset += consumed
            result.largest_record_bytes = max(result.largest_record_bytes, consumed)
            if oversized:
                result.bounded_record_overflow_count += 1
                if b"data:image" in line or b";base64," in line:
                    result.inline_media_indicator_records += 1
                # The rest of this physical line was drained in bounded chunks.
                # Continue with later records rather than allocating the giant
                # record just to produce aggregate diagnostics.
                continue
            if b"data:image" in line or b";base64," in line:
                result.inline_media_indicator_records += 1
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                continue
            if not isinstance(record, dict):
                continue
            result.scanned_record_count += 1
            outer_type = str(record.get("type") or "unknown")
            if first_outer_type is None:
                first_outer_type = outer_type
            payload = _record_payload(record)
            kind = str(payload.get("type") or "")

            if outer_type == "compacted" or kind in {"context_compacted", "compaction"}:
                result.compaction_record_count += 1
            if outer_type == "response_item":
                _check_typed_id(payload, start, result)

            if "encrypted_content" in payload:
                opaque_kind = _classify_opaque(payload.get("encrypted_content"))
                result.opaque_content_formats[opaque_kind] += 1
                if opaque_kind.startswith("malformed_"):
                    result.malformed_opaque_field_count += 1

            lifecycle_kind = kind.lower()
            if lifecycle_kind in _START_LIFECYCLE_TYPES:
                result.lifecycle_start_markers += 1
            if lifecycle_kind in _TERMINAL_LIFECYCLE_TYPES:
                result.lifecycle_terminal_markers += 1
            status = payload.get("status")
            if isinstance(status, str) and status.lower() in {
                "completed", "complete", "closed", "failed", "cancelled", "canceled", "interrupted"
            }:
                result.lifecycle_terminal_markers += 1

            writer = _writer_identity(record, payload)
            if writer is not None and writer != last_writer:
                result.writer_transition_count += int(last_writer is not None)
                if len(writer_transitions) < MAX_WRITER_TRANSITIONS:
                    writer_transitions.append((writer, start))
                last_writer = writer

    if result.lifecycle_terminal_markers:
        result.lifecycle_statement = "Persisted terminal lifecycle marker observed; live state is unavailable"
    elif result.lifecycle_start_markers:
        result.lifecycle_statement = "No terminal marker observed in persisted history; live state is unavailable"

    # A-B-A is explicit persisted interleaving between writer identities.  Mere
    # presence of several writers, children, or subagents is not enough.
    for index in range(len(writer_transitions) - 2):
        first, middle, third = writer_transitions[index:index + 3]
        if first[0] == third[0] and first[0] != middle[0]:
            if len(result.interleaved_writer_evidence) < MAX_ALPHA5_FINDINGS:
                result.interleaved_writer_evidence.append(
                    {
                        "first_writer": first[0],
                        "other_writer": middle[0],
                        "first_offset": first[1],
                        "other_offset": middle[1],
                        "return_offset": third[1],
                        "reason": "explicit writer identities interleave A-B-A in one persisted rollout",
                    }
                )

    result.header_only_rollout = (
        result.scanned_record_count == 1
        and first_outer_type == "session_meta"
        and result.bounded_record_overflow_count == 0
    )
    after = _stat_signature(source)
    result.source_changed_during_scan = before != after
    return result


def _thread_id(parsed: ParseResult, source: Path) -> str | None:
    value = parsed.session_metadata.get("session_id") or parsed.session_metadata.get("id")
    if value not in (None, ""):
        return str(value)
    match = _UUID_RE.search(source.name)
    return match.group(1) if match else None


def _codex_home_for_rollout(source: Path) -> Path | None:
    for parent in source.parents:
        if parent.name.lower() in {"sessions", "archived_sessions"}:
            return parent.parent
    return None


def _sqlite_uri(path: Path) -> str:
    encoded = quote(path.resolve().as_posix(), safe="/:")
    return f"file:{encoded}?mode=ro"


def _connect_read_only(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(_sqlite_uri(path), uri=True, timeout=0.1)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA query_only=ON")
    connection.execute("PRAGMA busy_timeout=100")
    return connection


def _quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _projection_shape(connection: sqlite3.Connection, table: str) -> tuple[str, str, str] | None:
    columns = {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({_quote_identifier(table)})")
    }
    id_names = ("thread_id", "session_id")
    offset_names = (
        "next_rollout_byte_offset",
        "next_byte_offset",
        "rollout_byte_offset",
    )
    ordinal_names = ("next_rollout_ordinal", "next_ordinal")
    id_column = next((name for name in id_names if name in columns), None)
    offset_column = next((name for name in offset_names if name in columns), None)
    ordinal_column = next((name for name in ordinal_names if name in columns), None)
    if id_column and offset_column and ordinal_column:
        return id_column, offset_column, ordinal_column
    return None


def _projection_rows(
    codex_home: Path,
    thread_id: str,
) -> tuple[list[tuple[Path, str, int, int]], list[str]]:
    candidates: list[Path] = []
    for pattern in ("*.sqlite", "*.sqlite3", "*.db"):
        try:
            candidates.extend(path for path in codex_home.glob(pattern) if path.is_file())
        except OSError:
            continue
    unique = sorted({path.resolve() for path in candidates}, key=lambda value: str(value))
    unique = unique[:MAX_SQLITE_CANDIDATES]
    rows: list[tuple[Path, str, int, int]] = []
    relevant_errors: list[str] = []
    for db_path in unique:
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect_read_only(db_path)
            tables = [
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name"
                )
            ]
            # Exact current table first, then schema-compatible historical names.
            tables.sort(key=lambda name: (name != "thread_history_projection_state", name))
            for table in tables:
                shape = _projection_shape(connection, table)
                if shape is None:
                    continue
                id_column, offset_column, ordinal_column = shape
                sql = (
                    f"SELECT {_quote_identifier(offset_column)}, {_quote_identifier(ordinal_column)} "
                    f"FROM {_quote_identifier(table)} WHERE {_quote_identifier(id_column)} = ?"
                )
                row = connection.execute(sql, (thread_id,)).fetchone()
                if row is None:
                    continue
                try:
                    next_offset = int(row[0])
                    next_ordinal = int(row[1])
                except (TypeError, ValueError, OverflowError):
                    relevant_errors.append(f"{db_path.name}:{table}: non-integer projection cursor")
                    continue
                if next_offset < 0 or next_ordinal < 0:
                    relevant_errors.append(f"{db_path.name}:{table}: negative projection cursor")
                    continue
                rows.append((db_path, table, next_offset, next_ordinal))
        except sqlite3.DatabaseError as exc:
            # Do not let an unrelated cache/log DB poison diagnosis.  Only
            # state/history-looking files are relevant when malformed.
            lowered = db_path.name.lower()
            if any(token in lowered for token in ("state", "thread", "history")):
                relevant_errors.append(f"{db_path.name}: {type(exc).__name__}")
        finally:
            if connection is not None:
                connection.close()
    return rows, relevant_errors


def _read_boundary_record(stream: Any) -> tuple[dict[str, Any] | None, bool]:
    while True:
        line, oversized, _ = _read_line_bounded(
            stream, max_bytes=MAX_PROJECTION_RECORD_BYTES, digest=None
        )
        if not line:
            return None, False
        if oversized:
            return None, True
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            return None, False
        return (value if isinstance(value, dict) else None), False


def _ordinal(record: dict[str, Any] | None) -> int | None:
    if not isinstance(record, dict):
        return None
    value = record.get("ordinal")
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def inspect_projection_parity(path: str | Path, parsed: ParseResult) -> ProjectionReport:
    """Compare a stable paginated canonical rollout with read-only SQLite projection state."""

    source = Path(path).expanduser().resolve()
    thread_id = _thread_id(parsed, source)
    canonical_size = source.stat().st_size
    if parsed.ordinal_mode != "paginated":
        return ProjectionReport(
            status="not_applicable",
            reason="legacy or non-paginated rollout",
            thread_id=thread_id,
            canonical_size=canonical_size,
            confidence="not_applicable",
        )
    if not thread_id:
        return ProjectionReport(
            status="unknown",
            reason="paginated rollout has no stable thread identity",
            canonical_size=canonical_size,
            confidence="unknown",
        )
    codex_home = _codex_home_for_rollout(source)
    if codex_home is None:
        return ProjectionReport(
            status="not_applicable",
            reason="rollout path is outside a supported Codex session root; projection DB not inferred",
            thread_id=thread_id,
            canonical_size=canonical_size,
            confidence="not_applicable",
        )

    rows, errors = _projection_rows(codex_home, thread_id)
    if not rows:
        if errors:
            return ProjectionReport(
                status="unknown",
                reason="projection database/schema could not be read safely: " + "; ".join(errors[:3]),
                thread_id=thread_id,
                canonical_size=canonical_size,
                confidence="unknown",
            )
        return ProjectionReport(
            status="not_applicable",
            reason="no readable projection row found for this thread",
            thread_id=thread_id,
            canonical_size=canonical_size,
            confidence="not_applicable",
        )

    states = {(row[2], row[3]) for row in rows}
    if len(states) != 1:
        return ProjectionReport(
            status="unknown",
            reason="multiple readable projection stores disagree on the cursor",
            thread_id=thread_id,
            canonical_size=canonical_size,
            confidence="unknown",
        )
    db_path, table, next_offset, next_ordinal = rows[0]
    base = ProjectionReport(
        status="unknown",
        reason="projection parity not established",
        thread_id=thread_id,
        db_path=str(db_path),
        table=table,
        next_rollout_byte_offset=next_offset,
        next_rollout_ordinal=next_ordinal,
        canonical_size=canonical_size,
        confidence="unknown",
    )
    if next_offset > canonical_size:
        base.reason = "projection byte cursor is beyond the canonical rollout"
        return base
    if next_offset == canonical_size:
        base.status = "exact"
        base.reason = "projection cursor exactly matches canonical rollout boundary"
        base.confidence = "strong"
        return base

    before = _stat_signature(source)
    with source.open("rb") as stream:
        if next_offset > 0:
            stream.seek(next_offset - 1)
            if stream.read(1) != b"\n":
                base.reason = "projection byte cursor is not aligned to a canonical record boundary"
                return base
        stream.seek(next_offset)
        first, oversized = _read_boundary_record(stream)
        if oversized:
            base.reason = "projection boundary record exceeds bounded inspection limit"
            return base
        first_ordinal = _ordinal(first)
        base.boundary_ordinal = first_ordinal
        if first_ordinal is None:
            base.reason = "canonical suffix at projection cursor has no usable paginated ordinal"
            return base
        second_ordinal: int | None = None
        if next_ordinal > 0 and first_ordinal == next_ordinal - 1:
            second, second_oversized = _read_boundary_record(stream)
            if not second_oversized:
                second_ordinal = _ordinal(second)
            base.next_boundary_ordinal = second_ordinal
    after = _stat_signature(source)
    if before != after:
        base.status = "active_write"
        base.reason = "canonical rollout changed while projection parity was inspected"
        base.confidence = "unknown"
        return base

    if first_ordinal == next_ordinal:
        base.status = "wedged"
        base.reason = "stable canonical rollout has an unprojected suffix beginning at the expected ordinal"
        base.confidence = "strong"
        return base
    if next_ordinal > 0 and first_ordinal == next_ordinal - 1 and second_ordinal == next_ordinal:
        base.status = "wedged"
        base.reason = "stable canonical suffix begins with one replayed projection-boundary ordinal before the expected ordinal"
        base.confidence = "strong"
        return base
    if first_ordinal < next_ordinal:
        base.reason = "canonical suffix regresses behind the persisted next ordinal"
    else:
        base.reason = "canonical suffix skips ahead of the persisted next ordinal"
    return base


__all__ = [
    "Alpha5RolloutDiagnostics",
    "ProjectionReport",
    "RESPONSE_ITEM_ID_PREFIXES",
    "inspect_projection_parity",
    "scan_rollout_alpha5",
]
