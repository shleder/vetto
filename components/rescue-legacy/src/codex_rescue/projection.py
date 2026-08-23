from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .alpha5 import (
    MAX_PROJECTION_RECORD_BYTES,
    ProjectionReport,
    inspect_projection_parity as _inspect_projection_parity,
)
from .transcript import ParseResult


def _stat_signature(path: Path) -> tuple[int, int]:
    stat = path.stat()
    return int(stat.st_size), int(stat.st_mtime_ns)


def _last_record_ordinal(path: Path) -> tuple[int | None, str | None]:
    """Read only the bounded final physical JSONL record and return its ordinal."""

    size = path.stat().st_size
    if size <= 0:
        return None, "canonical rollout is empty at exact projection boundary"
    window = min(size, MAX_PROJECTION_RECORD_BYTES + 2)
    with path.open("rb") as stream:
        stream.seek(size - window)
        data = stream.read(window)
    stripped = data.rstrip(b"\r\n")
    if not stripped:
        return None, "canonical rollout has no final JSON record"
    newline = stripped.rfind(b"\n")
    if newline < 0:
        if window < size:
            return None, "final canonical record exceeds bounded projection inspection limit"
        line = stripped
    else:
        line = stripped[newline + 1 :]
    if len(line) > MAX_PROJECTION_RECORD_BYTES:
        return None, "final canonical record exceeds bounded projection inspection limit"
    try:
        record: Any = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None, "final canonical record cannot be parsed for ordinal parity"
    if not isinstance(record, dict):
        return None, "final canonical record is not an object"
    ordinal = record.get("ordinal")
    if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 0:
        return None, "final canonical record has no usable paginated ordinal"
    return ordinal, None


def _validate_exact_eof_ordinal(path: str | Path, report: ProjectionReport) -> ProjectionReport:
    if report.status != "exact" or report.next_rollout_ordinal is None:
        return report
    source = Path(path).expanduser().resolve()
    before = _stat_signature(source)
    final_ordinal, error = _last_record_ordinal(source)
    after = _stat_signature(source)
    if before != after:
        report.status = "active_write"
        report.reason = "canonical rollout changed while exact projection boundary was verified"
        report.confidence = "unknown"
        return report
    report.boundary_ordinal = final_ordinal
    if error is not None or final_ordinal is None:
        report.status = "unknown"
        report.reason = error or "final canonical ordinal could not be established"
        report.confidence = "unknown"
        return report
    expected_next = final_ordinal + 1
    if report.next_rollout_ordinal != expected_next:
        report.status = "unknown"
        report.reason = (
            "projection byte cursor is at canonical EOF but next ordinal disagrees with "
            f"the final canonical ordinal (expected {expected_next})"
        )
        report.confidence = "unknown"
        return report
    report.reason = "projection byte and ordinal cursors exactly match canonical rollout boundary"
    report.confidence = "strong"
    return report


def inspect_projection_parity(path: str | Path, parsed: ParseResult) -> ProjectionReport:
    """Apply field-supported Alpha5 projection classifications.

    The base inspector establishes stable byte-boundary evidence read-only.
    Exact EOF parity additionally requires the persisted next ordinal to match
    the final canonical ordinal + 1; byte equality alone is not sufficient.
    Codex 0.146.1 field evidence also shows a durable off-by-one wedge where
    the DB says it expects ordinal N while the canonical record exactly at the
    stored byte cursor is N+1.  That narrow stable shape is strong wedge
    evidence rather than a generic unknown mismatch.
    """

    report = _validate_exact_eof_ordinal(path, _inspect_projection_parity(path, parsed))
    if (
        report.status == "unknown"
        and report.next_rollout_ordinal is not None
        and report.boundary_ordinal == report.next_rollout_ordinal + 1
        and report.reason == "canonical suffix skips ahead of the persisted next ordinal"
    ):
        report.status = "wedged"
        report.reason = (
            "stable projection cursor is off by one: canonical record at the persisted "
            "byte boundary is next_rollout_ordinal + 1"
        )
        report.confidence = "strong"
    return report


__all__ = ["inspect_projection_parity"]
