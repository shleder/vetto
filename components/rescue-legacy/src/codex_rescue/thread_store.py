from __future__ import annotations

import os
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .alpha5 import _connect_read_only, _quote_identifier
from .windows_paths import compare_windows_paths

WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE = "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE"
THREAD_STORE_PATH_OR_REFERENCE_DIVERGENCE = "THREAD_STORE_PATH_OR_REFERENCE_DIVERGENCE"
ROLLOUT_MISSING = "ROLLOUT_MISSING"
NEVER_PERSISTED_TEMP_CHILD = "NEVER_PERSISTED_TEMP_CHILD"
INDEX_DIVERGENCE = "INDEX_DIVERGENCE"


@dataclass(frozen=True)
class ThreadStoreReport:
    status: str
    findings: tuple[str, ...] = field(default_factory=tuple)
    db_path: str | None = None
    stored_rollout_path: str | None = None
    discovered_rollout_path: str | None = None
    path_relation: str = "UNKNOWN"
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = list(self.findings)
        return data


def classify_rollout_presence(
    *,
    rollout_exists: bool | None,
    db_row_present: bool | None,
    known_never_persisted_temp_child: bool = False,
) -> str:
    if known_never_persisted_temp_child and rollout_exists is False and db_row_present is False:
        return NEVER_PERSISTED_TEMP_CHILD
    if rollout_exists is False and db_row_present is True:
        return ROLLOUT_MISSING
    if rollout_exists is True and db_row_present is False:
        return INDEX_DIVERGENCE
    return "UNKNOWN"


def infer_codex_home(session_path: str | os.PathLike[str]) -> Path:
    path = Path(session_path)
    for parent in path.parents:
        if parent.name.casefold() in {"sessions", "archived_sessions"}:
            return parent.parent
    return path.parent


def _db_candidates(root: Path) -> list[Path]:
    preferred = [root / "state_5.sqlite", root / "state.sqlite", root / "state.db"]
    found: list[Path] = []
    seen: set[Path] = set()
    for path in preferred:
        if path.is_file():
            resolved = path.resolve()
            found.append(resolved)
            seen.add(resolved)
    for pattern in ("*.sqlite", "*.sqlite3", "*.db"):
        try:
            candidates = sorted(root.glob(pattern), key=lambda item: str(item))
        except OSError:
            continue
        for path in candidates:
            try:
                if not path.is_file():
                    continue
                resolved = path.resolve()
            except OSError:
                continue
            if resolved not in seen:
                found.append(resolved)
                seen.add(resolved)
    return found[:32]


def _column(columns: set[str], names: tuple[str, ...]) -> str | None:
    return next((name for name in names if name in columns), None)


def inspect_thread_store(
    session_path: str | os.PathLike[str],
    *,
    session_id: str | None = None,
    codex_home: str | os.PathLike[str] | None = None,
) -> ThreadStoreReport:
    path = Path(session_path)
    discovered = str(path.resolve())
    root = Path(codex_home).resolve() if codex_home is not None else infer_codex_home(path).resolve()
    dbs = _db_candidates(root)
    if not dbs:
        return ThreadStoreReport(
            status="UNRECORDED",
            discovered_rollout_path=discovered,
            reason="no compatible Codex thread-store database was discovered",
        )

    saw_compatible_store = False
    saw_read_error = False
    for db_path in dbs:
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect_read_only(db_path)
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            }
            if "threads" not in tables:
                continue
            columns = {str(row[1]) for row in connection.execute('PRAGMA table_info("threads")')}
            id_column = _column(columns, ("id", "thread_id", "session_id"))
            path_column = _column(columns, ("rollout_path", "session_path", "path"))
            if path_column is None:
                continue
            saw_compatible_store = True

            row = None
            if session_id and id_column:
                sql = (
                    f"SELECT {_quote_identifier(path_column)} FROM \"threads\" "
                    f"WHERE {_quote_identifier(id_column)}=? LIMIT 1"
                )
                row = connection.execute(sql, (session_id,)).fetchone()
            if row is None:
                sql = f"SELECT {_quote_identifier(path_column)} FROM \"threads\" LIMIT 100000"
                for candidate in connection.execute(sql):
                    stored = str(candidate[0]).strip() if candidate[0] not in (None, "") else None
                    if not stored:
                        continue
                    comparison = compare_windows_paths(
                        stored,
                        discovered,
                        allow_filesystem_identity=(os.name == "nt"),
                    )
                    if comparison.relation == "EQUIVALENT":
                        row = candidate
                        break

            if row is None:
                continue
            stored = str(row[0]).strip() if row[0] not in (None, "") else None
            if not stored:
                return ThreadStoreReport(
                    status="UNKNOWN",
                    db_path=str(db_path),
                    discovered_rollout_path=discovered,
                    reason="thread row exists but rollout_path is empty or unavailable",
                )
            if stored == discovered:
                return ThreadStoreReport(
                    status="CONSISTENT",
                    db_path=str(db_path),
                    stored_rollout_path=stored,
                    discovered_rollout_path=discovered,
                    path_relation="EQUIVALENT",
                    reason="thread-store rollout_path exactly matches the discovered rollout",
                )

            comparison = compare_windows_paths(
                stored,
                discovered,
                allow_filesystem_identity=(os.name == "nt"),
            )
            if comparison.relation == "EQUIVALENT" and comparison.namespace_divergence:
                return ThreadStoreReport(
                    status="DIVERGED",
                    findings=(WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE,),
                    db_path=str(db_path),
                    stored_rollout_path=stored,
                    discovered_rollout_path=discovered,
                    path_relation="EQUIVALENT",
                    reason="thread-store rollout_path and discovered rollout cross the Windows extended-path namespace boundary",
                )
            if comparison.relation == "EQUIVALENT":
                return ThreadStoreReport(
                    status="CONSISTENT",
                    db_path=str(db_path),
                    stored_rollout_path=stored,
                    discovered_rollout_path=discovered,
                    path_relation="EQUIVALENT",
                    reason="thread-store rollout_path identifies the discovered rollout",
                )
            if comparison.relation == "DIFFERENT":
                return ThreadStoreReport(
                    status="DIVERGED",
                    findings=(THREAD_STORE_PATH_OR_REFERENCE_DIVERGENCE,),
                    db_path=str(db_path),
                    stored_rollout_path=stored,
                    discovered_rollout_path=discovered,
                    path_relation="DIFFERENT",
                    reason="thread-store rollout_path identifies a different location; exact cause is not proven",
                )
            return ThreadStoreReport(
                status="UNKNOWN",
                db_path=str(db_path),
                stored_rollout_path=stored,
                discovered_rollout_path=discovered,
                path_relation="UNKNOWN",
                reason="rollout path identity could not be established safely",
            )
        except (sqlite3.DatabaseError, OSError):
            saw_read_error = True
            continue
        finally:
            if connection is not None:
                connection.close()

    if saw_read_error:
        return ThreadStoreReport(
            status="UNKNOWN",
            discovered_rollout_path=discovered,
            reason="thread-store database could not be inspected read-only",
        )
    if saw_compatible_store:
        return ThreadStoreReport(
            status="UNRECORDED",
            discovered_rollout_path=discovered,
            reason="no matching thread row was found; absence is not treated as rollout deletion",
        )
    return ThreadStoreReport(
        status="UNKNOWN",
        discovered_rollout_path=discovered,
        reason="database exists but no compatible threads.rollout_path schema was found",
    )


__all__ = [
    "INDEX_DIVERGENCE",
    "NEVER_PERSISTED_TEMP_CHILD",
    "ROLLOUT_MISSING",
    "THREAD_STORE_PATH_OR_REFERENCE_DIVERGENCE",
    "ThreadStoreReport",
    "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE",
    "classify_rollout_presence",
    "infer_codex_home",
    "inspect_thread_store",
]
