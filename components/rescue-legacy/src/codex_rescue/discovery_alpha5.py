from __future__ import annotations

import ntpath
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .alpha5 import _connect_read_only, _quote_identifier
from .discovery import (
    DEFAULT_HEAD_BYTES,
    DEFAULT_LIMIT,
    DEFAULT_PROMPT_LIMIT,
    DEFAULT_TAIL_BYTES,
    SessionSummary,
    _rollout_paths,
    codex_home_path,
    lightweight_scan,
)
from .thread_identity import parse_rollout_filename
from .thread_store import WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE
from .windows_paths import compare_windows_paths, path_identity as _path_identity


MAX_DB_INVENTORY_ROWS = 100_000
MAX_DB_CANDIDATES = 32
_WINDOWS_ABSOLUTE_RE = re.compile(
    r"(?i)^(?:[a-z]:[\\/]|(?:\\\\\?\\|//\?/)(?:[a-z]:[\\/]|UNC[\\/])|(?:\\\\|//)(?![?.][\\/]))"
)


@dataclass(frozen=True)
class Alpha5SessionSummary(SessionSummary):
    indexed: bool | None = None
    exists: bool = True
    inventory_mismatch: str | None = None
    inventory_db: str | None = None
    thread_store_status: str = "UNKNOWN"
    finding_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data = super().to_dict()
        data.update(
            {
                "indexed": self.indexed,
                "exists": self.exists,
                "inventory_mismatch": self.inventory_mismatch,
                "inventory_db": self.inventory_db,
                "thread_store_status": self.thread_store_status,
                "finding_ids": list(self.finding_ids),
            }
        )
        return data


@dataclass(frozen=True)
class _InventoryRow:
    thread_id: str | None
    rollout_path: str | None
    cwd: str | None
    archived: bool
    updated_at: float
    db_path: str


@dataclass
class _Candidate:
    path: Path | None
    raw_path: str | None
    thread_id: str | None
    mtime: float
    size: int
    archived: bool
    inventory: _InventoryRow | None = None


def _thread_id_from_path(path: Path) -> str | None:
    parsed = parse_rollout_filename(path)
    return parsed.thread_id if parsed else None


def path_identity(value: str | os.PathLike[str]) -> str:
    return _path_identity(value)


def _timestamp(value: Any) -> float:
    if value in (None, ""):
        return 0.0
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        number = float(value)
        if number > 10_000_000_000:
            number /= 1000.0
        return max(0.0, number)
    text = str(value).strip()
    try:
        number = float(text)
    except ValueError:
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.timestamp()
        except ValueError:
            return 0.0
    if number > 10_000_000_000:
        number /= 1000.0
    return max(0.0, number)


def _sqlite_candidates(root: Path) -> list[Path]:
    values: set[Path] = set()
    for pattern in ("*.sqlite", "*.sqlite3", "*.db"):
        try:
            for path in root.glob(pattern):
                if path.is_file():
                    values.add(path.resolve())
        except OSError:
            continue
    return sorted(values, key=lambda path: str(path))[:MAX_DB_CANDIDATES]


def _column(columns: set[str], names: tuple[str, ...]) -> str | None:
    return next((name for name in names if name in columns), None)


def _read_inventory(root: Path) -> tuple[list[_InventoryRow], bool, bool]:
    rows: list[_InventoryRow] = []
    inventory_available = False
    saw_database = False
    read_error = False
    for db_path in _sqlite_candidates(root):
        saw_database = True
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect_read_only(db_path)
            table_names = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            }
            if "threads" not in table_names:
                continue
            columns = {str(row[1]) for row in connection.execute('PRAGMA table_info("threads")')}
            id_column = _column(columns, ("id", "thread_id", "session_id"))
            path_column = _column(columns, ("rollout_path", "session_path", "path"))
            if id_column is None and path_column is None:
                continue
            inventory_available = True
            cwd_column = _column(columns, ("cwd", "workspace", "worktree"))
            archived_column = _column(columns, ("archived", "is_archived"))
            updated_column = _column(columns, ("updated_at", "modified_at", "created_at"))
            selected = [id_column, path_column, cwd_column, archived_column, updated_column]
            expressions = [_quote_identifier(name) if name else "NULL" for name in selected]
            order = f" ORDER BY {_quote_identifier(updated_column)} DESC" if updated_column else ""
            sql = "SELECT " + ", ".join(expressions) + ' FROM "threads"' + order + " LIMIT ?"
            for row in connection.execute(sql, (MAX_DB_INVENTORY_ROWS,)):
                thread_id = str(row[0]).strip() if row[0] not in (None, "") else None
                rollout_path = str(row[1]).strip() if row[1] not in (None, "") else None
                cwd = str(row[2]).strip() if row[2] not in (None, "") else None
                archived = bool(row[3]) if row[3] is not None else False
                rows.append(
                    _InventoryRow(
                        thread_id=thread_id,
                        rollout_path=rollout_path,
                        cwd=cwd,
                        archived=archived,
                        updated_at=_timestamp(row[4]),
                        db_path=str(db_path),
                    )
                )
        except (sqlite3.DatabaseError, OSError):
            read_error = True
            continue
        finally:
            if connection is not None:
                connection.close()
    inventory_unknown = saw_database and read_error and not inventory_available
    return rows, inventory_available, inventory_unknown


def _candidate_local_path(root: Path, raw: str | None) -> Path | None:
    if not raw:
        return None
    if _WINDOWS_ABSOLUTE_RE.match(raw):
        return Path(raw)
    expanded = Path(os.path.expandvars(os.path.expanduser(raw)))
    if not expanded.is_absolute():
        expanded = root / expanded
    try:
        return expanded.resolve()
    except OSError:
        return expanded


def _can_prove_local_absence(raw: str | None) -> bool:
    if not raw:
        return False
    if _WINDOWS_ABSOLUTE_RE.match(raw):
        return os.name == "nt"
    return True


def _repo_name(cwd: str | None) -> str | None:
    if not cwd:
        return None
    return ntpath.basename(cwd.rstrip("\\/")) or None


def _wrap(
    summary: SessionSummary,
    *,
    indexed: bool | None,
    mismatch: str | None,
    inventory: _InventoryRow | None,
    inventory_unknown: bool = False,
) -> Alpha5SessionSummary:
    status = summary.status
    reason = summary.reason
    findings: tuple[str, ...] = ()
    thread_store_status = "UNKNOWN"
    if summary.size == 0:
        status = "suspicious"
        reason = "empty rollout; may be actively materializing"
    if inventory is not None:
        thread_store_status = "CONSISTENT"
        if inventory.rollout_path:
            comparison = compare_windows_paths(inventory.rollout_path, str(summary.path))
            if comparison.relation == "EQUIVALENT" and comparison.namespace_divergence:
                status = "suspicious" if status == "healthy" else status
                reason = "source rollout is readable but thread-store path crosses the Windows extended-path namespace boundary"
                mismatch = "windows_rollout_path_identity_divergence"
                thread_store_status = "DIVERGED"
                findings = (WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE,)
            elif comparison.relation == "DIFFERENT" and path_identity(inventory.rollout_path) != path_identity(summary.path):
                thread_store_status = "DIVERGED"
            elif comparison.relation == "UNKNOWN" and path_identity(inventory.rollout_path) != path_identity(summary.path):
                thread_store_status = "UNKNOWN"
    elif inventory_unknown:
        thread_store_status = "UNKNOWN"
        if status == "healthy":
            status = "suspicious"
            reason = "source rollout is readable but thread-store inventory could not be inspected read-only"
        mismatch = mismatch or "inventory_unreadable"
    elif indexed is False:
        thread_store_status = "UNRECORDED"
    return Alpha5SessionSummary(
        path=summary.path,
        session_id=summary.session_id,
        cwd=summary.cwd or (inventory.cwd if inventory else None),
        repo=summary.repo or _repo_name(inventory.cwd if inventory else None),
        first_prompt=summary.first_prompt,
        last_prompt=summary.last_prompt,
        status=status,
        reason=reason,
        mtime=max(summary.mtime, inventory.updated_at if inventory else 0.0),
        size=summary.size,
        archived=summary.archived or bool(inventory and inventory.archived),
        thread_identity=summary.thread_identity,
        indexed=indexed,
        exists=True,
        inventory_mismatch=mismatch,
        inventory_db=inventory.db_path if inventory else None,
        thread_store_status=thread_store_status,
        finding_ids=findings,
    )


def discover_sessions(
    codex_home: str | os.PathLike[str] | None = None,
    *,
    limit: int | None = DEFAULT_LIMIT,
    include_archived: bool = True,
    head_bytes: int = DEFAULT_HEAD_BYTES,
    tail_bytes: int = DEFAULT_TAIL_BYTES,
    prompt_limit: int = DEFAULT_PROMPT_LIMIT,
) -> list[Alpha5SessionSummary]:
    root = codex_home_path(codex_home)
    inventory_rows, inventory_available, inventory_unknown = _read_inventory(root)
    candidates: list[_Candidate] = []
    by_id: dict[str, _Candidate] = {}
    by_path: dict[str, _Candidate] = {}

    for path in _rollout_paths(root, include_archived):
        try:
            stat = path.stat()
        except OSError:
            continue
        thread_id = _thread_id_from_path(path)
        candidate = _Candidate(
            path=path,
            raw_path=str(path),
            thread_id=thread_id,
            mtime=stat.st_mtime,
            size=stat.st_size,
            archived="archived_sessions" in {part.lower() for part in path.parts},
        )
        candidates.append(candidate)
        if thread_id:
            by_id.setdefault(thread_id, candidate)
        by_path.setdefault(path_identity(path), candidate)

    for inventory in inventory_rows:
        local_path = _candidate_local_path(root, inventory.rollout_path)
        identity = path_identity(inventory.rollout_path) if inventory.rollout_path else None
        candidate = by_id.get(inventory.thread_id or "") if inventory.thread_id else None
        if candidate is None and identity is not None:
            candidate = by_path.get(identity)
        if candidate is not None:
            candidate.inventory = inventory
            candidate.mtime = max(candidate.mtime, inventory.updated_at)
            candidate.archived = candidate.archived or inventory.archived
            continue
        if not include_archived and inventory.archived:
            continue
        missing = _Candidate(
            path=local_path,
            raw_path=inventory.rollout_path,
            thread_id=inventory.thread_id,
            mtime=inventory.updated_at,
            size=0,
            archived=inventory.archived,
            inventory=inventory,
        )
        candidates.append(missing)
        if inventory.thread_id:
            by_id[inventory.thread_id] = missing
        if identity:
            by_path[identity] = missing

    candidates.sort(
        key=lambda item: (item.mtime, item.thread_id or "", path_identity(item.raw_path or item.path or "")),
        reverse=True,
    )
    max_results = None if limit is None else max(0, int(limit))
    if max_results == 0:
        return []

    results: list[Alpha5SessionSummary] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for candidate in candidates:
        identity = path_identity(candidate.raw_path or candidate.path or "")
        if candidate.thread_id and candidate.thread_id in seen_ids:
            continue
        if identity and identity in seen_paths:
            continue
        if candidate.thread_id:
            seen_ids.add(candidate.thread_id)
        if identity:
            seen_paths.add(identity)

        path = candidate.path
        exists = False
        if path is not None and _can_prove_local_absence(candidate.raw_path or str(path)):
            try:
                exists = path.is_file()
            except OSError:
                exists = False
        if exists and path is not None:
            try:
                summary = lightweight_scan(
                    path,
                    head_bytes=head_bytes,
                    tail_bytes=tail_bytes,
                    prompt_limit=prompt_limit,
                    archived=candidate.archived,
                )
            except (OSError, ValueError):
                results.append(
                    Alpha5SessionSummary(
                        path=path,
                        session_id=candidate.thread_id,
                        cwd=candidate.inventory.cwd if candidate.inventory else None,
                        repo=_repo_name(candidate.inventory.cwd if candidate.inventory else None),
                        first_prompt=None,
                        last_prompt=None,
                        status="suspicious",
                        reason="rollout changed or became inaccessible during bounded discovery",
                        mtime=candidate.mtime,
                        size=candidate.size,
                        archived=candidate.archived,
                        indexed=True if candidate.inventory else (False if inventory_available else None),
                        exists=False,
                        inventory_mismatch="rollout_inaccessible" if candidate.inventory else None,
                        inventory_db=candidate.inventory.db_path if candidate.inventory else None,
                        thread_store_status="UNKNOWN",
                    )
                )
                if max_results is not None and len(results) >= max_results:
                    break
                continue
            indexed = True if candidate.inventory else (False if inventory_available else None)
            mismatch = "rollout_not_indexed" if inventory_available and candidate.inventory is None else None
            results.append(
                _wrap(
                    summary,
                    indexed=indexed,
                    mismatch=mismatch,
                    inventory=candidate.inventory,
                    inventory_unknown=inventory_unknown,
                )
            )
            if max_results is not None and len(results) >= max_results:
                break
            continue

        if candidate.inventory is None:
            continue
        missing_path = path or Path(candidate.raw_path or f"indexed-thread-{candidate.thread_id or 'unknown'}")
        absence_proven = _can_prove_local_absence(candidate.raw_path)
        results.append(
            Alpha5SessionSummary(
                path=missing_path,
                session_id=candidate.thread_id,
                cwd=candidate.inventory.cwd,
                repo=_repo_name(candidate.inventory.cwd),
                first_prompt=None,
                last_prompt=None,
                status="suspicious",
                reason=(
                    "indexed rollout missing from filesystem"
                    if absence_proven
                    else "indexed rollout path uses a foreign or uninspectable path namespace; presence is unknown"
                ),
                mtime=candidate.mtime,
                size=0,
                archived=candidate.archived,
                indexed=True,
                exists=False,
                inventory_mismatch="indexed_rollout_missing" if absence_proven else "rollout_presence_unknown",
                inventory_db=candidate.inventory.db_path,
                thread_store_status="DIVERGED" if absence_proven else "UNKNOWN",
                finding_ids=("ROLLOUT_MISSING",) if absence_proven else (),
            )
        )
        if max_results is not None and len(results) >= max_results:
            break
    return results


def resolve_latest(
    codex_home: str | os.PathLike[str] | None = None,
    *,
    include_archived: bool = True,
) -> Path | None:
    root = codex_home_path(codex_home)
    candidates: list[tuple[float, str, Path]] = []
    for path in _rollout_paths(root, include_archived):
        try:
            candidates.append((path.stat().st_mtime, path_identity(path), path))
        except OSError:
            continue
    if not candidates:
        return None
    return max(candidates, key=lambda item: (item[0], item[1]))[2]


__all__ = ["Alpha5SessionSummary", "discover_sessions", "path_identity", "resolve_latest"]
