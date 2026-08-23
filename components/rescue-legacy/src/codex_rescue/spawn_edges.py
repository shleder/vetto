from __future__ import annotations

import os
import sqlite3
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .alpha5 import _connect_read_only
from .thread_store import _db_candidates, infer_codex_home

SPAWN_EDGE_OPEN = "OPEN"
SPAWN_EDGE_CLOSED = "CLOSED"
SPAWN_EDGE_UNKNOWN = "UNKNOWN"
SPAWN_EDGE_UNRECORDED = "UNRECORDED"


@dataclass(frozen=True)
class SpawnEdgeEvidence:
    status: str
    parent_thread_id: str | None
    child_thread_id: str
    db_path: str | None = None
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _has_exact_schema(connection: sqlite3.Connection) -> bool:
    rows = list(connection.execute('PRAGMA table_info("thread_spawn_edges")'))
    expected = [
        (0, "parent_thread_id", "TEXT", 1, None, 0),
        (1, "child_thread_id", "TEXT", 1, None, 1),
        (2, "status", "TEXT", 1, None, 0),
    ]
    normalized = [
        (int(row[0]), str(row[1]), str(row[2]).upper(), int(row[3]), row[4], int(row[5]))
        for row in rows
    ]
    return normalized == expected


def inspect_thread_spawn_edge(
    session_path: str | os.PathLike[str],
    *,
    child_thread_id: str,
    parent_thread_id: str | None = None,
    codex_home: str | os.PathLike[str] | None = None,
) -> SpawnEdgeEvidence:
    """Read current Codex thread_spawn_edges evidence without mutation.

    Only the exact upstream schema is interpreted. Missing/incompatible schema,
    unreadable databases, parent mismatches, and unknown statuses fail closed to
    UNKNOWN. An exact readable table with no child row is UNRECORDED, never
    CLOSED.
    """
    path = Path(session_path)
    root = Path(codex_home).resolve() if codex_home is not None else infer_codex_home(path).resolve()
    dbs = _db_candidates(root)
    if not dbs:
        return SpawnEdgeEvidence(
            SPAWN_EDGE_UNKNOWN,
            parent_thread_id,
            child_thread_id,
            reason="no Codex state database was discovered",
        )

    saw_read_error = False
    saw_table = False
    saw_incompatible = False
    for db_path in dbs:
        connection: sqlite3.Connection | None = None
        try:
            connection = _connect_read_only(db_path)
            tables = {
                str(row[0])
                for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")
            }
            if "thread_spawn_edges" not in tables:
                continue
            saw_table = True
            if not _has_exact_schema(connection):
                saw_incompatible = True
                continue
            row = connection.execute(
                "SELECT parent_thread_id, child_thread_id, status "
                "FROM thread_spawn_edges WHERE child_thread_id=? LIMIT 1",
                (child_thread_id,),
            ).fetchone()
            if row is None:
                return SpawnEdgeEvidence(
                    SPAWN_EDGE_UNRECORDED,
                    parent_thread_id,
                    child_thread_id,
                    str(db_path),
                    "exact thread_spawn_edges schema is present but no child row was recorded",
                )

            stored_parent = str(row[0])
            stored_child = str(row[1])
            raw_status = str(row[2]).casefold()
            if stored_child != child_thread_id:
                return SpawnEdgeEvidence(
                    SPAWN_EDGE_UNKNOWN,
                    stored_parent,
                    child_thread_id,
                    str(db_path),
                    "spawn-edge child identity did not match the requested child",
                )
            if parent_thread_id is not None and stored_parent != parent_thread_id:
                return SpawnEdgeEvidence(
                    SPAWN_EDGE_UNKNOWN,
                    stored_parent,
                    child_thread_id,
                    str(db_path),
                    "spawn-edge parent identity conflicts with the expected parent",
                )
            if raw_status == "open":
                status = SPAWN_EDGE_OPEN
            elif raw_status == "closed":
                status = SPAWN_EDGE_CLOSED
            else:
                return SpawnEdgeEvidence(
                    SPAWN_EDGE_UNKNOWN,
                    stored_parent,
                    child_thread_id,
                    str(db_path),
                    "thread_spawn_edges status is not a recognized current Codex value",
                )
            return SpawnEdgeEvidence(
                status,
                stored_parent,
                child_thread_id,
                str(db_path),
                f"read-only thread_spawn_edges evidence reports {raw_status}",
            )
        except (sqlite3.DatabaseError, OSError):
            saw_read_error = True
        finally:
            if connection is not None:
                connection.close()

    if saw_read_error:
        reason = "thread_spawn_edges could not be inspected read-only"
    elif saw_incompatible:
        reason = "thread_spawn_edges exists but its schema is not the exact recognized Codex schema"
    elif saw_table:
        reason = "thread_spawn_edges exists but could not be interpreted safely"
    else:
        reason = "state database exists but thread_spawn_edges is unavailable"
    return SpawnEdgeEvidence(
        SPAWN_EDGE_UNKNOWN,
        parent_thread_id,
        child_thread_id,
        reason=reason,
    )


__all__ = [
    "SPAWN_EDGE_CLOSED",
    "SPAWN_EDGE_OPEN",
    "SPAWN_EDGE_UNKNOWN",
    "SPAWN_EDGE_UNRECORDED",
    "SpawnEdgeEvidence",
    "inspect_thread_spawn_edge",
]
