from __future__ import annotations

import hashlib
import os
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from codex_rescue.alpha7.blackbox.recorder import BlackBoxRecorder, EventType, StructuralEvent
from codex_rescue.alpha7.invariants import (
    InvariantCheckResult,
    InvariantEngine,
    InvariantId,
    InvariantStatus,
)
from codex_rescue.thread_identity import resolve_thread_identity
from codex_rescue.alpha7.simulation.transaction import compute_file_sha256
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter, WriterStatus


@dataclass
class FileValueSnapshot:
    path: str
    size: int
    mtime: float
    sha_prefix: str


@dataclass
class ProjectionCursorValue:
    thread_id: str
    next_byte_offset: int
    next_ordinal: int
    rollout_path: Optional[str]
    cursor_status: str  # IN_SYNC, CURSOR_STALLED, CURSOR_BEHIND, CURSOR_BEYOND_SOURCE


@dataclass
class ObserverSnapshot:
    timestamp: float
    files: Dict[str, FileValueSnapshot] = field(default_factory=dict)
    cursors: Dict[str, ProjectionCursorValue] = field(default_factory=dict)
    writer_status: WriterStatus = WriterStatus.UNKNOWN
    invariants_passed: bool = True
    invariants: List[InvariantCheckResult] = field(default_factory=list)


class StateObserver:
    """Active observer capturing real structured state values and invariant-backed causal timelines."""

    def __init__(self, codex_home: Path, recorder: BlackBoxRecorder):
        self.codex_home = codex_home
        self.recorder = recorder
        self.desktop_adapter = DesktopAdapter(self.codex_home)
        self._last_fs_state: Dict[str, FileValueSnapshot] = {}
        self._last_db_state: Dict[str, int] = {}
        self._last_thread_values: Dict[str, Dict[str, Any]] = {}
        self._last_cursor_values: Dict[str, ProjectionCursorValue] = {}
        self._snapshots: List[ObserverSnapshot] = []
        self.last_known_good: Optional[float] = None
        self.first_known_bad: Optional[float] = None
        self.poll_count = 0

    def poll_once(self) -> List[StructuralEvent]:
        """Performs one observation sweep across filesystem, SQLite state values, and projection cursors."""
        events: List[StructuralEvent] = []
        now = time.time()
        self.poll_count += 1

        # 1. Observe filesystem session rollouts with exact size, mtime, and sha_prefix
        sessions_dir = self.codex_home / "sessions"
        archived_dir = self.codex_home / "archived_sessions"
        current_fs_state: Dict[str, FileValueSnapshot] = {}

        for sdir in [sessions_dir, archived_dir]:
            if not sdir.exists():
                continue
            for p in sdir.rglob("*.jsonl"):
                try:
                    stat = p.stat()
                    sha_prefix = compute_file_sha256(p)[:16]
                    current_fs_state[str(p)] = FileValueSnapshot(
                        path=str(p),
                        size=stat.st_size,
                        mtime=stat.st_mtime,
                        sha_prefix=sha_prefix,
                    )
                except OSError:
                    continue

        # Detect additions & modifications
        for p_str, snap in current_fs_state.items():
            ident = resolve_thread_identity(p_str)
            sid = ident.thread_id

            if p_str not in self._last_fs_state:
                e = self.recorder.record_event(
                    EventType.ROLLOUT_CREATED,
                    session_id=sid,
                    details={
                        "path": p_str,
                        "size": snap.size,
                        "mtime": snap.mtime,
                        "sha_prefix": snap.sha_prefix,
                        "source": "OBSERVED",
                    },
                )
                events.append(e)
            elif (
                snap.size != self._last_fs_state[p_str].size
                or snap.sha_prefix != self._last_fs_state[p_str].sha_prefix
            ):
                e = self.recorder.record_event(
                    EventType.ROLLOUT_APPENDED,
                    session_id=sid,
                    details={
                        "path": p_str,
                        "size": snap.size,
                        "old_size": self._last_fs_state[p_str].size,
                        "sha_prefix": snap.sha_prefix,
                        "source": "OBSERVED",
                    },
                )
                events.append(e)

        # Detect deletions
        for p_str in self._last_fs_state:
            if p_str not in current_fs_state:
                ident = resolve_thread_identity(p_str)
                sid = ident.thread_id
                e = self.recorder.record_event(
                    EventType.ROLLOUT_DELETED,
                    session_id=sid,
                    details={"path": p_str, "source": "OBSERVED"},
                )
                events.append(e)

        self._last_fs_state = current_fs_state

        # 2. Observe SQLite state databases, thread row values, and projection cursor values
        current_db_state: Dict[str, int] = {}
        current_thread_values: Dict[str, Dict[str, Any]] = {}
        current_cursors: Dict[str, ProjectionCursorValue] = {}

        for db_name in ("state_5.sqlite", "state.db", "codex.db"):
            db_path = self.codex_home / db_name
            if not db_path.exists() or db_path.stat().st_size == 0:
                continue

            try:
                uri = f"file:{db_path.resolve()}?mode=ro"
                conn = sqlite3.connect(uri, uri=True, timeout=0.1)
                try:
                    conn.execute("PRAGMA query_only=ON")
                    cur = conn.cursor()
                    cur.execute("SELECT name FROM sqlite_schema WHERE type='table'")
                    tables = [str(r[0]) for r in cur.fetchall()]

                    for t in tables:
                        if t in ("threads", "thread_history_projection_state", "session_index"):
                            cur.execute(f"SELECT count(*) FROM \"{t}\"")
                            cnt = int(cur.fetchone()[0])
                            current_db_state[f"{db_name}:{t}"] = cnt

                        # Value-level thread row inspection
                        if t == "threads":
                            cur.execute("PRAGMA table_info('threads')")
                            cols = {str(r[1]) for r in cur.fetchall()}
                            if "id" in cols:
                                sel_cols = ["id"]
                                for opt_col in ("rollout_path", "updated_at", "archived"):
                                    if opt_col in cols:
                                        sel_cols.append(opt_col)
                                cur.execute(f"SELECT {', '.join(sel_cols)} FROM threads")
                                for r in cur.fetchall():
                                    row_dict = {sel_cols[i]: r[i] for i in range(len(sel_cols))}
                                    tid = str(row_dict["id"])
                                    current_thread_values[tid] = row_dict

                        # Value-level projection cursor inspection
                        if t == "thread_history_projection_state":
                            cur.execute("PRAGMA table_info('thread_history_projection_state')")
                            cols = {str(r[1]) for r in cur.fetchall()}
                            if "thread_id" in cols and "next_rollout_byte_offset" in cols:
                                cur.execute("SELECT thread_id, next_rollout_byte_offset, next_rollout_ordinal FROM thread_history_projection_state")
                                for r in cur.fetchall():
                                    tid = str(r[0])
                                    byte_off = int(r[1])
                                    ord_val = int(r[2]) if len(r) > 2 and r[2] is not None else 0
                                    current_cursors[tid] = ProjectionCursorValue(
                                        thread_id=tid,
                                        next_byte_offset=byte_off,
                                        next_ordinal=ord_val,
                                        rollout_path=None,
                                        cursor_status="IN_SYNC",
                                    )
                finally:
                    conn.close()
            except Exception:
                continue

        # Detect SQLite table row count changes
        for db_table, count in current_db_state.items():
            if db_table in self._last_db_state and count != self._last_db_state[db_table]:
                e = self.recorder.record_event(
                    EventType.INDEX_ROW_UPDATED,
                    details={
                        "target": db_table,
                        "old_count": self._last_db_state[db_table],
                        "new_count": count,
                        "source": "OBSERVED",
                    },
                )
                events.append(e)

        # Detect SQLite row value changes (even when row count is constant)
        for tid, row_val in current_thread_values.items():
            if tid in self._last_thread_values and row_val != self._last_thread_values[tid]:
                e = self.recorder.record_event(
                    EventType.INDEX_ROW_UPDATED,
                    session_id=tid,
                    details={
                        "target": "threads",
                        "thread_id": tid,
                        "old_values": self._last_thread_values[tid],
                        "new_values": row_val,
                        "source": "VALUE_OBSERVED",
                    },
                )
                events.append(e)

        # Detect projection cursor value changes
        for tid, cursor_val in current_cursors.items():
            if tid in self._last_cursor_values:
                old_c = self._last_cursor_values[tid]
                if old_c.next_byte_offset != cursor_val.next_byte_offset or old_c.next_ordinal != cursor_val.next_ordinal:
                    e = self.recorder.record_event(
                        EventType.CURSOR_ADVANCED,
                        session_id=tid,
                        details={
                            "thread_id": tid,
                            "old_offset": old_c.next_byte_offset,
                            "new_offset": cursor_val.next_byte_offset,
                            "source": "VALUE_OBSERVED",
                        },
                    )
                    events.append(e)

        self._last_db_state = current_db_state
        self._last_thread_values = current_thread_values
        self._last_cursor_values = current_cursors

        # 3. Detect Writer Status
        writer_status = self.desktop_adapter.detect_writer_status()

        # 4. Invariant Evaluation & Timeline Analysis (LKG / FKB)
        invariants: List[InvariantCheckResult] = []
        inv_writer = InvariantEngine.check_active_writer(
            has_active_writer=(writer_status == WriterStatus.ACTIVE_CONFIRMED),
            writer_pid=None,
            is_mutation_operation=False,
        )
        invariants.append(inv_writer)

        all_passed = all(i.passed for i in invariants)
        snapshot = ObserverSnapshot(
            timestamp=now,
            files=current_fs_state,
            cursors=current_cursors,
            writer_status=writer_status,
            invariants_passed=all_passed,
            invariants=invariants,
        )
        self._snapshots.append(snapshot)

        if all_passed:
            self.last_known_good = now
        elif self.first_known_bad is None:
            self.first_known_bad = now

        return events
