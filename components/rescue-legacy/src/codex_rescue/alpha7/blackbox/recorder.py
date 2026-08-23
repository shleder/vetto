from __future__ import annotations

import enum
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


class EventType(str, enum.Enum):
    THREAD_CREATED = "THREAD_CREATED"
    ROLLOUT_CREATED = "ROLLOUT_CREATED"
    ROLLOUT_APPENDED = "ROLLOUT_APPENDED"
    ROLLOUT_DELETED = "ROLLOUT_DELETED"
    ROLLOUT_MOVED = "ROLLOUT_MOVED"
    ROLLOUT_ARCHIVED = "ROLLOUT_ARCHIVED"
    SQLITE_ROW_INSERTED = "SQLITE_ROW_INSERTED"
    SQLITE_ROW_CHANGED = "SQLITE_ROW_CHANGED"
    WRITER_ATTACHED = "WRITER_ATTACHED"
    WRITER_DETACHED = "WRITER_DETACHED"
    WORKSPACE_CHANGED = "WORKSPACE_CHANGED"
    SCHEMA_CHANGED = "SCHEMA_CHANGED"
    MIGRATION_HAPPENED = "MIGRATION_HAPPENED"
    PROJECTION_CURSOR_ADVANCED = "PROJECTION_CURSOR_ADVANCED"
    PROJECTION_CURSOR_STOPPED = "PROJECTION_CURSOR_STOPPED"
    PROJECTION_CURSOR_REGRESSED = "PROJECTION_CURSOR_REGRESSED"
    COMPACTION_BOUNDARY = "COMPACTION_BOUNDARY"
    OVERSIZED_RECORD = "OVERSIZED_RECORD"
    SURFACE_VISIBILITY_CHANGED = "SURFACE_VISIBILITY_CHANGED"


@dataclass
class StructuralEvent:
    event_id: str
    event_type: EventType
    timestamp: float
    session_id: Optional[str] = None
    path: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    # Strictly structural metadata only. No prompts, responses, or raw contents.

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp,
            "session_id": self.session_id,
            "path": self.path,
            "details": self.details,
        }


@dataclass
class StructuralSnapshot:
    snapshot_id: str
    timestamp: float
    codex_version: Optional[str] = None
    total_sessions_count: int = 0
    archived_sessions_count: int = 0
    sqlite_rows_count: int = 0
    active_writers_count: int = 0
    sessions_hash_map: Dict[str, str] = field(default_factory=dict)  # session_id -> metadata_hash

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "codex_version": self.codex_version,
            "total_sessions_count": self.total_sessions_count,
            "archived_sessions_count": self.archived_sessions_count,
            "sqlite_rows_count": self.sqlite_rows_count,
            "active_writers_count": self.active_writers_count,
            "sessions_hash_map": self.sessions_hash_map,
        }


class BlackBoxRecorder:
    """Local flight recorder for Codex structural events. Privacy-first, metadata-only."""

    def __init__(self, storage_dir: Optional[Path] = None):
        self.storage_dir = storage_dir or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "blackbox"
        self.events: List[StructuralEvent] = []

    def record_event(
        self,
        event_type: EventType,
        session_id: Optional[str] = None,
        path: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> StructuralEvent:
        event = StructuralEvent(
            event_id=f"evt_{len(self.events) + 1}_{int(time.time()*1000)}",
            event_type=event_type,
            timestamp=time.time(),
            session_id=session_id,
            path=path,
            details=details or {},
        )
        self.events.append(event)
        return event

    def create_snapshot(self, codex_home: Path) -> StructuralSnapshot:
        """Creates privacy-safe, metadata-first, bounded structural snapshot."""
        now = time.time()
        sessions_dir = codex_home / "sessions"
        archived_dir = codex_home / "archived_sessions"

        fs_count = 0
        archived_count = 0
        hash_map = {}

        if sessions_dir.exists():
            for p in sessions_dir.glob("*.jsonl"):
                fs_count += 1
                try:
                    stat = p.stat()
                    # Hash of size + mtime
                    hash_map[p.stem] = f"{stat.st_size}_{int(stat.st_mtime)}"
                except Exception:
                    pass

        if archived_dir.exists():
            for p in archived_dir.glob("*.jsonl"):
                archived_count += 1
                try:
                    stat = p.stat()
                    hash_map[f"archived_{p.stem}"] = f"{stat.st_size}_{int(stat.st_mtime)}"
                except Exception:
                    pass

        return StructuralSnapshot(
            snapshot_id=f"snap_{int(now)}",
            timestamp=now,
            total_sessions_count=fs_count,
            archived_sessions_count=archived_count,
            sqlite_rows_count=0,
            active_writers_count=0,
            sessions_hash_map=hash_map,
        )

    def compare_snapshots(self, snap_a: StructuralSnapshot, snap_b: StructuralSnapshot) -> Dict[str, Any]:
        """Compares two structural snapshots (e.g. before vs after update)."""
        added = set(snap_b.sessions_hash_map.keys()) - set(snap_a.sessions_hash_map.keys())
        removed = set(snap_a.sessions_hash_map.keys()) - set(snap_b.sessions_hash_map.keys())
        modified = {
            k
            for k in set(snap_a.sessions_hash_map.keys()) & set(snap_b.sessions_hash_map.keys())
            if snap_a.sessions_hash_map[k] != snap_b.sessions_hash_map[k]
        }

        return {
            "snapshot_a": snap_a.snapshot_id,
            "snapshot_b": snap_b.snapshot_id,
            "elapsed_sec": round(snap_b.timestamp - snap_a.timestamp, 2),
            "added_sessions": list(added),
            "removed_sessions": list(removed),
            "modified_sessions": list(modified),
            "total_divergences": len(added) + len(removed) + len(modified),
        }
