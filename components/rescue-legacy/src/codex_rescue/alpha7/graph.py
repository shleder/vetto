from __future__ import annotations

import enum
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class PathNamespace(str, enum.Enum):
    WINDOWS_STANDARD = "WINDOWS_STANDARD"      # C:\path
    WINDOWS_EXTENDED = "WINDOWS_EXTENDED"      # \\?\C:\path
    WINDOWS_UNC = "WINDOWS_UNC"                # \\server\share
    WINDOWS_EXTENDED_UNC = "WINDOWS_EXTENDED_UNC"  # \\?\UNC\server\share
    WSL_MNT = "WSL_MNT"                        # /mnt/c/path
    POSIX_STANDARD = "POSIX_STANDARD"          # /home/user/path
    UNKNOWN = "UNKNOWN"


def detect_path_namespace(p: str | Path) -> PathNamespace:
    s = str(p)
    if s.startswith("\\\\?\\UNC\\"):
        return PathNamespace.WINDOWS_EXTENDED_UNC
    if s.startswith("\\\\?\\"):
        return PathNamespace.WINDOWS_EXTENDED
    if s.startswith("\\\\"):
        return PathNamespace.WINDOWS_UNC
    if s.startswith("/mnt/") and len(s) > 6 and s[6] == "/":
        return PathNamespace.WSL_MNT
    if len(s) >= 2 and s[1] == ":" and s[0].isalpha():
        return PathNamespace.WINDOWS_STANDARD
    if s.startswith("/"):
        return PathNamespace.POSIX_STANDARD
    return PathNamespace.UNKNOWN


from codex_rescue.windows_paths import normalize_windows_extended_path


def normalize_canonical_path(p: str | Path) -> str:
    """Safely normalizes path string while preserving underlying identity."""
    return normalize_windows_extended_path(p)


class SurfaceVisibility(str, enum.Enum):
    VISIBLE = "VISIBLE"
    HIDDEN = "HIDDEN"
    INACCESSIBLE = "INACCESSIBLE"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


@dataclass
class SurfaceObservation:
    surface: str  # "cli", "desktop", "ide", "app_server"
    visibility: SurfaceVisibility
    observed_path: Optional[str] = None
    timestamp: Optional[float] = None
    error_code: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "surface": self.surface,
            "visibility": self.visibility.value,
            "observed_path": self.observed_path,
            "timestamp": self.timestamp,
            "error_code": self.error_code,
            "notes": self.notes,
        }


@dataclass
class ThreadIdentity:
    session_id: str
    raw_path: str
    canonical_path: str
    namespace: PathNamespace
    is_archived: bool = False
    parent_session_id: Optional[str] = None
    subagent_ids: List[str] = field(default_factory=list)

    @property
    def thread_id(self) -> str:
        return self.session_id

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "thread_id": self.session_id,
            "raw_path": self.raw_path,
            "canonical_path": self.canonical_path,
            "namespace": self.namespace.value,
            "is_archived": self.is_archived,
            "parent_session_id": self.parent_session_id,
            "subagent_ids": self.subagent_ids,
        }


@dataclass
class StorageProfile:
    total_bytes: int = 0
    record_count: int = 0
    largest_record_bytes: int = 0
    inline_image_bytes: int = 0
    tool_output_bytes: int = 0
    compaction_product_bytes: int = 0
    other_bytes: int = 0
    amplification_ratio: float = 1.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "record_count": self.record_count,
            "largest_record_bytes": self.largest_record_bytes,
            "inline_image_bytes": self.inline_image_bytes,
            "tool_output_bytes": self.tool_output_bytes,
            "compaction_product_bytes": self.compaction_product_bytes,
            "other_bytes": self.other_bytes,
            "amplification_ratio": round(self.amplification_ratio, 2),
        }


@dataclass
class RuntimeState:
    has_active_writer: bool = False
    writer_pid: Optional[int] = None
    writer_namespace: Optional[str] = None
    is_writer_alive: bool = False
    lock_held: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "has_active_writer": self.has_active_writer,
            "writer_pid": self.writer_pid,
            "writer_namespace": self.writer_namespace,
            "is_writer_alive": self.is_writer_alive,
            "lock_held": self.lock_held,
        }


@dataclass
class SqliteState:
    db_readable: bool = True
    state_row_exists: bool = False
    projection_cursor: Optional[int] = None
    projection_status: str = "UNKNOWN"  # MATCH, WEDGED, STALE, NOT_APPLICABLE
    indexed_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "db_readable": self.db_readable,
            "state_row_exists": self.state_row_exists,
            "projection_cursor": self.projection_cursor,
            "projection_status": self.projection_status,
            "indexed_path": self.indexed_path,
        }


@dataclass
class WorkspaceState:
    cwd: Optional[str] = None
    git_root: Optional[str] = None
    git_head: Optional[str] = None
    worktree_id: Optional[str] = None
    is_valid: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "cwd": self.cwd,
            "git_root": self.git_root,
            "git_head": self.git_head,
            "worktree_id": self.worktree_id,
            "is_valid": self.is_valid,
        }


@dataclass
class ThreadNode:
    identity: ThreadIdentity
    storage: StorageProfile = field(default_factory=StorageProfile)
    runtime: RuntimeState = field(default_factory=RuntimeState)
    sqlite: SqliteState = field(default_factory=SqliteState)
    workspace: WorkspaceState = field(default_factory=WorkspaceState)
    surfaces: Dict[str, SurfaceObservation] = field(default_factory=dict)
    schema_version: int = 1
    status: str = "HEALTHY"
    findings: List[str] = field(default_factory=list)
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW, INSUFFICIENT_EVIDENCE
    evidence: Dict[str, Any] = field(default_factory=dict)
    invariants_evaluated: List[str] = field(default_factory=list)

    @property
    def has_cross_surface_divergence(self) -> bool:
        vis_set = {
            obs.visibility
            for obs in self.surfaces.values()
            if obs.visibility in (SurfaceVisibility.VISIBLE, SurfaceVisibility.HIDDEN)
        }
        return len(vis_set) > 1

    def to_dict(self) -> Dict[str, Any]:
        return {
            "identity": self.identity.to_dict(),
            "storage": self.storage.to_dict(),
            "runtime": self.runtime.to_dict(),
            "sqlite": self.sqlite.to_dict(),
            "workspace": self.workspace.to_dict(),
            "surfaces": {k: v.to_dict() for k, v in self.surfaces.items()},
            "schema_version": self.schema_version,
            "status": self.status,
            "findings": self.findings,
            "confidence": self.confidence,
            "has_cross_surface_divergence": self.has_cross_surface_divergence,
            "evidence": self.evidence,
            "invariants_evaluated": self.invariants_evaluated,
        }


class UnifiedStateGraph:
    """Unified normalized multi-surface state representation for Codex Rescue Alpha7."""

    def __init__(self):
        self.nodes: Dict[str, ThreadNode] = {}
        self.canonical_index: Dict[str, str] = {}  # canonical_path -> session_id

    def add_or_update_node(self, node: ThreadNode) -> None:
        self.nodes[node.identity.session_id] = node
        self.canonical_index[node.identity.canonical_path] = node.identity.session_id

    def get_by_session_id(self, session_id: str) -> Optional[ThreadNode]:
        return self.nodes.get(session_id)

    def get_by_path(self, path: str | Path) -> Optional[ThreadNode]:
        cpath = normalize_canonical_path(path)
        sid = self.canonical_index.get(cpath)
        if sid:
            return self.nodes.get(sid)
        return None

    def get_cross_surface_divergences(self) -> List[ThreadNode]:
        return [node for node in self.nodes.values() if node.has_cross_surface_divergence]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_threads": len(self.nodes),
            "threads": {k: v.to_dict() for k, v in self.nodes.items()},
            "cross_surface_divergences": [
                node.identity.session_id for node in self.get_cross_surface_divergences()
            ],
        }
