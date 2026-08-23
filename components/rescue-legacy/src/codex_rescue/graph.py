from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .lifecycle_truth import classify_subagent_lifecycle, scan_durable_lifecycle
from .spawn_edges import SPAWN_EDGE_UNKNOWN, inspect_thread_spawn_edge
from .thread_identity import parse_rollout_filename


@dataclass
class GraphNode:
    session_id: str | None
    session_path: str
    depth: int = 0
    parent_id: str | None = None
    children: list["GraphNode"] = field(default_factory=list)
    size_bytes: int = 0
    turn_count: int = 0
    lifecycle_status: str = "unknown"
    lifecycle_class: str = "UNKNOWN"
    durable_state: str = "UNKNOWN"
    runtime_state: str = "UNKNOWN"
    presentation_state: str = "UNKNOWN"
    dispatchable: bool | None = None
    finding_ids: list[str] = field(default_factory=list)
    spawn_edge: dict[str, Any] = field(default_factory=dict)
    thread_identity: dict[str, Any] = field(default_factory=dict)
    is_archived: bool = False
    is_orphan: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_path": self.session_path,
            "depth": self.depth,
            "parent_id": self.parent_id,
            "size_bytes": self.size_bytes,
            "turn_count": self.turn_count,
            "lifecycle_status": self.lifecycle_status,
            "lifecycle_class": self.lifecycle_class,
            "durable_state": self.durable_state,
            "runtime_state": self.runtime_state,
            "presentation_state": self.presentation_state,
            "dispatchable": self.dispatchable,
            "finding_ids": list(self.finding_ids),
            "spawn_edge": dict(self.spawn_edge),
            "thread_identity": dict(self.thread_identity),
            "is_archived": self.is_archived,
            "is_orphan": self.is_orphan,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class SessionGraph:
    root_session_id: str | None
    family_sessions_count: int = 1
    max_depth: int = 0
    aggregate_family_bytes: int = 0
    root_node: GraphNode | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "root_session_id": self.root_session_id,
            "family_sessions_count": self.family_sessions_count,
            "max_depth": self.max_depth,
            "aggregate_family_bytes": self.aggregate_family_bytes,
            "tree": self.root_node.to_dict() if self.root_node else None,
        }

    def render_text(self) -> str:
        lines: list[str] = []
        lines.append(f"Session Family Graph: {self.root_session_id or 'UNKNOWN'}")
        lines.append(
            f"Family sessions: {self.family_sessions_count} | "
            f"Aggregate bytes: {self.aggregate_family_bytes} | Max depth: {self.max_depth}\n"
        )

        def _render_node(node: GraphNode, indent: str = "") -> None:
            status_flag = f"[{node.lifecycle_status}]"
            orphan_flag = " (ORPHAN)" if node.is_orphan else ""
            lines.append(
                f"{indent}├── {node.session_id or 'UNKNOWN'} {status_flag}{orphan_flag} "
                f"({node.size_bytes} bytes, {node.turn_count} turns)"
            )
            for child in node.children:
                _render_node(child, indent + "│   ")

        if self.root_node:
            _render_node(self.root_node)
        return "\n".join(lines)


def _runtime_active(evidence: Any) -> bool | None:
    if evidence.writer.lock_present and evidence.writer.is_alive is True:
        return True
    return None


def _unknown_spawn_edge(*, parent_id: str | None, child_id: str | None, reason: str) -> dict[str, Any]:
    return {
        "status": SPAWN_EDGE_UNKNOWN,
        "parent_thread_id": parent_id,
        "child_thread_id": child_id,
        "db_path": None,
        "reason": reason,
    }


def _lifecycle_node_fields(
    path: Path,
    evidence: Any,
    *,
    session_id: str | None,
    parent_id: str | None,
    codex_home: Path | str | None,
) -> dict[str, Any]:
    durable = scan_durable_lifecycle(path)
    if session_id is None:
        spawn_edge_dict = _unknown_spawn_edge(
            parent_id=parent_id,
            child_id=None,
            reason="logical ThreadId is unresolved; spawn-edge correlation was not attempted",
        )
        spawn_edge_status = SPAWN_EDGE_UNKNOWN
    else:
        spawn_edge = inspect_thread_spawn_edge(
            path,
            child_thread_id=session_id,
            parent_thread_id=parent_id,
            codex_home=codex_home,
        )
        spawn_edge_dict = spawn_edge.to_dict()
        spawn_edge_status = spawn_edge.status
    truth = classify_subagent_lifecycle(
        durable_state=durable.state,
        runtime_active=_runtime_active(evidence),
        presentation_active=None,
        spawn_edge_status=spawn_edge_status,
    )
    legacy_status = {
        "WORKING": "active",
        "DONE": "completed",
        "INACTIVE": "inactive",
        "UNKNOWN": "unknown",
    }[truth.status]
    return {
        "lifecycle_status": legacy_status,
        "lifecycle_class": truth.status,
        "durable_state": truth.durable_state,
        "runtime_state": truth.runtime_state,
        "presentation_state": truth.presentation_state,
        "dispatchable": truth.dispatchable,
        "finding_ids": list(truth.findings),
        "spawn_edge": spawn_edge_dict,
        "thread_identity": evidence.thread_identity.to_dict(),
    }


def _find_child_path(parent_path: Path, child_id: str) -> Path | None:
    candidate_dir = parent_path.parent / "subagents"
    search_dir = candidate_dir if candidate_dir.is_dir() else parent_path.parent
    try:
        matches = sorted(search_dir.glob(f"*{child_id}*.jsonl"), key=lambda item: str(item))
    except OSError:
        return None
    for match in matches:
        parsed = parse_rollout_filename(match)
        if parsed is not None and parsed.thread_id == child_id:
            return match
    return None


def build_session_graph(
    session_path: Path | str,
    codex_home: Path | str | None = None,
    max_depth: int = 10,
) -> SessionGraph:
    path = Path(session_path).resolve()
    root_ev = collect_session_evidence(path, codex_home=codex_home)
    seen_paths: set[Path] = {path}
    seen_ids: set[str] = set()
    if root_ev.session_id:
        seen_ids.add(root_ev.session_id)

    def _make_node(
        node_path: Path,
        evidence: Any,
        *,
        depth: int,
        parent_id: str | None,
    ) -> GraphNode:
        session_id = evidence.session_id
        fields = _lifecycle_node_fields(
            node_path,
            evidence,
            session_id=session_id,
            parent_id=parent_id,
            codex_home=codex_home,
        )
        return GraphNode(
            session_id=session_id,
            session_path=evidence.session_path,
            depth=depth,
            parent_id=parent_id,
            size_bytes=evidence.size_bytes,
            turn_count=evidence.rollout.turn_count,
            is_archived=bool(evidence.is_archived),
            **fields,
        )

    root_node = _make_node(
        path,
        root_ev,
        depth=0,
        parent_id=root_ev.rollout.parent_id,
    )
    if root_ev.rollout.parent_id:
        root_node.is_orphan = not bool(
            list(path.parent.glob(f"*{root_ev.rollout.parent_id}*.jsonl"))
        )

    graph = SessionGraph(
        root_session_id=root_ev.session_id,
        family_sessions_count=1,
        max_depth=0,
        aggregate_family_bytes=root_ev.size_bytes,
        root_node=root_node,
    )

    def _attach_children(
        parent_node: GraphNode,
        parent_path: Path,
        parent_evidence: Any,
        depth: int,
    ) -> None:
        if depth >= max_depth:
            return
        for child_id in parent_evidence.rollout.subagent_ids:
            if child_id in seen_ids:
                continue
            child_path = _find_child_path(parent_path, child_id)
            if child_path is None:
                continue
            try:
                resolved = child_path.resolve()
            except OSError:
                resolved = child_path
            if resolved in seen_paths:
                continue

            child_ev = collect_session_evidence(resolved, codex_home=codex_home)
            # The parent hint is only a lookup hint. The child rollout must
            # independently resolve to the same logical ThreadId before it is
            # attached to the family graph.
            if child_ev.session_id != child_id:
                continue
            seen_paths.add(resolved)
            seen_ids.add(child_id)
            child_node = _make_node(
                resolved,
                child_ev,
                depth=depth + 1,
                parent_id=parent_node.session_id,
            )
            parent_node.children.append(child_node)
            graph.family_sessions_count += 1
            graph.aggregate_family_bytes += child_ev.size_bytes
            graph.max_depth = max(graph.max_depth, depth + 1)
            _attach_children(child_node, resolved, child_ev, depth + 1)

    _attach_children(root_node, path, root_ev, 0)
    return graph
