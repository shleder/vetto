from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path


@dataclass
class FilteredSessionItem:
    session_id: str
    session_path: str
    category: str
    reason: str
    size_bytes: int = 0
    mtime: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def filter_sessions(
    codex_home: Path | str | None = None,
    orphans: bool = False,
    unindexed: bool = False,
    duplicates: bool = False,
) -> list[FilteredSessionItem]:
    home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"
    results: list[FilteredSessionItem] = []

    if not home.exists():
        return results

    session_files: list[Path] = []
    for pat in ("sessions/*.jsonl", "archived_sessions/*.jsonl", "subagents/*.jsonl", "*.jsonl"):
        session_files.extend(home.glob(pat))

    unique_paths = sorted(list({p.resolve() for p in session_files}))

    id_to_paths: dict[str, list[Path]] = defaultdict(list)
    evidences = {}

    for p in unique_paths:
        ev = collect_session_evidence(p, codex_home=home, max_scan_lines=500)
        evidences[p] = ev
        id_to_paths[ev.session_id].append(p)

    if duplicates:
        for sid, paths in id_to_paths.items():
            if len(paths) > 1:
                for p in paths:
                    ev = evidences[p]
                    results.append(
                        FilteredSessionItem(
                            session_id=sid,
                            session_path=ev.session_path,
                            category="duplicate",
                            reason=f"Multiple distinct rollout files exist on disk with identical session ID '{sid}'.",
                            size_bytes=ev.size_bytes,
                            mtime=ev.mtime,
                        )
                    )

    if unindexed:
        for p, ev in evidences.items():
            if ev.sqlite.present and not ev.sqlite.thread_found:
                results.append(
                    FilteredSessionItem(
                        session_id=ev.session_id,
                        session_path=ev.session_path,
                        category="unindexed",
                        reason="Rollout exists on filesystem but has no matching row in SQLite threads index.",
                        size_bytes=ev.size_bytes,
                        mtime=ev.mtime,
                    )
                )

    if orphans:
        for p, ev in evidences.items():
            if ev.rollout.parent_id:
                parent_exists = any(ev.rollout.parent_id in p2.stem for p2 in unique_paths)
                if not parent_exists:
                    results.append(
                        FilteredSessionItem(
                            session_id=ev.session_id,
                            session_path=ev.session_path,
                            category="orphan",
                            reason=f"Subagent references parent session ID '{ev.rollout.parent_id}' which cannot be resolved in store.",
                            size_bytes=ev.size_bytes,
                            mtime=ev.mtime,
                        )
                    )

    return results
