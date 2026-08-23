from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path


@dataclass
class LayerDivergence:
    dimension: str
    rollout_value: Any
    sqlite_value: Any
    divergence_type: str
    note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SessionDiff:
    session_id: str
    session_path: str
    divergences: list[LayerDivergence] = field(default_factory=list)
    is_aligned: bool = True
    summary: str = "Persisted layers are in sync."

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_path": self.session_path,
            "is_aligned": self.is_aligned,
            "summary": self.summary,
            "divergences": [d.to_dict() for d in self.divergences],
        }


def diff_session(session_path: Path | str, codex_home: Path | str | None = None) -> SessionDiff:
    evidence = collect_session_evidence(session_path, codex_home=codex_home)
    diff = SessionDiff(
        session_id=evidence.session_id,
        session_path=evidence.session_path,
    )

    if evidence.sqlite.present:
        if not evidence.sqlite.thread_found:
            diff.divergences.append(
                LayerDivergence(
                    dimension="thread_inventory",
                    rollout_value="present_on_filesystem",
                    sqlite_value="absent_from_sqlite",
                    divergence_type="UNINDEXED_ROLLOUT",
                    note="Rollout file exists on disk but is unindexed in SQLite state DB.",
                )
            )
        else:
            last_ord = evidence.rollout.last_ordinal
            cursor = evidence.sqlite.projection_cursor
            if last_ord is not None and cursor is not None and last_ord != cursor:
                diff.divergences.append(
                    LayerDivergence(
                        dimension="projection_cursor",
                        rollout_value=last_ord,
                        sqlite_value=cursor,
                        divergence_type="CURSOR_DIVERGENCE",
                        note=f"Rollout ordinal ({last_ord}) differs from SQLite projection cursor ({cursor}).",
                    )
                )

            turns = evidence.rollout.turn_count
            items = evidence.sqlite.item_count
            if items > 0 and turns > 0 and turns != items:
                diff.divergences.append(
                    LayerDivergence(
                        dimension="item_turn_count",
                        rollout_value=turns,
                        sqlite_value=items,
                        divergence_type="COUNT_MISMATCH",
                        note=f"Rollout turn count ({turns}) differs from SQLite item count ({items}).",
                    )
                )
    else:
        diff.divergences.append(
            LayerDivergence(
                dimension="sqlite_store",
                rollout_value="present",
                sqlite_value="sqlite_db_absent",
                divergence_type="STANDALONE_ROLLOUT",
                note="No associated SQLite database discovered; session operates in standalone filesystem mode.",
            )
        )

    if evidence.is_archived and evidence.sqlite.present and evidence.sqlite.thread_found:
        diff.divergences.append(
            LayerDivergence(
                dimension="archive_state",
                rollout_value="archived_location",
                sqlite_value="active_thread_row",
                divergence_type="ARCHIVE_MISMATCH",
                note="Rollout is located in archived store while SQLite row remains active.",
            )
        )

    if evidence.workspace.saved_cwd and not evidence.workspace.accessible and evidence.workspace.path_family != "unknown":
        diff.divergences.append(
            LayerDivergence(
                dimension="workspace_accessibility",
                rollout_value=evidence.workspace.saved_cwd,
                sqlite_value=evidence.workspace.translated_path or "untranslated",
                divergence_type="WORKSPACE_INACCESSIBLE",
                note=f"Saved workspace path is inaccessible in current runtime environment ({evidence.workspace.path_family}).",
            )
        )

    if diff.divergences:
        diff.is_aligned = False
        diff.summary = f"Detected {len(diff.divergences)} layer divergence(s) between filesystem and derived state."

    return diff
