from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path


@dataclass
class WriterInspectionReport:
    session_id: str
    session_path: str
    lock_present: bool
    lock_path: str | None
    owner_pid: int | None
    owner_process_alive: bool | None
    runtime_surface: str | None
    lock_age_seconds: float | None
    rollout_health: str
    safe_to_modify: bool
    diagnostic_note: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_text(self) -> str:
        lines = [
            f"Writer Ownership Inspection: {self.session_id}\n",
            f"Lock Present: {'YES' if self.lock_present else 'NO'}",
        ]
        if self.lock_present:
            lines.append(f"Lock Path: {self.lock_path or 'unknown'}")
            lines.append(f"Owner PID: {self.owner_pid if self.owner_pid is not None else 'unrecorded'}")
            lines.append(f"Owner Process Alive: {'YES' if self.owner_process_alive else ('NO' if self.owner_process_alive is False else 'UNKNOWN')}")
            lines.append(f"Runtime Surface: {self.runtime_surface or 'unknown'}")
            if self.lock_age_seconds is not None:
                lines.append(f"Lock Age: {self.lock_age_seconds}s")
        lines.append(f"\nRollout Health (Independent): {self.rollout_health}")
        lines.append(f"Safe to Mutate / Apply Recovery: {'YES' if self.safe_to_modify else 'NO (LOCK CONFLICT)'}")
        lines.append(f"\nNote: {self.diagnostic_note}")
        return "\n".join(lines)


def inspect_writer(
    session_path: Path | str,
    codex_home: Path | str | None = None,
) -> WriterInspectionReport:
    ev = collect_session_evidence(session_path, codex_home=codex_home)
    is_active = bool(ev.writer.lock_present and ev.writer.is_alive)
    safe_to_mod = not is_active

    if not ev.writer.lock_present:
        note = "No active lock detected. Safe for read-only diagnosis and recovery operations."
    elif ev.writer.is_alive:
        note = "Session is currently held by an active live writer process. Read-only diagnosis allowed; mutations strictly prohibited."
    else:
        note = "Lock file exists on disk but owner PID is dead or unresolvable. Do NOT automatically delete lock files; investigate before mutating."

    return WriterInspectionReport(
        session_id=ev.session_id,
        session_path=ev.session_path,
        lock_present=ev.writer.lock_present,
        lock_path=ev.writer.lock_path,
        owner_pid=ev.writer.pid,
        owner_process_alive=ev.writer.is_alive,
        runtime_surface=ev.writer.runtime_surface,
        lock_age_seconds=ev.writer.lock_age_seconds,
        rollout_health=ev.status,
        safe_to_modify=safe_to_mod,
        diagnostic_note=note,
    )
