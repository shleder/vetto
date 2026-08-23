from __future__ import annotations

import os
import platform
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence, detect_path_family, translate_path
from .redact import sanitize_path


@dataclass
class WorkspaceAdvisorReport:
    session_id: str
    session_path: str
    saved_cwd: str | None
    saved_path_family: str
    current_os: str
    current_path_family: str
    cwd_accessible: bool
    repo_accessible: bool
    is_git_repository: bool
    translated_path: str | None
    transcript_health: str
    workspace_health: str
    advice: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_text(self) -> str:
        lines = [
            f"Workspace Analysis for Session: {self.session_id}\n",
            f"Saved Working Directory: {self.saved_cwd or 'unavailable'} ({self.saved_path_family})",
            f"Current Runtime OS: {self.current_os} ({self.current_path_family})",
            f"Directory Accessible: {'YES' if self.cwd_accessible else 'NO'}",
            f"Git Repository Valid: {'YES' if self.is_git_repository else 'NO'}",
        ]
        if self.translated_path:
            lines.append(f"Deterministic Path Translation: {self.translated_path}")
        lines.append(f"\nTranscript Health: {self.transcript_health}")
        lines.append(f"Workspace Association Health: {self.workspace_health}")
        lines.append(f"\nAdvice: {self.advice}")
        return "\n".join(lines)


def analyze_workspace(
    session_path: Path | str,
    codex_home: Path | str | None = None,
) -> WorkspaceAdvisorReport:
    ev = collect_session_evidence(session_path, codex_home=codex_home)
    curr_sys = platform.system().lower()
    curr_family = "windows" if curr_sys == "windows" else "posix"
    if "microsoft" in platform.uname().release.lower():
        curr_family = "wsl"

    saved_cwd = ev.workspace.saved_cwd
    saved_fam = detect_path_family(saved_cwd) if saved_cwd else "unknown"

    cwd_acc = False
    repo_acc = False
    is_git = False
    translated = translate_path(saved_cwd) if saved_cwd else None

    if saved_cwd:
        test_path = Path(saved_cwd)
        if test_path.exists():
            cwd_acc = True
            if (test_path / ".git").exists():
                is_git = True
                repo_acc = True
        elif translated and Path(translated).exists():
            test_trans = Path(translated)
            cwd_acc = True
            if (test_trans / ".git").exists():
                is_git = True
                repo_acc = True

    if not saved_cwd:
        ws_health = "UNRECORDED"
        advice = "No workspace directory was persisted in rollout; transcript remains independently valid."
    elif cwd_acc:
        ws_health = "HEALTHY"
        advice = "Saved workspace is accessible in current runtime environment."
    elif saved_fam != curr_family and translated:
        ws_health = "CROSS_PLATFORM_MISMATCH"
        advice = f"Session recorded under {saved_fam}. Plausible native translation: {translated}. No metadata changes required."
    else:
        ws_health = "INACCESSIBLE"
        advice = "Workspace path is not present on current filesystem. Transcript health is unaffected."

    return WorkspaceAdvisorReport(
        session_id=ev.session_id,
        session_path=ev.session_path,
        saved_cwd=saved_cwd,
        saved_path_family=saved_fam,
        current_os=curr_sys,
        current_path_family=curr_family,
        cwd_accessible=cwd_acc,
        repo_accessible=repo_acc,
        is_git_repository=is_git,
        translated_path=translated,
        transcript_health=ev.status,
        workspace_health=ws_health,
        advice=advice,
    )
