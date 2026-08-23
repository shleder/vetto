from __future__ import annotations

import enum
import os
import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from codex_rescue.alpha7.compatibility.path_remap import PathRemappingEngine
from codex_rescue.alpha7.graph import PathNamespace, detect_path_namespace


class WorkspaceContinuityStatus(str, enum.Enum):
    MATCHED = "MATCHED"
    MOVED = "MOVED"
    WORKTREE_CHANGED = "WORKTREE_CHANGED"
    REPOSITORY_CHANGED = "REPOSITORY_CHANGED"
    MISSING = "MISSING"
    UNRECORDED = "UNRECORDED"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


@dataclass
class GitMetadata:
    is_git_repository: bool = False
    repo_root: Optional[str] = None
    common_dir: Optional[str] = None
    head_commit: Optional[str] = None
    branch: Optional[str] = None
    is_detached_head: bool = False
    is_worktree: bool = False
    remote_origin_url: Optional[str] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WorkspaceContinuityReport:
    session_id: str
    status: WorkspaceContinuityStatus
    saved_cwd: Optional[str]
    current_cwd: Optional[str]
    saved_git: GitMetadata = field(default_factory=GitMetadata)
    current_git: GitMetadata = field(default_factory=GitMetadata)
    path_namespace: str = PathNamespace.UNKNOWN.value
    confidence: str = "HIGH"
    reason: str = ""
    guidance: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "status": self.status.value,
            "saved_cwd": self.saved_cwd,
            "current_cwd": self.current_cwd,
            "saved_git": self.saved_git.to_dict(),
            "current_git": self.current_git.to_dict(),
            "path_namespace": self.path_namespace,
            "confidence": self.confidence,
            "reason": self.reason,
            "guidance": self.guidance,
        }


class WorkspaceContinuityEngine:
    """Read-only Git and Workspace Continuity evaluator for Alpha7.

    Evaluates whether the active filesystem workspace matches the session's
    persisted working directory and Git repository state without performing
    any state modifications.
    """

    @staticmethod
    def inspect_git_read_only(target_dir: Path) -> GitMetadata:
        """Inspects git repository metadata strictly read-only using safe git commands."""
        if not target_dir.exists() or not target_dir.is_dir():
            return GitMetadata(is_git_repository=False, error="Directory does not exist")

        # 1. Check if git repo root exists
        try:
            res_toplevel = subprocess.run(
                ["git", "-C", str(target_dir), "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res_toplevel.returncode != 0:
                return GitMetadata(is_git_repository=False)

            repo_root = res_toplevel.stdout.strip()
            if not Path(repo_root).is_absolute():
                repo_root = str((target_dir / repo_root).resolve())
            else:
                repo_root = str(Path(repo_root).resolve())
        except Exception as e:
            return GitMetadata(is_git_repository=False, error=str(e))

        # 2. Check git common dir (for worktrees)
        common_dir = None
        is_worktree = False
        try:
            res_commondir = subprocess.run(
                ["git", "-C", str(target_dir), "rev-parse", "--git-common-dir"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res_commondir.returncode == 0:
                raw_common = res_commondir.stdout.strip()
                if raw_common:
                    p_common = Path(raw_common)
                    common_dir = str((target_dir / p_common).resolve() if not p_common.is_absolute() else p_common.resolve())

                git_dir_res = subprocess.run(
                    ["git", "-C", str(target_dir), "rev-parse", "--git-dir"],
                    capture_output=True,
                    text=True,
                    timeout=2.0,
                    check=False,
                )
                if git_dir_res.returncode == 0:
                    raw_git_dir = git_dir_res.stdout.strip()
                    if raw_git_dir:
                        p_git_dir = Path(raw_git_dir)
                        git_dir_resolved = str((target_dir / p_git_dir).resolve() if not p_git_dir.is_absolute() else p_git_dir.resolve())
                        if common_dir and git_dir_resolved != common_dir:
                            is_worktree = True
        except Exception:
            pass

        # 3. Read HEAD commit
        head_commit = None
        try:
            res_head = subprocess.run(
                ["git", "-C", str(target_dir), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res_head.returncode == 0:
                head_commit = res_head.stdout.strip()
        except Exception:
            pass

        # 4. Read branch and detached HEAD
        branch = None
        is_detached = False
        try:
            res_branch = subprocess.run(
                ["git", "-C", str(target_dir), "symbolic-ref", "--short", "-q", "HEAD"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res_branch.returncode == 0 and res_branch.stdout.strip():
                branch = res_branch.stdout.strip()
            else:
                is_detached = True
        except Exception:
            pass

        # 5. Read remote origin URL if configured
        remote_url = None
        try:
            res_remote = subprocess.run(
                ["git", "-C", str(target_dir), "config", "--get", "remote.origin.url"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if res_remote.returncode == 0 and res_remote.stdout.strip():
                remote_url = res_remote.stdout.strip()
        except Exception:
            pass

        return GitMetadata(
            is_git_repository=True,
            repo_root=repo_root,
            common_dir=common_dir,
            head_commit=head_commit,
            branch=branch,
            is_detached_head=is_detached,
            is_worktree=is_worktree,
            remote_origin_url=remote_url,
        )

    @staticmethod
    def evaluate_continuity(
        session_id: str,
        saved_cwd: Optional[str],
        current_cwd: Optional[str] = None,
        saved_git_metadata: Optional[GitMetadata] = None,
        explicit_mappings: Optional[Dict[str, str]] = None,
    ) -> WorkspaceContinuityReport:
        if not saved_cwd:
            return WorkspaceContinuityReport(
                session_id=session_id,
                status=WorkspaceContinuityStatus.UNRECORDED,
                saved_cwd=None,
                current_cwd=current_cwd,
                reason="No working directory was recorded in the session metadata.",
                guidance="Transcript remains valid; workspace context is not required for diagnosis.",
            )

        ns = detect_path_namespace(saved_cwd)
        active_target_dir_str = current_cwd or saved_cwd
        active_path = Path(active_target_dir_str)

        # Apply remapping if requested or platform translation needed
        if explicit_mappings and saved_cwd in explicit_mappings:
            active_path = Path(explicit_mappings[saved_cwd])
            active_target_dir_str = str(active_path)

        if not active_path.exists():
            return WorkspaceContinuityReport(
                session_id=session_id,
                status=WorkspaceContinuityStatus.MISSING,
                saved_cwd=saved_cwd,
                current_cwd=str(active_path),
                path_namespace=ns.value,
                reason=f"Saved workspace path '{saved_cwd}' is not present on disk.",
                guidance="Workspace is missing. Check if repository was moved or supply explicit path mapping.",
            )

        current_git = WorkspaceContinuityEngine.inspect_git_read_only(active_path)
        saved_git = saved_git_metadata or GitMetadata()

        # Check repository identity
        if saved_git.is_git_repository and not current_git.is_git_repository:
            return WorkspaceContinuityReport(
                session_id=session_id,
                status=WorkspaceContinuityStatus.REPOSITORY_CHANGED,
                saved_cwd=saved_cwd,
                current_cwd=str(active_path),
                saved_git=saved_git,
                current_git=current_git,
                path_namespace=ns.value,
                reason="Saved directory was a git repository, but current directory has no git metadata.",
                guidance="Directory was reused without git context. Review repository setup.",
            )

        if saved_git.is_git_repository and current_git.is_git_repository:
            # Check if remote origin differs
            if (
                saved_git.remote_origin_url
                and current_git.remote_origin_url
                and saved_git.remote_origin_url != current_git.remote_origin_url
            ):
                return WorkspaceContinuityReport(
                    session_id=session_id,
                    status=WorkspaceContinuityStatus.CONFLICT,
                    saved_cwd=saved_cwd,
                    current_cwd=str(active_path),
                    saved_git=saved_git,
                    current_git=current_git,
                    path_namespace=ns.value,
                    reason=f"Git remote origin URL changed from '{saved_git.remote_origin_url}' to '{current_git.remote_origin_url}'.",
                    guidance="Directory contains a different git repository than the session was created in.",
                )

            # Check worktree change
            if saved_git.is_worktree != current_git.is_worktree or (
                saved_git.common_dir and current_git.common_dir and saved_git.common_dir != current_git.common_dir
            ):
                return WorkspaceContinuityReport(
                    session_id=session_id,
                    status=WorkspaceContinuityStatus.WORKTREE_CHANGED,
                    saved_cwd=saved_cwd,
                    current_cwd=str(active_path),
                    saved_git=saved_git,
                    current_git=current_git,
                    path_namespace=ns.value,
                    reason="Git worktree root or common directory diverged from recorded state.",
                    guidance="Worktree topology changed. Review git worktree links.",
                )

        # Check path relocation
        if saved_cwd != str(active_path) and active_path.resolve() != Path(saved_cwd).resolve():
            return WorkspaceContinuityReport(
                session_id=session_id,
                status=WorkspaceContinuityStatus.MOVED,
                saved_cwd=saved_cwd,
                current_cwd=str(active_path),
                saved_git=saved_git,
                current_git=current_git,
                path_namespace=ns.value,
                reason=f"Workspace relocated from '{saved_cwd}' to '{active_path}'.",
                guidance="Workspace moved. Session continues under translated path without modifying original transcript.",
            )

        return WorkspaceContinuityReport(
            session_id=session_id,
            status=WorkspaceContinuityStatus.MATCHED,
            saved_cwd=saved_cwd,
            current_cwd=str(active_path),
            saved_git=saved_git,
            current_git=current_git,
            path_namespace=ns.value,
            reason="Saved workspace path and git state match active environment.",
            guidance="Workspace is fully aligned.",
        )
