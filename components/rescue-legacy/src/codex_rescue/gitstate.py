from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path


class GitStateError(RuntimeError):
    pass


@dataclass(frozen=True)
class GitState:
    cwd: str
    root: str
    worktree: str
    branch: str | None
    head_sha: str
    staged: tuple[str, ...]
    modified: tuple[str, ...]
    untracked: tuple[str, ...]
    diff_hash: str
    fingerprint_scope: str = "git-diff-v2:no-ext-diff,no-textconv,no-renames;tracked+cached+untracked"
    index_flags: tuple[str, ...] = ()

    @property
    def changed_files(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.staged + self.modified + self.untracked)))

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["changed_files"] = list(self.changed_files)
        return data


def _git_environment() -> dict[str, str]:
    """Return a child environment that cannot inject an external diff.

    Git honours several environment variables before it reads command-line
    flags.  Remove those controls and make the child non-interactive.  The
    caller's normal PATH/HOME remain available for locating git and its
    credential-free config, while all diff commands also carry explicit
    ``--no-ext-diff``/``--no-textconv`` flags.
    """

    env = os.environ.copy()
    for key in (
        "GIT_EXTERNAL_DIFF",
        "GIT_DIFF_OPTS",
        "GIT_PAGER",
        "PAGER",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_PARAMETERS",
    ):
        env.pop(key, None)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_PAGER"] = "cat"
    return env


def _git(cwd: Path, *args: str, binary: bool = False, check: bool = True) -> bytes | str:
    try:
        result = subprocess.run(
            ["git", *args],
            cwd=cwd,
            check=check,
            capture_output=True,
            text=not binary,
            encoding=None if binary else "utf-8",
            errors=None if binary else "surrogateescape",
            env=_git_environment(),
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise GitStateError(detail.strip()) from exc
    return result.stdout


def _split_z(raw: str) -> tuple[str, ...]:
    return tuple(sorted(item for item in raw.split("\0") if item))


def _index_flags(root: Path) -> tuple[str, ...]:
    """Return tracked paths hidden by Git index trust flags.

    ``git diff`` deliberately honours ``assume-unchanged`` and
    ``skip-worktree``.  Those flags can therefore make a modified worktree
    look clean.  Read the index metadata without changing it and surface the
    paths so verification can fail closed instead of reporting a safe state.
    """

    raw = str(_git(root, "ls-files", "-v", "-z", "--"))
    flagged: list[str] = []
    for entry in raw.split("\0"):
        if len(entry) < 3 or entry[1] != " ":
            continue
        marker, path = entry[0], entry[2:]
        if marker == "h":
            flagged.append(f"assume-unchanged:{path}")
        elif marker == "S":
            flagged.append(f"skip-worktree:{path}")
    return tuple(sorted(flagged))


def _untracked_manifest(root: Path, paths: tuple[str, ...]) -> bytes:
    manifest: list[dict[str, object]] = []
    for rel in paths:
        path = root / rel
        if path.is_symlink():
            content = str(path.readlink()).encode("utf-8", "surrogateescape")
            kind = "symlink"
        elif path.is_file():
            kind = "file"
            digest = hashlib.sha256()
            size = 0
            try:
                with path.open("rb") as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        size += len(chunk)
                        digest.update(chunk)
            except OSError:
                kind = "unreadable"
                size = 0
                digest = hashlib.sha256()
        else:
            kind = "other"
            size = 0
            digest = hashlib.sha256()
        if path.is_symlink():
            size = len(content)
            digest = hashlib.sha256(content)
        manifest.append(
            {
                "path": rel.replace("\\", "/"),
                "kind": kind,
                "size": size,
                "mode": path.lstat().st_mode,
                "sha256": digest.hexdigest(),
            }
        )
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()


def inspect_git_state(cwd: str | Path) -> GitState:
    cwd_path = Path(cwd).resolve()
    if not cwd_path.exists():
        raise GitStateError(f"cwd does not exist: {cwd_path}")
    root = Path(str(_git(cwd_path, "rev-parse", "--show-toplevel")).strip()).resolve()
    worktree = str(_git(cwd_path, "rev-parse", "--show-toplevel")).strip()
    head = str(_git(root, "rev-parse", "HEAD")).strip()
    branch_raw = str(_git(root, "symbolic-ref", "--quiet", "--short", "HEAD", check=False)).strip()
    branch = branch_raw or None
    diff_flags = ("--no-ext-diff", "--no-textconv", "--no-renames")
    staged = _split_z(str(_git(root, "diff", *diff_flags, "--cached", "--name-only", "-z", "--")))
    modified = _split_z(str(_git(root, "diff", *diff_flags, "--name-only", "-z", "--")))
    untracked = _split_z(str(_git(root, "ls-files", "--others", "--exclude-standard", "-z", "--")))
    index_flags = _index_flags(root)

    digest = hashlib.sha256()
    digest.update(b"codex-rescue-diff-v2\0")
    digest.update(b"scope=tracked+cached+untracked;flags=no-ext-diff,no-textconv,no-renames\0")
    digest.update(bytes(_git(root, "diff", *diff_flags, "--full-index", "--binary", "--", binary=True)))
    digest.update(b"\0cached\0")
    digest.update(bytes(_git(root, "diff", *diff_flags, "--cached", "--full-index", "--binary", "--", binary=True)))
    digest.update(b"\0untracked\0")
    digest.update(_untracked_manifest(root, untracked))

    return GitState(
        cwd=str(cwd_path),
        root=str(root),
        worktree=worktree,
        branch=branch,
        head_sha=head,
        staged=staged,
        modified=modified,
        untracked=untracked,
        diff_hash=digest.hexdigest(),
        index_flags=index_flags,
    )


def compare_git_state(expected: dict[str, object], actual: GitState) -> list[str]:
    conflicts: list[str] = []
    comparisons = {
        "root": actual.root,
        "worktree": actual.worktree,
        "head_sha": actual.head_sha,
        "diff_hash": actual.diff_hash,
        "fingerprint_scope": actual.fingerprint_scope,
        "index_flags": actual.index_flags,
    }
    for key, actual_value in comparisons.items():
        expected_value = expected.get(key)
        if expected_value and expected_value != actual_value:
            conflicts.append(f"{key}: expected {expected_value}, actual {actual_value}")
    if actual.index_flags:
        conflicts.append(
            "index flags require review: " + ", ".join(actual.index_flags)
        )
    expected_files = set(expected.get("changed_files") or [])
    actual_files = set(actual.changed_files)
    if expected_files and expected_files != actual_files:
        missing = sorted(expected_files - actual_files)
        added = sorted(actual_files - expected_files)
        conflicts.append(f"changed_files differ: missing={missing}, added={added}")
    return conflicts
