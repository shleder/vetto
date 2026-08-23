from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import write_rescue
from .gitstate import GitStateError, compare_git_state, inspect_git_state
from .journal import read_entries
from .reconstruct import (
    build_handoff,
    continuation_argv,
    continuation_prompt,
    recovery_brief,
    render_continuation_command,
)


@dataclass(frozen=True)
class SalvageResult:
    rescue_id: str
    rescue_dir: str
    handoff_path: str
    continuation_command: str
    continuation_argv: tuple[str, ...]
    source_sha256_before: str
    source_sha256_after: str
    original_untouched: bool

    def to_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_snapshot(path: str | Path) -> dict[str, object]:
    """Capture hash and stat evidence in a bounded streaming pass."""

    source = Path(path)
    before = source.stat()
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    after = source.stat()
    return {
        "sha256": digest.hexdigest(),
        "size": size,
        "mtime_ns": int(after.st_mtime_ns),
        "stable": (before.st_size == after.st_size and before.st_mtime_ns == after.st_mtime_ns and before.st_ino == after.st_ino),
    }


def salvage_session(
    session_path: str | Path,
    parsed: Any,
    doctor_status: str,
    findings: list[str],
    rescue_root: str | Path,
    fork: bool,
) -> SalvageResult:
    if not fork:
        raise ValueError("PoC salvage requires --fork; in-place recovery is forbidden")
    source = Path(session_path).resolve()
    source_snapshot_before = file_snapshot(source)
    if not source_snapshot_before["stable"]:
        raise RuntimeError("source rollout mutated while taking initial snapshot")
    source_before = str(source_snapshot_before["sha256"])
    metadata = getattr(parsed, "session_metadata", {}) or {}
    cwd = metadata.get("cwd") if isinstance(metadata, dict) else None
    git_state = None
    if cwd:
        try:
            git_state = inspect_git_state(cwd)
        except GitStateError:
            git_state = None
    source_id = metadata.get("session_id") if isinstance(metadata, dict) else source.stem
    journal_entries, _partial = read_entries(rescue_root, source_id or source.stem)
    if git_state and journal_entries:
        latest = journal_entries[-1]
        expected = {
            "worktree": latest.get("worktree"),
            "head_sha": latest.get("head_sha"),
            "diff_hash": latest.get("diff_hash"),
            "changed_files": latest.get("changed_files"),
        }
        conflicts = compare_git_state(expected, git_state)
        if conflicts:
            doctor_status = "REPO_STATE_DIVERGED"
            findings = ["REPO_STATE_DIVERGED", *[item for item in findings if item != "REPO_STATE_DIVERGED"]]
    source_snapshot_after_parse = file_snapshot(source)
    if not source_snapshot_after_parse["stable"] or source_snapshot_after_parse["sha256"] != source_before:
        # Do not emit a handoff based on a moving source.  The caller can retry
        # once the rollout has become quiescent; no source mutation is made.
        raise RuntimeError("source rollout mutated during salvage; refusing to create handoff")
    handoff = build_handoff(str(source), parsed, git_state, journal_entries, doctor_status, findings)
    handoff["source_snapshot"] = {
        "sha256": source_before,
        "size": source_snapshot_before["size"],
        "mtime_ns": source_snapshot_before["mtime_ns"],
        "stable": True,
        "evidence_refs": [
            {"source": "filesystem", "locator": str(source), "digest": source_before, "note": "stable read-only source snapshot"}
        ],
    }
    # Take the final source snapshot immediately before publishing any rescue
    # artifact.  A mutation observed during parsing/building must not produce
    # a handoff that looks complete.  The post-publish check below remains a
    # second read-only guard for races that happen while writing rescue files.
    source_snapshot_before_write = file_snapshot(source)
    if (
        not source_snapshot_before_write["stable"]
        or source_snapshot_before_write["sha256"] != source_before
        or source_snapshot_before_write["size"] != source_snapshot_before["size"]
        or source_snapshot_before_write["mtime_ns"] != source_snapshot_before["mtime_ns"]
    ):
        raise RuntimeError("source rollout mutated before rescue publication; refusing to create handoff")
    provisional_brief = recovery_brief(handoff)
    provisional_prompt = continuation_prompt(Path("handoff.v1.json"))
    rescue_id, rescue_dir = write_rescue(Path(rescue_root), handoff, provisional_brief, provisional_prompt)
    handoff_path = rescue_dir / "handoff.v1.json"
    # Regenerate the bounded prompt with its exact absolute handoff path. This file is
    # outside the content-addressed handoff and does not change the rescue id.
    from .artifacts import atomic_write

    atomic_write(rescue_dir / "CONTINUATION_PROMPT.md", continuation_prompt(handoff_path).encode("utf-8"))
    source_snapshot_after = file_snapshot(source)
    source_after = str(source_snapshot_after["sha256"])
    if not source_snapshot_after["stable"] or source_after != source_before:
        # The source was changed after the handoff was constructed.  Keep the
        # immutable artifact for forensics, but verification will fail closed
        # against the saved snapshot evidence.
        handoff["source_snapshot"]["stable"] = False
    argv = continuation_argv(handoff_path, handoff["session"].get("cwd") or source.parent)
    command = render_continuation_command(argv)
    return SalvageResult(
        rescue_id=rescue_id,
        rescue_dir=str(rescue_dir),
        handoff_path=str(handoff_path),
        continuation_command=command,
        continuation_argv=argv,
        source_sha256_before=source_before,
        source_sha256_after=source_after,
        original_untouched=source_before == source_after,
    )
