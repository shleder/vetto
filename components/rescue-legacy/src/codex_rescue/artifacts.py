from __future__ import annotations

import hashlib
import errno
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any


HANDOFF_SCHEMA = "codex-rescue/handoff.v1"
RESCUE_ID_RE = re.compile(r"^[0-9a-f]{24}$")


def canonical_json(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _replace_retryable(exc: OSError) -> bool:
    """Identify transient Windows sharing/permission failures for os.replace."""

    return (
        getattr(exc, "winerror", None) in {5, 32}
        or getattr(exc, "errno", None) in {errno.EACCES, errno.EEXIST, errno.EBUSY}
    )


def _atomic_replace(temp: Path, target: Path, attempts: int = 6) -> None:
    """Publish a complete temp file, retrying only bounded sharing failures."""

    for attempt in range(max(1, attempts)):
        try:
            os.replace(temp, target)
            return
        except OSError as exc:
            if not _replace_retryable(exc) or attempt + 1 >= max(1, attempts):
                raise
            time.sleep(min(0.05, 0.001 * (2**attempt)))


def atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    # A PID-only temporary name collides when two salvage requests run in the
    # same process.  NamedTemporaryFile gives each writer an exclusive inode;
    # os.replace then publishes the complete file atomically.
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temp = Path(temp_name)
    try:
        offset = 0
        while offset < len(data):
            offset += os.write(fd, data[offset:])
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        _atomic_replace(temp, path)
    finally:
        try:
            temp.unlink()
        except FileNotFoundError:
            pass
    if os.name != "nt":
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _evidence_errors(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        return [f"{label} must contain at least one evidence reference"]
    errors: list[str] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            errors.append(f"{label}[{index}] is not an object")
            continue
        for key in ("source", "locator", "note"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                errors.append(f"{label}[{index}].{key} is missing")
    return errors


def validate_handoff(handoff: object, *, strict: bool = True) -> list[str]:
    """Validate the versioned handoff without coercing or guessing fields.

    Older alpha artifacts did not carry a schema marker.  They remain
    readable for forensic compatibility when ``strict`` is false; all Rescue
    v1 artifacts carry ``HANDOFF_SCHEMA`` and are checked fail-closed.
    """

    if not isinstance(handoff, dict):
        return ["handoff must be an object"]
    if not strict and handoff.get("schema") != HANDOFF_SCHEMA:
        return []
    errors: list[str] = []
    if handoff.get("schema") != HANDOFF_SCHEMA:
        errors.append(f"unsupported handoff schema: {handoff.get('schema')!r}")
    if handoff.get("version") != 1:
        errors.append("handoff version must be 1")
    if handoff.get("schema_version") != 1:
        errors.append("handoff schema_version must be 1")
    for key in ("session", "goal", "repository", "progress", "tool_state", "transcript"):
        if not isinstance(handoff.get(key), dict):
            errors.append(f"{key} must be an object")
    session = handoff.get("session") if isinstance(handoff.get("session"), dict) else {}
    for key in ("source_id", "source_ref", "cwd"):
        if not isinstance(session.get(key), str) or not session[key].strip():
            errors.append(f"session.{key} is missing")
    errors.extend(_evidence_errors(session.get("evidence_refs"), "session.evidence_refs"))
    repository = handoff.get("repository") if isinstance(handoff.get("repository"), dict) else {}
    if repository.get("confidence") not in {"verified", "reconstructed", "unknown"}:
        errors.append("repository.confidence is invalid")
    if repository.get("confidence") == "verified":
        for key in ("root", "worktree", "head_sha", "diff_hash"):
            if not isinstance(repository.get(key), str) or not repository[key].strip():
                errors.append(f"repository.{key} is missing")
        if not isinstance(repository.get("changed_files"), list) or not all(isinstance(item, str) for item in repository.get("changed_files", [])):
            errors.append("repository.changed_files must be a list of paths")
    errors.extend(_evidence_errors(repository.get("evidence_refs"), "repository.evidence_refs"))
    goal = handoff.get("goal") if isinstance(handoff.get("goal"), dict) else {}
    if goal.get("confidence") not in {"verified", "reconstructed", "unknown"}:
        errors.append("goal.confidence is invalid")
    errors.extend(_evidence_errors(goal.get("evidence_refs"), "goal.evidence_refs"))
    transcript = handoff.get("transcript") if isinstance(handoff.get("transcript"), dict) else {}
    digest = transcript.get("hash")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", digest):
        errors.append("transcript.hash must be a SHA-256 hex digest")
    size = transcript.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        errors.append("transcript.size must be a non-negative integer")
    errors.extend(_evidence_errors(transcript.get("evidence_refs"), "transcript.evidence_refs"))
    if not isinstance(transcript.get("corruption_class"), str) or not transcript["corruption_class"].strip():
        errors.append("transcript.corruption_class is missing")
    tool_state = handoff.get("tool_state") if isinstance(handoff.get("tool_state"), dict) else {}
    if "unfinished_action" not in tool_state:
        errors.append("tool_state.unfinished_action is missing")
    if tool_state.get("confidence") not in {"verified", "reconstructed", "unknown"}:
        errors.append("tool_state.confidence is invalid")
    if not isinstance(handoff.get("findings"), list):
        errors.append("findings must be a list")
    if not isinstance(handoff.get("tests"), list):
        errors.append("tests must be a list")
    if handoff.get("overall_confidence") not in {"verified", "reconstructed", "unknown"}:
        errors.append("overall_confidence is invalid")
    return errors


def write_rescue(root: Path, handoff: dict[str, Any], brief: str, continuation: str) -> tuple[str, Path]:
    errors = validate_handoff(handoff, strict=handoff.get("schema") == HANDOFF_SCHEMA)
    if errors:
        raise ValueError("invalid handoff: " + "; ".join(errors))
    handoff_bytes = canonical_json(handoff)
    rescue_id = hashlib.sha256(handoff_bytes).hexdigest()[:24]
    rescue_dir = root / "rescues" / rescue_id
    atomic_write(rescue_dir / "handoff.v1.json", handoff_bytes + b"\n")
    atomic_write(rescue_dir / "RECOVERY_BRIEF.md", brief.encode("utf-8"))
    atomic_write(rescue_dir / "CONTINUATION_PROMPT.md", continuation.encode("utf-8"))
    return rescue_id, rescue_dir


def load_handoff(root: Path, rescue_id: str) -> dict[str, Any]:
    if not isinstance(rescue_id, str) or not RESCUE_ID_RE.fullmatch(rescue_id):
        raise ValueError("invalid rescue id")
    path = root / "rescues" / rescue_id / "handoff.v1.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    errors = validate_handoff(data, strict=data.get("schema") == HANDOFF_SCHEMA if isinstance(data, dict) else True)
    if errors:
        raise ValueError("invalid handoff: " + "; ".join(errors))
    actual_id = hashlib.sha256(canonical_json(data)).hexdigest()[:24]
    if actual_id != rescue_id:
        raise ValueError(f"handoff hash mismatch: expected {rescue_id}, actual {actual_id}")
    return data
