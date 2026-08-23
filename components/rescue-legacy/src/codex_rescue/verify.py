from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .artifacts import load_handoff, validate_handoff
from .gitstate import GitStateError, compare_git_state, inspect_git_state


@dataclass(frozen=True)
class VerifyResult:
    status: str
    conflicts: tuple[str, ...]
    review_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "conflicts": list(self.conflicts),
            "review_reasons": list(self.review_reasons),
        }


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _first_value(*values: object) -> object | None:
    for value in values:
        if value is not None and value != "":
            return value
    return None


def _source_rollout_check(handoff: dict[str, Any]) -> tuple[list[str], list[str]]:
    """Re-check a saved source rollout without changing it.

    Handoffs written by early versions did not always retain a source path,
    digest, or byte size.  Missing metadata is therefore intentionally a
    no-op for compatibility.  When a path and saved evidence are present, a
    changed source is a hard divergence and an unavailable source requires
    review before continuation.
    """

    session = _mapping(handoff.get("session"))
    transcript = _mapping(handoff.get("transcript"))
    source = _mapping(handoff.get("source"))
    snapshot = _mapping(handoff.get("source_snapshot"))
    source_ref = _first_value(
        session.get("source_ref"),
        session.get("source_path"),
        source.get("path"),
        source.get("source_ref"),
        transcript.get("path"),
    )
    expected_hash = _first_value(
        transcript.get("hash"),
        transcript.get("sha256"),
        session.get("source_sha256"),
        session.get("source_hash"),
        source.get("sha256"),
        source.get("hash"),
    )
    expected_size = _first_value(
        transcript.get("size"),
        transcript.get("byte_size"),
        transcript.get("source_size"),
        session.get("source_size"),
        session.get("source_byte_size"),
        source.get("size"),
        source.get("byte_size"),
    )
    expected_mtime_ns = _first_value(snapshot.get("mtime_ns"))

    # An old handoff can contain only a logical source identifier.  Do not
    # mistake that identifier for a local path and break verification.
    if not isinstance(source_ref, (str, Path)):
        return [], []
    source_text = str(source_ref).strip()
    if not source_text or (expected_hash is None and expected_size is None):
        return [], []

    path = Path(source_text).expanduser()
    # Very old handoffs used a logical source id (for example ``"session-1"``)
    # in ``source_ref``.  Only path-shaped references can be rechecked; keep
    # those artifacts verifiable using their saved repository evidence.
    if (
        not path.is_absolute()
        and path.parent == Path(".")
        and path.suffix.lower() not in {
        ".jsonl",
        ".ndjson",
        ".json",
        }
    ):
        return [], []
    try:
        stat = path.stat()
        actual_size = int(stat.st_size)
        actual_hash = _sha256_file(path)
    except (OSError, ValueError) as exc:
        return [], [f"source rollout unavailable: {source_text} ({exc})"]

    conflicts: list[str] = []
    if expected_hash is not None:
        expected_hash_text = str(expected_hash).strip().lower()
        if expected_hash_text and expected_hash_text != actual_hash.lower():
            conflicts.append(
                f"source_sha256: expected {expected_hash_text}, actual {actual_hash}"
            )
    if expected_size is not None:
        try:
            expected_size_value = int(expected_size)
        except (TypeError, ValueError):
            return [], [f"saved source size is invalid: {expected_size!r}"]
        if expected_size_value != actual_size:
            conflicts.append(
                f"source_size: expected {expected_size_value}, actual {actual_size}"
            )
    if expected_mtime_ns is not None:
        try:
            expected_mtime_value = int(expected_mtime_ns)
        except (TypeError, ValueError):
            return conflicts, [f"saved source mtime is invalid: {expected_mtime_ns!r}"]
        if expected_mtime_value != int(stat.st_mtime_ns):
            conflicts.append(
                f"source_mtime_ns: expected {expected_mtime_value}, actual {int(stat.st_mtime_ns)}"
            )
    return conflicts, []


def verify_rescue(root: str | Path, rescue_id: str) -> VerifyResult:
    try:
        handoff = load_handoff(Path(root), rescue_id)
    except (OSError, ValueError, TypeError) as exc:
        return VerifyResult("REVIEW_REQUIRED", (), (f"handoff unavailable or invalid: {exc}",))

    # Legacy alpha artifacts had no schema marker.  Enforce the strict v1
    # contract whenever a v1 marker is present; retain read-only compatibility
    # for markerless forensic artifacts.
    schema_errors = validate_handoff(
        handoff,
        strict=isinstance(handoff, dict) and ("schema" in handoff or "schema_version" in handoff),
    )
    if schema_errors:
        return VerifyResult("REVIEW_REQUIRED", (), tuple(f"invalid v1 handoff: {item}" for item in schema_errors))

    repository = _mapping(handoff.get("repository"))
    session = _mapping(handoff.get("session"))
    cwd = session.get("cwd")
    if not cwd:
        return VerifyResult("REVIEW_REQUIRED", (), ("source cwd is unknown",))
    source_conflicts, source_review_reasons = _source_rollout_check(handoff)
    try:
        actual = inspect_git_state(cwd)
    except GitStateError as exc:
        reasons = tuple(source_review_reasons) + (str(exc),)
        return VerifyResult("REVIEW_REQUIRED", (), reasons)
    conflicts = compare_git_state(repository, actual)
    conflicts.extend(source_conflicts)
    if conflicts:
        return VerifyResult("STATE_DIVERGED", tuple(conflicts), ())
    reasons: list[str] = []
    reasons.extend(source_review_reasons)
    transcript = _mapping(handoff.get("transcript"))
    if transcript.get("compacted"):
        reasons.append("compaction was observed; continuation requires review")
    if transcript.get("compaction_state_loss"):
        reasons.append("compaction state-loss evidence requires review")
    if transcript.get("corrupted_tool_calls"):
        reasons.append("corrupted tool-call metadata requires review")
    if transcript.get("correlation_ambiguities"):
        reasons.append("tool call/output correlation is ambiguous")
    if transcript.get("operational_schema_issues"):
        reasons.append("unknown operational schema requires review")
    if transcript.get("ordinal_reuse"):
        reasons.append("persisted paginated ordinal reuse requires external projection/state review")
    if transcript.get("ordinal_tracking_overflow"):
        reasons.append("bounded persisted paginated ordinal scan cannot establish absence of later reuse")
    snapshot = _mapping(handoff.get("source_snapshot"))
    if snapshot.get("stable") is False:
        reasons.append("source rollout changed during salvage snapshot")
    unfinished = _mapping(handoff.get("tool_state")).get("unfinished_action")
    if unfinished:
        reasons.append("unfinished action requires inspection before replay")
    if handoff.get("overall_confidence") == "unknown":
        reasons.append("handoff contains load-bearing unknowns")
    if reasons:
        return VerifyResult("REVIEW_REQUIRED", (), tuple(reasons))
    return VerifyResult("SAFE_TO_CONTINUE", (), ())
