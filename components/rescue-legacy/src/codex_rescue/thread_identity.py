from __future__ import annotations

import ntpath
import os
import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

THREAD_IDENTITY_CONFLICT = "THREAD_IDENTITY_CONFLICT"
THREAD_IDENTITY_SESSION_META = "SESSION_META"
THREAD_IDENTITY_FILENAME = "FILENAME"
THREAD_IDENTITY_UNKNOWN = "UNKNOWN"
THREAD_IDENTITY_PROVEN = "PROVEN"
THREAD_IDENTITY_CONSISTENT = "CONSISTENT"

_UUID_TEXT = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_ROLLOUT_NAME_RE = re.compile(
    rf"^rollout-(?P<timestamp>\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}-\d{{2}}-\d{{2}})-"
    rf"(?P<thread_id>{_UUID_TEXT})(?:_(?P<rollout_id>{_UUID_TEXT}))?\.jsonl$"
)


@dataclass(frozen=True)
class RolloutFilenameIdentity:
    thread_id: str
    rollout_id: str
    timestamp: str
    filename: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ThreadIdentityEvidence:
    thread_id: str | None = None
    source: str = THREAD_IDENTITY_UNKNOWN
    confidence: str = THREAD_IDENTITY_UNKNOWN
    filename_thread_id: str | None = None
    filename_rollout_id: str | None = None
    metadata_thread_id: str | None = None
    metadata_session_id: str | None = None
    metadata_field: str | None = None
    conflict: bool = False
    reason: str = "thread identity is not safely resolvable"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _canonical_uuid(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not re.fullmatch(_UUID_TEXT, text):
        return None
    try:
        return str(UUID(text))
    except (ValueError, AttributeError):
        return None


def _metadata_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return _canonical_uuid(text) or text


def _basename(path: str | os.PathLike[str]) -> str:
    # ntpath handles Windows and POSIX separators even on a non-Windows host.
    return ntpath.basename(os.fspath(path).rstrip("/\\"))


def parse_rollout_filename(path: str | os.PathLike[str]) -> RolloutFilenameIdentity | None:
    """Parse the exact current Codex rollout filename grammar.

    Current upstream uses:
      rollout-YYYY-MM-DDTHH-MM-SS-<thread_id>.jsonl
      rollout-YYYY-MM-DDTHH-MM-SS-<thread_id>_<rollout_id>.jsonl

    For revert rollouts the first ID is the stable ThreadId and the second ID is
    the immutable RolloutId. Unknown/malformed/future forms fail closed.
    """
    filename = _basename(path)
    match = _ROLLOUT_NAME_RE.fullmatch(filename)
    if match is None:
        return None
    timestamp = match.group("timestamp")
    try:
        datetime.strptime(timestamp, "%Y-%m-%dT%H-%M-%S")
    except ValueError:
        return None
    thread_id = _canonical_uuid(match.group("thread_id"))
    rollout_id = _canonical_uuid(match.group("rollout_id") or match.group("thread_id"))
    if thread_id is None or rollout_id is None:
        return None
    return RolloutFilenameIdentity(
        thread_id=thread_id,
        rollout_id=rollout_id,
        timestamp=timestamp,
        filename=filename,
    )


def resolve_thread_identity(
    path: str | os.PathLike[str],
    *,
    session_meta: dict[str, Any] | None = None,
) -> ThreadIdentityEvidence:
    """Resolve logical Codex ThreadId without conflating it with a rollout path.

    Current `SessionMeta.id` is the authoritative persisted ThreadId. Current
    `SessionMeta.session_id` is a distinct SessionId, so when a canonical
    filename is available it is never substituted for ThreadId. A
    `session_id`-only non-canonical historical/synthetic envelope is retained as
    a compatibility fallback, but plain filename stems are never identities.
    """
    filename = parse_rollout_filename(path)
    filename_thread_id = filename.thread_id if filename else None
    filename_rollout_id = filename.rollout_id if filename else None

    meta = session_meta if isinstance(session_meta, dict) else None
    metadata_session_id = _metadata_text(meta.get("session_id")) if meta else None

    if meta is not None and "id" in meta:
        metadata_thread_id = _metadata_text(meta.get("id"))
        if metadata_thread_id is None:
            return ThreadIdentityEvidence(
                thread_id=None,
                source=THREAD_IDENTITY_UNKNOWN,
                confidence=THREAD_IDENTITY_UNKNOWN,
                filename_thread_id=filename_thread_id,
                filename_rollout_id=filename_rollout_id,
                metadata_thread_id=None,
                metadata_session_id=metadata_session_id,
                metadata_field="id",
                reason="recognized SessionMeta.id is empty or unusable",
            )
        if filename_thread_id is not None and metadata_thread_id != filename_thread_id:
            return ThreadIdentityEvidence(
                thread_id=None,
                source=THREAD_IDENTITY_UNKNOWN,
                confidence=THREAD_IDENTITY_UNKNOWN,
                filename_thread_id=filename_thread_id,
                filename_rollout_id=filename_rollout_id,
                metadata_thread_id=metadata_thread_id,
                metadata_session_id=metadata_session_id,
                metadata_field="id",
                conflict=True,
                reason="authoritative SessionMeta.id conflicts with canonical rollout filename ThreadId",
            )
        if filename_thread_id is not None:
            return ThreadIdentityEvidence(
                thread_id=metadata_thread_id,
                source=THREAD_IDENTITY_SESSION_META,
                confidence=THREAD_IDENTITY_CONSISTENT,
                filename_thread_id=filename_thread_id,
                filename_rollout_id=filename_rollout_id,
                metadata_thread_id=metadata_thread_id,
                metadata_session_id=metadata_session_id,
                metadata_field="id",
                reason="SessionMeta.id agrees with the canonical rollout filename ThreadId",
            )
        return ThreadIdentityEvidence(
            thread_id=metadata_thread_id,
            source=THREAD_IDENTITY_SESSION_META,
            confidence=THREAD_IDENTITY_PROVEN,
            filename_thread_id=None,
            filename_rollout_id=None,
            metadata_thread_id=metadata_thread_id,
            metadata_session_id=metadata_session_id,
            metadata_field="id",
            reason="SessionMeta.id provides the persisted ThreadId; filename is not canonical",
        )

    # Current SessionId is not ThreadId. Prefer a canonical filename whenever
    # the current ThreadId field is absent. This also keeps revert semantics
    # correct because the canonical parser selects the first ID before `_`.
    if filename_thread_id is not None:
        return ThreadIdentityEvidence(
            thread_id=filename_thread_id,
            source=THREAD_IDENTITY_FILENAME,
            confidence=THREAD_IDENTITY_PROVEN,
            filename_thread_id=filename_thread_id,
            filename_rollout_id=filename_rollout_id,
            metadata_thread_id=None,
            metadata_session_id=metadata_session_id,
            metadata_field="session_id" if meta is not None and "session_id" in meta else None,
            reason="canonical rollout filename provides ThreadId; SessionMeta.id is unavailable",
        )

    # Compatibility only: older/synthetic envelopes can contain session_id but
    # no current ThreadId field and no canonical current filename. This is
    # explicit metadata evidence, not path-stem inference.
    if meta is not None and "session_id" in meta and metadata_session_id is not None:
        return ThreadIdentityEvidence(
            thread_id=metadata_session_id,
            source=THREAD_IDENTITY_SESSION_META,
            confidence=THREAD_IDENTITY_PROVEN,
            metadata_session_id=metadata_session_id,
            metadata_field="session_id",
            reason="legacy session_id-only metadata retained as compatibility identity; no filename stem was used",
        )

    return ThreadIdentityEvidence(
        filename_thread_id=filename_thread_id,
        filename_rollout_id=filename_rollout_id,
        metadata_session_id=metadata_session_id,
        reason="no understood SessionMeta.id or canonical rollout filename ThreadId is available",
    )


__all__ = [
    "RolloutFilenameIdentity",
    "THREAD_IDENTITY_CONFLICT",
    "THREAD_IDENTITY_CONSISTENT",
    "THREAD_IDENTITY_FILENAME",
    "THREAD_IDENTITY_PROVEN",
    "THREAD_IDENTITY_SESSION_META",
    "THREAD_IDENTITY_UNKNOWN",
    "ThreadIdentityEvidence",
    "parse_rollout_filename",
    "resolve_thread_identity",
]
