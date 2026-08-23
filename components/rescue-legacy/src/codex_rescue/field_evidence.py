from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from typing import Any

from .transcript import ParseResult, TranscriptEvent


MAX_FIELD_EVIDENCE = 32
_WSL_MNT_RE = re.compile(r"^/mnt/([A-Za-z])(?:/(.*))?$")
_WINDOWS_DRIVE_RE = re.compile(r"^([A-Za-z]):[\\/](.*)$")


@dataclass(frozen=True)
class WorkspacePortabilityReport:
    saved_cwd: str | None
    runtime_platform: str
    saved_path_family: str
    mismatch: bool
    confidence: str
    reason: str
    suggested_native_cwd: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "saved_cwd": self.saved_cwd,
            "runtime_platform": self.runtime_platform,
            "saved_path_family": self.saved_path_family,
            "mismatch": self.mismatch,
            "confidence": self.confidence,
            "reason": self.reason,
            "suggested_native_cwd": self.suggested_native_cwd,
        }


@dataclass
class FieldEvidenceReport:
    retained_event_count: int = 0
    retained_event_bytes: int = 0
    interrupted_input_boundary_count: int = 0
    interrupted_input_boundaries: list[dict[str, Any]] = field(default_factory=list)
    interrupted_input_statement: str = "No conservative interrupted-input persistence gap observed in the retained event window"

    def to_dict(self) -> dict[str, Any]:
        return {
            "retained_event_count": self.retained_event_count,
            "retained_event_bytes": self.retained_event_bytes,
            "interrupted_input_boundary_count": self.interrupted_input_boundary_count,
            "interrupted_input_boundaries": self.interrupted_input_boundaries,
            "interrupted_input_statement": self.interrupted_input_statement,
        }


def inspect_workspace_portability(cwd: object) -> WorkspacePortabilityReport:
    runtime = "windows" if os.name == "nt" else "posix"
    if not isinstance(cwd, str) or not cwd.strip():
        return WorkspacePortabilityReport(
            saved_cwd=None,
            runtime_platform=runtime,
            saved_path_family="unknown",
            mismatch=False,
            confidence="unknown",
            reason="no persisted working directory is available",
        )

    value = cwd.strip()
    wsl_match = _WSL_MNT_RE.match(value)
    windows_match = _WINDOWS_DRIVE_RE.match(value)

    if wsl_match:
        drive = wsl_match.group(1).upper()
        suffix = (wsl_match.group(2) or "").replace("/", "\\")
        suggested = f"{drive}:\\{suffix}" if suffix else f"{drive}:\\"
        if runtime == "windows":
            return WorkspacePortabilityReport(
                saved_cwd=value,
                runtime_platform=runtime,
                saved_path_family="wsl_mnt",
                mismatch=True,
                confidence="strong",
                reason="persisted WSL /mnt/<drive> cwd is being inspected by a Windows-native runtime",
                suggested_native_cwd=suggested,
            )
        return WorkspacePortabilityReport(
            saved_cwd=value,
            runtime_platform=runtime,
            saved_path_family="wsl_mnt",
            mismatch=False,
            confidence="bounded",
            reason="persisted cwd uses a WSL-style /mnt/<drive> path on a POSIX runtime",
        )

    if windows_match:
        drive = windows_match.group(1).lower()
        suffix = windows_match.group(2).replace("\\", "/")
        suggested = f"/mnt/{drive}/{suffix}" if suffix else f"/mnt/{drive}"
        if runtime == "posix":
            return WorkspacePortabilityReport(
                saved_cwd=value,
                runtime_platform=runtime,
                saved_path_family="windows_drive",
                mismatch=True,
                confidence="bounded",
                reason="persisted Windows drive cwd is being inspected by a POSIX runtime",
                suggested_native_cwd=suggested,
            )
        return WorkspacePortabilityReport(
            saved_cwd=value,
            runtime_platform=runtime,
            saved_path_family="windows_drive",
            mismatch=False,
            confidence="strong",
            reason="persisted cwd and runtime both use Windows-native path semantics",
        )

    return WorkspacePortabilityReport(
        saved_cwd=value,
        runtime_platform=runtime,
        saved_path_family="posix" if value.startswith("/") else "other",
        mismatch=False,
        confidence="bounded",
        reason=f"no explicit cross-platform cwd mismatch recognized on {sys.platform}",
    )


def _outer_type(event: TranscriptEvent) -> str:
    return str(event.type or "unknown")


def analyze_field_evidence(parsed: ParseResult) -> FieldEvidenceReport:
    """Analyze already-retained bounded events; never re-scan the rollout.

    This deliberately avoids a third sequential pass over multi-gigabyte field
    rollouts.  The interrupted-input check is therefore scoped to the parser's
    bounded retained event window.  It never claims to reconstruct prompt text
    that was not durably persisted.
    """

    result = FieldEvidenceReport(
        retained_event_count=len(parsed.events),
        retained_event_bytes=parsed.retained_event_bytes,
    )
    turn_start_offset: int | None = None
    turn_context_seen = False
    durable_user_input_seen = False

    for event in parsed.events:
        outer_type = _outer_type(event)
        payload = event.payload if isinstance(event.payload, dict) else {}
        payload_type = str(payload.get("type") or "").lower()

        if outer_type == "event_msg" and payload_type == "task_started":
            turn_start_offset = event.offset
            turn_context_seen = False
            durable_user_input_seen = False
            continue

        if turn_start_offset is None:
            continue

        if outer_type == "turn_context":
            turn_context_seen = True

        # event_msg/user_message is the strongest durable marker for the
        # submitted prompt.  A post-turn_context response_item user message is
        # accepted as a compatibility fallback. Earlier role=user records may
        # be injected context and therefore do not suppress a finding alone.
        if outer_type == "event_msg" and payload_type == "user_message":
            durable_user_input_seen = True
        elif (
            outer_type == "response_item"
            and payload_type == "message"
            and str(payload.get("role") or "").lower() == "user"
            and turn_context_seen
        ):
            durable_user_input_seen = True

        if outer_type == "event_msg" and payload_type in {
            "turn_aborted",
            "turn_interrupted",
        }:
            if not durable_user_input_seen:
                result.interrupted_input_boundary_count += 1
                if len(result.interrupted_input_boundaries) < MAX_FIELD_EVIDENCE:
                    result.interrupted_input_boundaries.append(
                        {
                            "task_started_offset": turn_start_offset,
                            "terminal_offset": event.offset,
                            "terminal_type": payload_type,
                            "reason": "turn ended before a conservative durable submitted-user-input marker was observed",
                        }
                    )
            turn_start_offset = None
            turn_context_seen = False
            durable_user_input_seen = False
        elif outer_type == "event_msg" and payload_type in {
            "task_complete",
            "task_completed",
            "turn_complete",
            "turn_completed",
            "turn_failed",
        }:
            turn_start_offset = None
            turn_context_seen = False
            durable_user_input_seen = False

    if result.interrupted_input_boundary_count:
        result.interrupted_input_statement = (
            "At least one retained turn ended before a conservative durable submitted-user-input marker; "
            "missing prompt text cannot be reconstructed from absent rollout data"
        )
    return result


__all__ = [
    "FieldEvidenceReport",
    "WorkspacePortabilityReport",
    "analyze_field_evidence",
    "inspect_workspace_portability",
]
