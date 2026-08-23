from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from .gitstate import GitStateError, inspect_git_state
from .journal import JournalEntry, append_entry, utc_timestamp


HOOK_EVENTS = (
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
    "PermissionRequest", "PreCompact", "PostCompact", "Stop",
    "SessionEnd", "SubagentStart", "SubagentStop",
)

_SECRET_PATTERNS = (
    (re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bnpm_[A-Za-z0-9_-]{16,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{16,}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)(https?://)([^/\s:@]+):([^@\s/]+)@"), r"\1[REDACTED_USER]:[REDACTED]@"),
    (re.compile(r'''(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret)\s*(?:\\?["'])?\s*[:=]\s*(?:\\?["'])?)[^\s,;"'}]+'''), r"\1[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED_TOKEN]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.DOTALL), "[REDACTED_PRIVATE_KEY]"),
)


def _bounded(value: Any, limit: int = 500) -> str | None:
    if value is None:
        return None
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    text = re.sub(r"data:[^;]+;base64,[A-Za-z0-9+/=]+", "[REDACTED_INLINE_PAYLOAD]", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;]+", r"\1[REDACTED]", text)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    if len(text) > limit:
        digest = hashlib.sha256(text.encode("utf-8", "surrogateescape")).hexdigest()[:16]
        return f"{text[:limit]}… [bounded sha256:{digest}]"
    return text


def capture_hook(event: str, root: Path, raw: dict[str, Any]) -> Path:
    cwd = raw.get("cwd")
    git_state = None
    if cwd:
        try:
            git_state = inspect_git_state(cwd)
        except GitStateError:
            git_state = None
    transcript_path = raw.get("transcript_path")
    transcript_offset = None
    transcript_hash = None
    if transcript_path and Path(transcript_path).is_file():
        transcript = Path(transcript_path)
        transcript_offset = transcript.stat().st_size
        digest = hashlib.sha256()
        with transcript.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        transcript_hash = digest.hexdigest()
    tool_use_id = raw.get("tool_use_id")
    tool_name = raw.get("tool_name")
    pending_action = None
    completed_actions: tuple[dict[str, Any], ...] = ()
    commands: tuple[dict[str, Any], ...] = ()
    if event == "PreCompact":
        pending_action = {"type": "compaction", "trigger": raw.get("trigger"), "confidence": "verified"}
    elif event == "PreToolUse":
        pending_action = {
            "type": "tool_call", "tool_use_id": tool_use_id, "tool_name": tool_name,
            "input": _bounded(raw.get("tool_input")), "confidence": "verified",
        }
    elif event == "PermissionRequest":
        pending_action = {
            "type": "permission", "tool_use_id": tool_use_id, "tool_name": tool_name,
            "input": _bounded(raw.get("tool_input")), "confidence": "verified",
        }
    elif event == "PostToolUse":
        result = {
            "type": "tool_result", "tool_use_id": tool_use_id, "tool_name": tool_name,
            "input": _bounded(raw.get("tool_input")),
            "response": _bounded(raw.get("tool_response")), "confidence": "verified",
        }
        completed_actions = (result,)
        if tool_name in {"Bash", "shell_command", "exec_command"}:
            commands = (result,)

    lifecycle = {
        key: raw.get(key)
        for key in ("trigger", "reason", "turn_id", "agent_id", "agent_type")
        if raw.get(key) is not None
    }
    if pending_action is None and lifecycle:
        pending_action = {"type": "lifecycle", **lifecycle, "confidence": "verified"}

    entry = JournalEntry(
        version=1,
        session_id=str(raw.get("session_id") or "unknown"),
        timestamp=utc_timestamp(),
        event=event,
        cwd=cwd,
        worktree=git_state.worktree if git_state else None,
        base_sha=None,
        head_sha=git_state.head_sha if git_state else None,
        diff_hash=git_state.diff_hash if git_state else None,
        changed_files=git_state.changed_files if git_state else (),
        last_user_prompt=_bounded(raw.get("prompt"), 1000) if event == "UserPromptSubmit" else None,
        completed_actions=completed_actions,
        pending_action=pending_action,
        commands=commands,
        transcript_offset=transcript_offset,
        transcript_hash=transcript_hash,
    )
    return append_entry(root, entry)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("event", choices=HOOK_EVENTS)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        raw = json.load(sys.stdin)
        capture_hook(args.event, args.root, raw)
    except Exception as exc:  # hooks must fail open and never block Codex
        print(f"codex-rescue hook warning: {exc}", file=sys.stderr)
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
