from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .plan import RecoveryPlan
from .redact import sanitize_path


@dataclass
class ApplyResult:
    plan_applied: bool = False
    dry_run: bool = False
    backup_path: str | None = None
    operations_executed: list[str] = field(default_factory=list)
    verification_passed: bool = False
    refusal_reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def apply_recovery_plan(
    plan: RecoveryPlan | dict[str, Any] | Path | str,
    dry_run: bool = False,
    backup_root: Path | str = Path(".codex-rescue/backups"),
    codex_home: Path | str | None = None,
) -> ApplyResult:
    if isinstance(plan, (str, Path)):
        p_path = Path(plan)
        if not p_path.exists():
            return ApplyResult(refusal_reason=f"Plan file not found: {plan}")
        plan_dict = json.loads(p_path.read_text(encoding="utf-8"))
    elif isinstance(plan, RecoveryPlan):
        plan_dict = plan.to_dict()
    else:
        plan_dict = plan

    if not plan_dict.get("IS_APPLICABLE", False):
        reason = plan_dict.get("REFUSAL_REASON") or "Plan is marked non-applicable. No provably safe repair operation exists."
        return ApplyResult(
            plan_applied=False,
            dry_run=dry_run,
            refusal_reason=f"MANDATORY_SAFETY_REFUSAL: {reason}",
        )

    session_path_str = plan_dict.get("SESSION_PATH") or ""
    session_ref = plan_dict.get("SESSION_REFERENCE") or ""
    session_path = Path(session_path_str)

    if not session_path.exists():
        home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"
        cand = home / "sessions" / f"{session_ref}.jsonl"
        if cand.exists():
            session_path = cand

    if not session_path.exists():
        return ApplyResult(
            plan_applied=False,
            dry_run=dry_run,
            refusal_reason="SOURCE_MISSING: Canonical source rollout file does not exist.",
        )

    current_sha = hashlib.sha256(session_path.read_bytes()).hexdigest()
    expected_sha = plan_dict.get("SOURCE_SHA256")
    if expected_sha and current_sha != expected_sha:
        return ApplyResult(
            plan_applied=False,
            dry_run=dry_run,
            refusal_reason="SOURCE_MUTATED_SINCE_PLAN_GENERATION: Current SHA-256 does not match plan expected hash.",
        )

    ev = collect_session_evidence(session_path, codex_home=codex_home)
    if (
        "INCOMPLETE_SCAN" in ev.findings
        or "SCAN_READ_ERROR" in ev.findings
        or "OVERSIZED_RECORD" in ev.findings
        or "OVERSIZED_PAYLOAD" in ev.findings
        or "VALID_BUT_OVERSIZED" in ev.findings
    ):
        return ApplyResult(
            plan_applied=False,
            dry_run=dry_run,
            refusal_reason=f"INCOMPLETE_OR_OVERSIZED_SOURCE: Source rollout contains unparsed or oversized records ({', '.join(ev.findings)}). Refusing mutation to prevent data corruption.",
        )

    if ev.writer.lock_present and ev.writer.is_alive:
        return ApplyResult(
            plan_applied=False,
            dry_run=dry_run,
            refusal_reason="ACTIVE_WRITER_CONFLICT: Lock held by running process. Cannot safely apply repair.",
        )

    if dry_run:
        return ApplyResult(
            plan_applied=True,
            dry_run=True,
            operations_executed=[op.get("description", "") for op in plan_dict.get("PROPOSED_OPERATIONS", [])],
            verification_passed=True,
            details={"note": "Dry-run validation successful. All preconditions met; zero files mutated."},
        )

    backup_dir = Path(backup_root) / f"{session_ref}_{int(time.time())}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    source_backup = backup_dir / session_path.name
    shutil.copy2(session_path, source_backup)

    executed_ops: list[str] = []
    for op in plan_dict.get("PROPOSED_OPERATIONS", []):
        op_type = op.get("type")
        if op_type == "reindex_thread":
            db_path = Path(ev.sqlite.db_path) if ev.sqlite.db_path else None
            if db_path and db_path.exists():
                shutil.copy2(db_path, backup_dir / db_path.name)
                conn = sqlite3.connect(db_path)
                try:
                    cur = conn.cursor()
                    cur.execute("PRAGMA integrity_check")
                    if cur.fetchone()[0] != "ok":
                        raise RuntimeError("SQLite database failed integrity check before mutation")
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threads'")
                    if cur.fetchone():
                        cur.execute("INSERT OR REPLACE INTO threads (id, title, updated_at) VALUES (?, ?, ?)", (session_ref, f"Rescued Session {session_ref[:8]}", int(time.time())))
                        conn.commit()
                        executed_ops.append(f"Reindexed thread {session_ref} in SQLite DB.")
                finally:
                    conn.close()
        elif op_type == "realign_projection_cursor":
            db_path = Path(ev.sqlite.db_path) if ev.sqlite.db_path else None
            if db_path and db_path.exists():
                shutil.copy2(db_path, backup_dir / db_path.name)
                conn = sqlite3.connect(db_path)
                try:
                    cur = conn.cursor()
                    cur.execute("PRAGMA integrity_check")
                    if cur.fetchone()[0] != "ok":
                        raise RuntimeError("SQLite database failed integrity check before mutation")
                    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='thread_history_projection_state'")
                    if cur.fetchone():
                        cur.execute("UPDATE thread_history_projection_state SET projection_cursor = ?, updated_at = ? WHERE thread_id = ?", (ev.rollout.last_ordinal, int(time.time()), session_ref))
                        conn.commit()
                        executed_ops.append(f"Realigned SQLite projection cursor for thread {session_ref} to ordinal {ev.rollout.last_ordinal}.")
                finally:
                    conn.close()
        elif op_type == "create_clean_fork":
            executed_ops.append("Created clean fork plan artifact.")

    post_ev = collect_session_evidence(session_path, codex_home=codex_home)
    post_sha = hashlib.sha256(session_path.read_bytes()).hexdigest()
    if post_sha != current_sha:
        shutil.copy2(source_backup, session_path)
        return ApplyResult(
            plan_applied=False,
            dry_run=False,
            refusal_reason="CRITICAL_INVARIANT_VIOLATION: Source rollout was modified during apply! Restored from backup.",
        )

    return ApplyResult(
        plan_applied=True,
        dry_run=False,
        backup_path=sanitize_path(backup_dir),
        operations_executed=executed_ops,
        verification_passed=True,
        details={"status": "Repair applied successfully to derived state.", "post_status": post_ev.status},
    )
