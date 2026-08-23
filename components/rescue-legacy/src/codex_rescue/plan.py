from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path

PLAN_SCHEMA_VERSION = 1


@dataclass
class RecoveryPlan:
    plan_schema_version: int = PLAN_SCHEMA_VERSION
    session_reference: str = ""
    session_path: str = ""
    source_sha256: str = ""
    source_mtime: float = 0.0
    source_size_bytes: int = 0
    finding: str = "HEALTHY"
    canonical_source: str = "FILESYSTEM_ROLLOUT"
    derived_state_affected: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    proposed_operations: list[dict[str, Any]] = field(default_factory=list)
    source_files_modified: bool = False
    backup_required: bool = True
    verify_steps: list[str] = field(default_factory=list)
    rollback_strategy: str = "RESTORE_FROM_BACKUP"
    confidence: str = "HIGH"
    is_applicable: bool = False
    refusal_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "PLAN_SCHEMA_VERSION": self.plan_schema_version,
            "SESSION_REFERENCE": self.session_reference,
            "SESSION_PATH": self.session_path,
            "SOURCE_SHA256": self.source_sha256,
            "SOURCE_MTIME": self.source_mtime,
            "SOURCE_SIZE_BYTES": self.source_size_bytes,
            "FINDING": self.finding,
            "CANONICAL_SOURCE": self.canonical_source,
            "DERIVED_STATE_AFFECTED": self.derived_state_affected,
            "PRECONDITIONS": self.preconditions,
            "PROPOSED_OPERATIONS": self.proposed_operations,
            "SOURCE_FILES_MODIFIED": "YES" if self.source_files_modified else "NO",
            "BACKUP_REQUIRED": "YES" if self.backup_required else "NO",
            "VERIFY_STEPS": self.verify_steps,
            "ROLLBACK_STRATEGY": self.rollback_strategy,
            "CONFIDENCE": self.confidence,
            "IS_APPLICABLE": self.is_applicable,
        }
        if self.refusal_reason:
            d["REFUSAL_REASON"] = self.refusal_reason
        return d

    def render_text(self) -> str:
        lines = [
            f"Recovery Plan for Session: {self.session_reference}",
            f"Plan Schema Version: {self.plan_schema_version}",
            f"Finding: {self.finding} (Confidence: {self.confidence})",
            f"Canonical Source: {self.canonical_source}",
            f"Source Files Modified: {'YES' if self.source_files_modified else 'NO (SOURCE PRESERVED)'}",
            f"Applicable for Safe Apply: {'YES' if self.is_applicable else 'NO'}",
        ]
        if self.refusal_reason:
            lines.append(f"\nREFUSAL REASON: {self.refusal_reason}")
        if self.preconditions:
            lines.append("\nPreconditions:")
            for p in self.preconditions:
                lines.append(f"  * {p}")
        if self.proposed_operations:
            lines.append("\nProposed Operations:")
            for op in self.proposed_operations:
                lines.append(f"  * [{op.get('target', 'derived_state')}] {op.get('description', '')}")
        if self.verify_steps:
            lines.append("\nVerification Steps:")
            for v in self.verify_steps:
                lines.append(f"  1. {v}")
        return "\n".join(lines)


def generate_recovery_plan(
    session_path: Path | str,
    codex_home: Path | str | None = None,
) -> RecoveryPlan:
    path = Path(session_path).resolve()
    ev = collect_session_evidence(path, codex_home=codex_home)

    sha = ""
    if path.exists():
        try:
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            pass

    plan = RecoveryPlan(
        session_reference=ev.session_id,
        session_path=ev.session_path,
        source_sha256=sha,
        source_mtime=ev.mtime,
        source_size_bytes=ev.size_bytes,
        finding=", ".join(ev.findings) if ev.findings else ev.status,
        confidence=ev.confidence,
    )

    plan.source_files_modified = False

    if ev.writer.lock_present and ev.writer.is_alive:
        plan.is_applicable = False
        plan.refusal_reason = "ACTIVE_WRITER_CONFLICT: Session is locked by a running process. Refusing mutation."
        plan.preconditions.append("Active writer must be stopped before generating executable repairs.")
        return plan

    if (
        "INCOMPLETE_SCAN" in ev.findings
        or "SCAN_READ_ERROR" in ev.findings
        or "OVERSIZED_RECORD" in ev.findings
        or "OVERSIZED_PAYLOAD" in ev.findings
        or "VALID_BUT_OVERSIZED" in ev.findings
    ):
        plan.is_applicable = False
        plan.refusal_reason = f"INCOMPLETE_OR_OVERSIZED_SOURCE: Source rollout contains unparsed or oversized records ({plan.finding}). Refusing mutation to prevent data loss."
        return plan

    if "UNINDEXED_SESSION" in ev.findings or (ev.sqlite.present and not ev.sqlite.thread_found):
        if ev.status not in ("HEALTHY", "WARNINGS") or "MALFORMED_JSONL" in ev.findings or "TRUNCATED_JSONL" in ev.findings:
            plan.is_applicable = False
            plan.refusal_reason = f"SOURCE_NOT_HEALTHY: Rollout has findings '{plan.finding}'. Cannot reindex damaged rollout into SQLite without repair."
            return plan

        plan.derived_state_affected.append("sqlite_thread_inventory")
        plan.preconditions.extend([
            f"Source rollout sha256 matches {sha[:16]}...",
            "SQLite state DB passes PRAGMA integrity_check",
            "No active writer lock present",
        ])
        plan.proposed_operations.append({
            "target": "sqlite_state_db",
            "type": "reindex_thread",
            "description": "Insert thread row into SQLite inventory referencing intact canonical rollout.",
        })
        plan.verify_steps.extend([
            "Query SQLite state DB for thread ID matching session reference",
            "Run 'codex-rescue doctor' on session to confirm alignment",
        ])
        plan.is_applicable = True
        return plan

    if "WEDGED_PROJECTION" in ev.findings or "CURSOR_DIVERGENCE" in ev.findings or (ev.sqlite.projection_cursor is not None and ev.rollout.last_ordinal is not None and ev.sqlite.projection_cursor != ev.rollout.last_ordinal):
        if ev.status in ("HEALTHY", "WARNINGS") and "MALFORMED_JSONL" not in ev.findings and "TRUNCATED_JSONL" not in ev.findings:
            plan.derived_state_affected.append("sqlite_projection_cursor")
            plan.preconditions.extend([
                f"Source rollout sha256 matches {sha[:16]}...",
                "SQLite state DB passes PRAGMA integrity_check",
                "No active writer lock present",
                "Source rollout contains verified monotonic ordinals",
            ])
            plan.proposed_operations.append({
                "target": "sqlite_state_db",
                "type": "realign_projection_cursor",
                "description": f"Update SQLite projection cursor to match canonical rollout boundary ordinal ({ev.rollout.last_ordinal}).",
            })
            plan.verify_steps.extend([
                "Query SQLite projection cursor to confirm match with rollout boundary",
                "Run 'codex-rescue diff' to verify zero remaining divergences",
            ])
            plan.is_applicable = True
            return plan
        else:
            plan.is_applicable = False
            plan.refusal_reason = f"SOURCE_ROLLOUT_UNSOUND: Canonical rollout has findings '{plan.finding}'. Refusing derived projection update."
            return plan

    if ev.status == "HEALTHY":
        plan.is_applicable = False
        plan.refusal_reason = "SESSION_ALREADY_HEALTHY: No repair required."
        return plan

    if "TRUNCATED_JSONL" in ev.findings or "MALFORMED_JSONL" in ev.findings:
        plan.derived_state_affected.append("fork_salvage_workspace")
        plan.preconditions.extend([
            f"Source rollout sha256 matches {sha[:16]}...",
            "Destination directory is writable",
            "Original rollout remains strictly unmodified",
        ])
        plan.proposed_operations.append({
            "target": "salvage_target",
            "type": "create_clean_fork",
            "description": "Extract durable prior history into a clean forked session rollout without altering original.",
        })
        plan.verify_steps.extend([
            "Verify all preserved prior records parse cleanly in new forked session",
            "Verify original source file SHA-256 remains unchanged",
        ])
        plan.is_applicable = True
        return plan

    plan.is_applicable = False
    plan.refusal_reason = f"NO_PROVABLY_SAFE_REPAIR: Available evidence model cannot guarantee deterministic safe repair for findings '{plan.finding}'."
    return plan
