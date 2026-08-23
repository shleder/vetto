from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .alpha5 import Alpha5RolloutDiagnostics, ProjectionReport, scan_rollout_alpha5
from .field_evidence import (
    FieldEvidenceReport,
    WorkspacePortabilityReport,
    analyze_field_evidence,
    inspect_workspace_portability,
)
from .gitstate import GitStateError, inspect_git_state
from .migration_consistency import MigrationConsistencyReport, inspect_migration_consistency
from .projection import inspect_projection_parity
from .schema_compat import SchemaCompatibilityReport, apply_schema_compatibility
from .thread_identity import THREAD_IDENTITY_CONFLICT, ThreadIdentityEvidence, resolve_thread_identity
from .thread_store import ThreadStoreReport, inspect_thread_store
from .transcript import ParseResult, parse_transcript


SEVERITY = [
    "UNKNOWN_CORRUPTION",
    "CORRUPTED_TOOL_CALL",
    "MALFORMED_RECORD",
    "TRUNCATED_TRANSCRIPT",
    "OVERSIZED_PAYLOAD",
    "VALID_BUT_OVERSIZED",
    "INTERLEAVED_WRITERS",
    "INVALID_PERSISTED_ITEM_ID",
    "UNKNOWN_OPERATIONAL_SCHEMA",
    "PROJECTION_STATE_UNKNOWN",
    "WEDGED_PROJECTION",
    "PERSISTED_PAGINATED_ORDINAL_REUSE",
    "ORDINAL_ANALYSIS_INCOMPLETE",
    "ACTIVE_WRITE_UNCERTAIN",
    "INCOMPLETE_ROLLOUT",
    "UNFINISHED_TOOL_CALL",
    "COMPACTION_STATE_LOSS",
    "REPO_STATE_DIVERGED",
    "SUBAGENT_HISTORY_BOUNDARY_SUSPECT",
    "THREAD_NAME_METADATA_DIVERGED",
    "INTERRUPTED_INPUT_NOT_DURABLE",
    "WORKSPACE_CONTEXT_MISMATCH",
    "THREAD_IDENTITY_CONFLICT",
    "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE",
    "HEALTHY",
]


@dataclass
class DoctorResult:
    session: str
    status: str
    findings: list[str]
    transcript: ParseResult
    repository: dict[str, Any]
    alpha5: Alpha5RolloutDiagnostics
    projection: ProjectionReport
    schema_compatibility: SchemaCompatibilityReport
    field_evidence: FieldEvidenceReport
    workspace_portability: WorkspacePortabilityReport
    migration_consistency: MigrationConsistencyReport
    thread_store: ThreadStoreReport
    source_integrity: dict[str, Any]
    thread_identity: ThreadIdentityEvidence

    def to_dict(self) -> dict[str, Any]:
        return {
            "session": self.session,
            "status": self.status,
            "findings": self.findings,
            "source_integrity": self.source_integrity,
            "thread_identity": self.thread_identity.to_dict(),
            "thread_store": self.thread_store.to_dict(),
            "transcript": self.transcript.to_dict(),
            "repository": self.repository,
            "alpha5": self.alpha5.to_dict(),
            "projection": self.projection.to_dict(),
            "schema_compatibility": self.schema_compatibility.to_dict(),
            "field_evidence": self.field_evidence.to_dict(),
            "workspace_portability": self.workspace_portability.to_dict(),
            "migration_consistency": self.migration_consistency.to_dict(),
        }


def _classify_git_error(exc: GitStateError) -> str:
    text = str(exc).lower()
    if "not a git repository" in text or "outside repository" in text:
        return "non_git_workspace"
    if "cwd does not exist" in text or "permission denied" in text or "access is denied" in text:
        return "inaccessible_repository"
    if "no such file or directory" in text or "not found" in text or "executable" in text:
        return "git_unavailable"
    return "git_unavailable_or_repository_inaccessible"


def _ordered_findings(findings: set[str]) -> list[str]:
    return sorted(findings, key=lambda item: SEVERITY.index(item) if item in SEVERITY else len(SEVERITY))


def doctor_session(path: str | Path, oversized_threshold: int = 1_000_000) -> DoctorResult:
    parsed = parse_transcript(path, oversized_threshold=oversized_threshold)
    schema_compatibility = apply_schema_compatibility(parsed)
    alpha5 = scan_rollout_alpha5(path)
    field_evidence = analyze_field_evidence(parsed)
    migration_consistency = inspect_migration_consistency(path, parsed)
    projection = inspect_projection_parity(path, parsed)
    source_findings: set[str] = set()
    if parsed.corruption_class:
        source_findings.add(parsed.corruption_class)
    if parsed.oversized_records or parsed.oversized_record_count > 0:
        source_findings.add("OVERSIZED_PAYLOAD")
        for rec in parsed.oversized_records:
            cls_name = rec.get("classification")
            if cls_name == "VALID_BUT_OVERSIZED":
                source_findings.add("VALID_BUT_OVERSIZED")
            elif cls_name == "MALFORMED":
                source_findings.add("MALFORMED_RECORD")
            elif cls_name == "TRUNCATED":
                source_findings.add("TRUNCATED_TRANSCRIPT")
    if alpha5.bounded_record_overflow_count > 0:
        source_findings.add("OVERSIZED_PAYLOAD")
        source_findings.add("VALID_BUT_OVERSIZED")
    if parsed.first_invalid_offset is not None and not parsed.corruption_class:
        source_findings.add("UNKNOWN_CORRUPTION")
    if parsed.operational_schema_issues or parsed.correlation_ambiguities:
        source_findings.add("UNKNOWN_OPERATIONAL_SCHEMA")
    if parsed.ordinal_mode not in {None, "legacy", "paginated"}:
        source_findings.add("UNKNOWN_OPERATIONAL_SCHEMA")
    if parsed.ordinal_reuse:
        source_findings.add("PERSISTED_PAGINATED_ORDINAL_REUSE")
    if parsed.ordinal_tracking_overflow:
        source_findings.add("ORDINAL_ANALYSIS_INCOMPLETE")
    if parsed.unfinished_tool_calls:
        source_findings.add("UNFINISHED_TOOL_CALL")
    if parsed.compaction_state_loss:
        source_findings.add("COMPACTION_STATE_LOSS")

    if alpha5.typed_id_violation_count:
        source_findings.add("INVALID_PERSISTED_ITEM_ID")
    if alpha5.interleaved_writer_evidence:
        source_findings.add("INTERLEAVED_WRITERS")
    if alpha5.source_changed_during_scan:
        source_findings.add("ACTIVE_WRITE_UNCERTAIN")
    if alpha5.empty_rollout or alpha5.header_only_rollout or (parsed.valid_record_count == 0 and parsed.source_size > 0):
        source_findings.add("INCOMPLETE_ROLLOUT")
    if alpha5.malformed_opaque_field_count:
        source_findings.add("UNKNOWN_OPERATIONAL_SCHEMA")

    if field_evidence.interrupted_input_boundary_count:
        source_findings.add("INTERRUPTED_INPUT_NOT_DURABLE")
    source_findings.update(migration_consistency.findings)

    if projection.status == "wedged":
        source_findings.add("WEDGED_PROJECTION")
    elif projection.status == "active_write":
        source_findings.add("ACTIVE_WRITE_UNCERTAIN")
    elif projection.status == "unknown" and parsed.ordinal_mode == "paginated":
        source_findings.add("PROJECTION_STATE_UNKNOWN")

    cwd = parsed.session_metadata.get("cwd")
    workspace_portability = inspect_workspace_portability(cwd)
    repository: dict[str, Any]
    if cwd:
        try:
            repository = inspect_git_state(cwd).to_dict()
            repository["classification"] = "git_available"
        except GitStateError as exc:
            repository = {
                "cwd": cwd,
                "error": str(exc),
                "confidence": "unknown",
                "classification": _classify_git_error(exc),
            }
    else:
        repository = {"cwd": None, "confidence": "unknown", "classification": "no_workspace"}
    repository["workspace_portability"] = workspace_portability.to_dict()

    if (
        workspace_portability.mismatch
        and repository.get("classification") in {
            "inaccessible_repository",
            "git_unavailable_or_repository_inaccessible",
        }
    ):
        source_findings.add("WORKSPACE_CONTEXT_MISMATCH")

    source_status = "HEALTHY" if not source_findings else next(
        (label for label in SEVERITY if label in source_findings),
        "UNKNOWN_CORRUPTION",
    )
    source_integrity = {
        "status": source_status,
        "findings": _ordered_findings(source_findings),
    }

    session_meta = parsed.session_metadata if parsed.session_metadata else None
    thread_identity = resolve_thread_identity(path, session_meta=session_meta)
    thread_store = inspect_thread_store(path, session_id=thread_identity.thread_id)

    findings = set(source_findings)
    findings.update(thread_store.findings)
    if thread_identity.conflict:
        findings.add(THREAD_IDENTITY_CONFLICT)
    if not findings:
        findings.add("HEALTHY")
    ordered = _ordered_findings(findings)
    status = next((label for label in SEVERITY if label in findings), ordered[0])
    return DoctorResult(
        str(Path(path).resolve()),
        status,
        ordered,
        parsed,
        repository,
        alpha5,
        projection,
        schema_compatibility,
        field_evidence,
        workspace_portability,
        migration_consistency,
        thread_store,
        source_integrity,
        thread_identity,
    )
