from __future__ import annotations

import json
import platform
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from . import __version__
from .diff import diff_session
from .evidence import collect_session_evidence
from .redact import audit_privacy, sanitize_path
from .schema_inspector import inspect_schemas
from .timeline import build_timeline


@dataclass
class DiagnosticBundle:
    tool_version: str = f"codex-rescue {__version__}"
    platform: str = platform.platform()
    session_id: str = ""
    evidence_summary: dict[str, Any] = field(default_factory=dict)
    findings: list[str] = field(default_factory=list)
    state_diff: dict[str, Any] = field(default_factory=dict)
    timeline: dict[str, Any] = field(default_factory=dict)
    schema_info: dict[str, Any] = field(default_factory=dict)
    redaction_audit_passed: bool = False
    redaction_report: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def generate_support_bundle(
    session_path: Path | str,
    output_bundle_path: Path | str | None = None,
    codex_home: Path | str | None = None,
) -> tuple[DiagnosticBundle, str | None]:
    """Generate a sanitized support bundle using strict allowlist-first field extraction

    Layer 1: Strict schema allowlist extracts only safe metadata (counts, sizes, event kinds,
             ordinals, byte offsets, hashes, boolean flags, error codes). No arbitrary text payloads.
    Layer 2: Regex privacy audit scans entire JSON document for credentials, tokens, or unmasked home paths.
    """
    path = Path(session_path).resolve()
    ev = collect_session_evidence(path, codex_home=codex_home)
    diff = diff_session(path, codex_home=codex_home)
    tl = build_timeline(path, max_events=200)
    schema = inspect_schemas(codex_home=codex_home, session_files=[path])

    # Allowlist-only projection for timeline events:
    safe_events = [
        {
            "index": e.index,
            "event_type": e.event_type,
            "ordinal": e.ordinal,
            "timestamp": e.timestamp,
            "byte_offset": e.byte_offset,
            "record_size": e.record_size,
        }
        for e in tl.events[:50]
    ]

    # Allowlist-only projection for divergences:
    safe_divergences = [
        {
            "dimension": d.dimension,
            "divergence_type": d.divergence_type,
            "note": d.note,
        }
        for d in diff.divergences
    ]

    bundle = DiagnosticBundle(
        session_id=str(ev.session_id),
        evidence_summary={
            "session_path": sanitize_path(ev.session_path),
            "is_archived": bool(ev.is_archived),
            "size_bytes": int(ev.size_bytes),
            "total_lines": int(ev.rollout.total_lines),
            "turn_count": int(ev.rollout.turn_count),
            "tool_call_count": int(ev.rollout.tool_call_count),
            "compaction_count": int(ev.rollout.compaction_count),
            "last_ordinal": ev.rollout.last_ordinal,
            "status": str(ev.status),
            "confidence": str(ev.confidence),
        },
        findings=[str(f) for f in ev.findings],
        state_diff={
            "session_id": str(diff.session_id),
            "is_aligned": bool(diff.is_aligned),
            "divergences": safe_divergences,
            "summary": str(diff.summary),
        },
        timeline={
            "total_events": int(tl.total_events),
            "events_sample": safe_events,
        },
        schema_info={
            "rollout_generations": [str(g) for g in schema.rollout_generations],
            "sqlite_db_versions": [int(v) for v in schema.sqlite_db_versions],
            "recognized_record_kinds": [str(k) for k in schema.recognized_record_kinds],
            "unknown_record_kinds": [str(k) for k in schema.unknown_record_kinds],
            "schema_coverage_pct": float(schema.schema_coverage_pct),
            "status": str(schema.status),
        },
    )

    bundle_dict = bundle.to_dict()
    violations = audit_privacy(bundle_dict)
    bundle.redaction_report = violations
    bundle.redaction_audit_passed = (len(violations) == 0)

    if not bundle.redaction_audit_passed:
        raise ValueError(f"Privacy Redaction Audit FAILED: Detected {len(violations)} leakage violation(s): {violations}")

    target_file = Path(output_bundle_path) if output_bundle_path else Path(f"support_bundle_{ev.session_id}.json")
    target_file.write_text(json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    return bundle, str(target_file)


def audit_bundle_file(bundle_path: Path | str) -> list[str]:
    p = Path(bundle_path)
    if not p.exists():
        return [f"File not found: {bundle_path}"]
    try:
        content = json.loads(p.read_text(encoding="utf-8"))
    except Exception as e:
        return [f"Invalid JSON in artifact: {e}"]
    return audit_privacy(content)
