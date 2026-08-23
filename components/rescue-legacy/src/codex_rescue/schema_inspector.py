from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .transcript import _read_line_bounded, MAX_RECORD_BYTES

KNOWN_RECORD_KINDS = {
    "task_started",
    "turn_started",
    "user_message",
    "agent_message",
    "assistant_message",
    "tool_call",
    "function_call",
    "local_shell_call",
    "tool_search_call",
    "web_search_call",
    "image_generation_call",
    "tool_output",
    "function_call_output",
    "tool_search_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "reasoning",
    "compaction",
    "context_compaction",
    "task_complete",
    "task_completed",
    "turn_complete",
    "abort",
    "interruption",
}


@dataclass
class SchemaReport:
    """Codex Rescue schema coverage report.

    NOTE: The 'rollout_generations' values (such as 'standard_linear_v1', 'ordinal_sequenced_v1',
    'paginated_v2') are Codex Rescue's internal diagnostic classification tags used to recognize
    structural layout traits. They are NOT official upstream Codex schema identifiers.
    """
    rollout_generations: list[str] = field(default_factory=list)
    sqlite_db_versions: list[int] = field(default_factory=list)
    recognized_record_kinds: list[str] = field(default_factory=list)
    unknown_record_kinds: list[str] = field(default_factory=list)
    schema_coverage_pct: float = 100.0
    opaque_or_unsupported_sections: list[str] = field(default_factory=list)
    compatibility_warnings: list[str] = field(default_factory=list)
    status: str = "SUPPORTED"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_text(self) -> str:
        lines = [
            "Codex Rescue Schema Compatibility Report\n",
            "Note: Generation labels reflect Rescue-internal structural traits, not upstream Codex schema names.\n",
            f"Status: {self.status} (Coverage: {self.schema_coverage_pct:.1f}%)",
            f"Rollout Trait Generations: {', '.join(self.rollout_generations) or 'none detected'}",
            f"SQLite DB Generations: {', '.join(str(v) for v in self.sqlite_db_versions) or 'none detected'}",
            f"Recognized Record Kinds ({len(self.recognized_record_kinds)}): {', '.join(sorted(self.recognized_record_kinds))}",
        ]
        if self.unknown_record_kinds:
            lines.append(f"UNKNOWN Record Kinds ({len(self.unknown_record_kinds)}): {', '.join(sorted(self.unknown_record_kinds))}")
        if self.opaque_or_unsupported_sections:
            lines.append(f"Opaque/Unsupported Sections: {', '.join(self.opaque_or_unsupported_sections)}")
        if self.compatibility_warnings:
            lines.append("\nCompatibility Warnings:")
            for w in self.compatibility_warnings:
                lines.append(f"  * {w}")
        return "\n".join(lines)


def inspect_schemas(
    codex_home: Path | str | None = None,
    session_files: list[Path] | None = None,
) -> SchemaReport:
    report = SchemaReport()
    home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"

    recognized = set()
    unknown = set()
    generations = set()

    if home.exists():
        for db_name in ("state.db", "codex.db", "threads.db"):
            db_path = home / db_name
            if db_path.exists():
                try:
                    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=1.0)
                    cur = conn.cursor()
                    cur.execute("PRAGMA user_version")
                    uv = cur.fetchone()
                    if uv and uv[0] not in report.sqlite_db_versions:
                        report.sqlite_db_versions.append(uv[0])
                    conn.close()
                except Exception:
                    pass

    files_to_check = session_files or []
    if not files_to_check and home.exists():
        files_to_check = list(home.glob("sessions/*.jsonl"))[:20]

    for sf in files_to_check:
        try:
            with open(sf, "rb") as f:
                for _ in range(100):
                    line_bytes, oversized, _ = _read_line_bounded(f, MAX_RECORD_BYTES)
                    if not line_bytes:
                        break
                    if oversized:
                        section_msg = f"Session {sf.name} contains oversized record(s) exceeding bounded reader limit ({MAX_RECORD_BYTES} bytes)"
                        if section_msg not in report.opaque_or_unsupported_sections:
                            report.opaque_or_unsupported_sections.append(section_msg)
                        warn_msg = f"Oversized record encountered in {sf.name}; schema inspection is bounded"
                        if warn_msg not in report.compatibility_warnings:
                            report.compatibility_warnings.append(warn_msg)
                        continue
                    try:
                        record = json.loads(line_bytes.decode("utf-8", errors="ignore"))
                    except Exception:
                        warn_msg = f"Malformed/unparseable JSON record encountered in {sf.name}"
                        if warn_msg not in report.compatibility_warnings:
                            report.compatibility_warnings.append(warn_msg)
                        continue

                    rtype = record.get("type") or record.get("event")
                    if rtype:
                        if rtype in KNOWN_RECORD_KINDS:
                            recognized.add(rtype)
                        else:
                            unknown.add(rtype)

                    if "ordinal" in record or "seq" in record:
                        generations.add("ordinal_sequenced_v1")
                    if "page" in record or "pagination" in record:
                        generations.add("paginated_v2")
        except Exception:
            pass

    if not generations:
        generations.add("standard_linear_v1")

    report.rollout_generations = sorted(list(generations))
    report.recognized_record_kinds = sorted(list(recognized))
    report.unknown_record_kinds = sorted(list(unknown))

    total_kinds = len(recognized) + len(unknown)
    if total_kinds > 0:
        report.schema_coverage_pct = round((len(recognized) / total_kinds) * 100, 1)

    if unknown or report.opaque_or_unsupported_sections:
        report.status = "PARTIALLY_UNSUPPORTED"
        if unknown:
            report.compatibility_warnings.append(
                f"Detected {len(unknown)} unmodeled record kind(s): {', '.join(sorted(unknown))}. Treat diagnostics as incomplete."
            )

    return report
