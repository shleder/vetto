from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path


@dataclass
class StorageReport:
    total_sessions: int = 0
    active_sessions: int = 0
    archived_sessions: int = 0
    total_logical_bytes: int = 0
    active_bytes: int = 0
    archived_bytes: int = 0
    total_records: int = 0
    total_turns: int = 0
    total_tool_calls: int = 0
    total_tool_output_bytes: int = 0
    total_compacted_records: int = 0
    total_inline_image_bytes: int = 0
    total_inline_image_count: int = 0
    size_buckets: dict[str, int] = field(default_factory=dict)
    largest_sessions: list[dict[str, Any]] = field(default_factory=list)
    anomalous_growth_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_text(self) -> str:
        lines = [
            "Codex Session Store Storage Summary\n",
            f"Total Sessions: {self.total_sessions} ({self.active_sessions} active, {self.archived_sessions} archived)",
            f"Total Logical Storage: {self.total_logical_bytes:,} bytes ({self.active_bytes:,} active, {self.archived_bytes:,} archived)",
            f"Total Records: {self.total_records:,} (Turns: {self.total_turns:,}, Tool Calls: {self.total_tool_calls:,}, Compactions: {self.total_compacted_records:,})",
            f"Tool Output Contribution: {self.total_tool_output_bytes:,} bytes",
            f"Inline Images / Data-URLs: {self.total_inline_image_bytes:,} bytes ({self.total_inline_image_count} images)",
            "\nSize Distribution:",
        ]
        for bucket, count in self.size_buckets.items():
            lines.append(f"  {bucket:<15}: {count}")
        if self.largest_sessions:
            lines.append("\nLargest Sessions:")
            for s in self.largest_sessions[:5]:
                lines.append(f"  {s['session_id']} — {s['size_bytes']:,} bytes ({s['status']})")
        if self.anomalous_growth_indicators:
            lines.append("\nAnomalous Growth Indicators:")
            for ind in self.anomalous_growth_indicators:
                lines.append(f"  * {ind}")
        return "\n".join(lines)


def analyze_storage(
    codex_home: Path | str | None = None,
    limit_sessions: int = 1000,
) -> StorageReport:
    home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"
    report = StorageReport(
        size_buckets={
            "< 100 KB": 0,
            "100 KB - 1 MB": 0,
            "1 MB - 10 MB": 0,
            "10 MB - 16 MB": 0,
            "> 16 MB": 0,
        }
    )

    if not home.exists():
        return report

    session_files: list[Path] = []
    for pat in ("sessions/*.jsonl", "archived_sessions/*.jsonl", "subagents/*.jsonl", "*.jsonl"):
        session_files.extend(home.glob(pat))

    unique_paths = sorted(list({p.resolve() for p in session_files}))[:limit_sessions]
    session_summaries: list[dict[str, Any]] = []
    oversized_session_count = 0

    for path in unique_paths:
        ev = collect_session_evidence(path, codex_home=home, max_scan_lines=5000)
        report.total_sessions += 1
        if ev.is_archived:
            report.archived_sessions += 1
            report.archived_bytes += ev.size_bytes
        else:
            report.active_sessions += 1
            report.active_bytes += ev.size_bytes

        report.total_logical_bytes += ev.size_bytes
        report.total_records += ev.rollout.total_lines
        report.total_turns += ev.rollout.turn_count
        report.total_tool_calls += ev.rollout.tool_call_count
        report.total_tool_output_bytes += ev.rollout.tool_output_bytes
        report.total_compacted_records += ev.rollout.compaction_count
        report.total_inline_image_bytes += ev.rollout.inline_image_bytes
        report.total_inline_image_count += ev.rollout.inline_image_count

        if ev.size_bytes < 100 * 1024:
            report.size_buckets["< 100 KB"] += 1
        elif ev.size_bytes < 1024 * 1024:
            report.size_buckets["100 KB - 1 MB"] += 1
        elif ev.size_bytes < 10 * 1024 * 1024:
            report.size_buckets["1 MB - 10 MB"] += 1
        elif ev.size_bytes < 16 * 1024 * 1024:
            report.size_buckets["10 MB - 16 MB"] += 1
        else:
            report.size_buckets["> 16 MB"] += 1

        if (
            "OVERSIZED_RECORD" in ev.findings
            or "OVERSIZED_PAYLOAD" in ev.findings
            or "VALID_BUT_OVERSIZED" in ev.findings
        ):
            oversized_session_count += 1

        session_summaries.append({
            "session_id": ev.session_id,
            "path": ev.session_path,
            "size_bytes": ev.size_bytes,
            "status": ev.status,
            "turns": ev.rollout.turn_count,
        })

    session_summaries.sort(key=lambda s: s["size_bytes"], reverse=True)
    report.largest_sessions = session_summaries[:10]

    if oversized_session_count > 0:
        report.anomalous_growth_indicators.append(
            f"{oversized_session_count} session(s) contain oversized records exceeding bounded reader thresholds."
        )
    if report.total_inline_image_bytes > 50 * 1024 * 1024:
        report.anomalous_growth_indicators.append(
            f"High inline image / Data URL footprint: {report.total_inline_image_bytes:,} bytes across {report.total_inline_image_count} images."
        )
    if report.total_tool_output_bytes > report.total_logical_bytes * 0.7 and report.total_logical_bytes > 10 * 1024 * 1024:
        report.anomalous_growth_indicators.append(
            "Tool outputs account for >70% of total store volume; consider compaction or selective salvaging."
        )

    return report
