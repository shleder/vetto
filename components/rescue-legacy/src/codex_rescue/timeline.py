from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .evidence import collect_session_evidence
from .redact import sanitize_path
from .transcript import _read_line_bounded, MAX_RECORD_BYTES


@dataclass
class TimelineEvent:
    index: int
    event_type: str
    observed: bool
    timestamp: str | None = None
    ordinal: int | None = None
    byte_offset: int = 0
    record_size: int = 0
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SessionTimeline:
    session_id: str
    session_path: str
    events: list[TimelineEvent] = field(default_factory=list)
    total_events: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "session_path": self.session_path,
            "total_events": len(self.events),
            "events": [e.to_dict() for e in self.events],
        }


def build_timeline(
    session_path: Path | str,
    max_events: int = 5000,
) -> SessionTimeline:
    path = Path(session_path).resolve()
    session_id = path.stem
    if session_id.endswith(".jsonl"):
        session_id = session_id[:-6]

    timeline = SessionTimeline(
        session_id=session_id,
        session_path=sanitize_path(path),
    )

    if not path.exists():
        return timeline

    offset = 0
    event_idx = 0

    try:
        with open(path, "rb") as f:
            while event_idx < max_events:
                line_offset = offset
                line_bytes, oversized, total_len = _read_line_bounded(f, MAX_RECORD_BYTES)
                if not line_bytes:
                    break
                line_len = total_len
                offset += line_len
                complete_line = line_bytes.endswith(b"\n")
                has_nul = b"\x00" in line_bytes

                if oversized:
                    classification = "VALID_BUT_OVERSIZED" if (complete_line and not has_nul) else ("TRUNCATED" if not complete_line else "MALFORMED")
                    timeline.events.append(
                        TimelineEvent(
                            index=event_idx,
                            event_type="oversized_record_boundary",
                            observed=True,
                            byte_offset=line_offset,
                            record_size=line_len,
                            details={
                                "classification": classification,
                                "reason": "record exceeds bounded processing limit",
                            },
                        )
                    )
                    event_idx += 1
                    continue

                if has_nul:
                    timeline.events.append(
                        TimelineEvent(
                            index=event_idx,
                            event_type="malformed_record_boundary",
                            observed=True,
                            byte_offset=line_offset,
                            record_size=line_len,
                            details={"error": "embedded_nul_byte"},
                        )
                    )
                    event_idx += 1
                    continue

                try:
                    record = json.loads(line_bytes.decode("utf-8", errors="ignore"))
                except Exception:
                    timeline.events.append(
                        TimelineEvent(
                            index=event_idx,
                            event_type="truncated_record_boundary" if not complete_line else "malformed_record_boundary",
                            observed=True,
                            byte_offset=line_offset,
                            record_size=line_len,
                            details={"error": "json_decode_failure"},
                        )
                    )
                    event_idx += 1
                    continue

                rtype = record.get("type") or record.get("event") or "unknown_event"
                ts = record.get("timestamp") or record.get("created_at") or record.get("time")
                ord_val = record.get("ordinal") or record.get("seq") or record.get("idx")

                evt_type = "unclassified_record"
                observed = True
                details: dict[str, Any] = {}

                if rtype in ("turn_started", "user_message", "turn"):
                    evt_type = "turn_started"
                    details["is_user_initiated"] = True
                elif rtype in ("tool_call", "function_call", "call"):
                    evt_type = "tool_call_started"
                    tool_name = record.get("name") or record.get("tool")
                    if tool_name:
                        details["tool_name"] = str(tool_name)[:64]
                elif rtype in ("tool_output", "function_call_output", "result"):
                    evt_type = "tool_output_persisted"
                    tool_name = record.get("name") or record.get("tool")
                    if tool_name:
                        details["tool_name"] = str(tool_name)[:64]
                    details["payload_bytes"] = len(str(record.get("output") or ""))
                elif rtype in ("compaction", "context_compaction"):
                    evt_type = "compaction"
                elif rtype in ("task_complete", "task_completed", "turn_complete"):
                    evt_type = "task_complete"
                elif rtype in ("abort", "interruption", "cancel"):
                    evt_type = "abort_interruption"
                elif rtype in ("migration", "schema_migration"):
                    evt_type = "migration_boundary"
                else:
                    evt_type = f"record_{rtype}"

                timeline.events.append(
                    TimelineEvent(
                        index=event_idx,
                        event_type=evt_type,
                        observed=observed,
                        timestamp=ts if isinstance(ts, str) else None,
                        ordinal=ord_val if isinstance(ord_val, int) else None,
                        byte_offset=line_offset,
                        record_size=line_len,
                        details=details,
                    )
                )
                event_idx += 1

    except Exception:
        timeline.events.append(
            TimelineEvent(
                index=event_idx,
                event_type="stream_error_boundary",
                observed=False,
                details={"error": "unhandled_read_error"},
            )
        )

    timeline.total_events = len(timeline.events)
    return timeline
