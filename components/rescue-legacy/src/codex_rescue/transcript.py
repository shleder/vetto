from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TranscriptEvent:
    offset: int
    end_offset: int
    type: str | None
    payload: dict[str, Any]


@dataclass
class ParseResult:
    path: str
    source_size: int = 0
    last_valid_offset: int = 0
    first_invalid_offset: int | None = None
    valid_record_count: int = 0
    record_types: Counter[str] = field(default_factory=Counter)
    oversized_records: list[dict[str, Any]] = field(default_factory=list)
    corruption_class: str | None = None
    recoverable_prefix: bool = True
    sha256: str = ""
    session_metadata: dict[str, Any] = field(default_factory=dict)
    events: list[TranscriptEvent] = field(default_factory=list)
    unfinished_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    compacted: bool = False
    operational_events_after_compaction: int = 0
    compaction_state_loss: bool = False
    compaction_loss_evidence: list[dict[str, Any]] = field(default_factory=list)
    malformed_tool_arguments: list[dict[str, Any]] = field(default_factory=list)
    corrupted_tool_calls: list[dict[str, Any]] = field(default_factory=list)
    # Correlation is deliberately conservative.  A repeated call id, a
    # family mismatch, or an output that cannot be tied to one call is an
    # ambiguity rather than evidence of completion.
    correlation_ambiguities: list[dict[str, Any]] = field(default_factory=list)
    operational_schema_issues: list[dict[str, Any]] = field(default_factory=list)
    oversized_record_count: int = 0
    correlation_overflow: bool = False
    unfinished_tool_call_count: int = 0
    record_type_overflow: bool = False
    compaction_evidence_overflow: bool = False
    retained_event_bytes: int = 0
    # In a paginated Codex rollout, a persisted physical record may carry a
    # u64 ordinal.  A repeated ordinal is a narrow rollout-local finding;
    # it is not proof of projection divergence, pagination failure, or
    # thread-history corruption.
    ordinal_mode: str | None = None
    ordinal_reuse: list[dict[str, Any]] = field(default_factory=list)
    ordinal_reuse_count: int = 0
    ordinal_tracking_overflow: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "source_size": self.source_size,
            "last_valid_offset": self.last_valid_offset,
            "first_invalid_offset": self.first_invalid_offset,
            "valid_record_count": self.valid_record_count,
            "record_types": dict(self.record_types),
            "oversized_records": self.oversized_records,
            "corruption_class": self.corruption_class,
            "recoverable_prefix": self.recoverable_prefix,
            "sha256": self.sha256,
            "session_metadata": self.session_metadata,
            "unfinished_tool_calls": self.unfinished_tool_calls,
            "compacted": self.compacted,
            "operational_events_after_compaction": self.operational_events_after_compaction,
            "compaction_state_loss": self.compaction_state_loss,
            "compaction_loss_evidence": self.compaction_loss_evidence,
            "malformed_tool_arguments": self.malformed_tool_arguments,
            "corrupted_tool_calls": self.corrupted_tool_calls,
            "correlation_ambiguities": self.correlation_ambiguities,
            "operational_schema_issues": self.operational_schema_issues,
            "oversized_record_count": self.oversized_record_count,
            "correlation_overflow": self.correlation_overflow,
            "unfinished_tool_call_count": self.unfinished_tool_call_count,
            "record_type_overflow": self.record_type_overflow,
            "compaction_evidence_overflow": self.compaction_evidence_overflow,
            "retained_event_bytes": self.retained_event_bytes,
            "ordinal_mode": self.ordinal_mode,
            "ordinal_reuse": self.ordinal_reuse,
            "ordinal_reuse_count": self.ordinal_reuse_count,
            "ordinal_tracking_overflow": self.ordinal_tracking_overflow,
        }


def _record_kind(record: dict[str, Any]) -> str:
    outer = str(record.get("type") or "unknown")
    payload = record.get("payload")
    inner = payload.get("type") if isinstance(payload, dict) else None
    return f"{outer}/{inner}" if inner else outer


def _safe_session_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = (
        "session_id", "id", "parent_thread_id", "timestamp", "cwd",
        "originator", "cli_version", "source", "thread_source",
        "model_provider", "history_mode", "context_window",
    )
    return {key: payload.get(key) for key in allowed if key in payload}


def _looks_like_large_inline_payload(line: bytes, record_kind: str, threshold: int) -> bool:
    if len(line) > threshold:
        return True
    # Small/medium data URLs are normal Codex records and must not make an
    # otherwise healthy session look damaged. Only flag an inline payload when
    # the record itself is materially large.
    payload_floor = max(256 * 1024, threshold // 2)
    if len(line) < payload_floor:
        return False
    return b"data:image" in line or b"base64" in line


def _call_data(event: TranscriptEvent) -> tuple[str | None, str | None, object | None]:
    payload = event.payload
    kind = payload.get("type")
    if kind in {"function_call", "custom_tool_call", "tool_search_call"}:
        return str(payload.get("call_id") or payload.get("id") or ""), str(payload.get("name") or "tool_call"), payload.get("arguments", payload.get("input"))
    return None, None, None


_CALL_FAMILIES = {"function_call", "custom_tool_call", "tool_search_call"}
_OUTPUT_FAMILIES = {
    "function_call_output": "function_call",
    "custom_tool_call_output": "custom_tool_call",
    "tool_search_output": "tool_search_call",
}
# mcp_tool_call_end is a current-format terminal record.  It carries the
# identity of an MCP call, but it is not itself a call or an output that this
# parser can safely correlate.  Recognize the record narrowly so a valid end
# marker is not reported as an unknown schema or fabricated as an unfinished
# call.
_KNOWN_OPERATIONAL_TYPES = _CALL_FAMILIES | set(_OUTPUT_FAMILIES) | {"mcp_tool_call_end"}
_OPERATIONAL_ENVELOPES = {"event_msg", "response_item"}
MAX_RECORD_BYTES = 8 * 1024 * 1024
MAX_RETAINED_FINDINGS = 128
MAX_CORRELATION_STATES = 1024
MAX_OCCURRENCES_PER_ID = 2
MAX_RECORD_TYPES = 1024
MAX_RETAINED_EVENT_BYTES = 256 * 1024
MAX_EVENT_TAIL_BYTES = 4 * 1024 * 1024
# Complete duplicate detection needs historical state.  Keep that state
# bounded; after the cap, adjacent duplicates remain detectable, while a
# later non-adjacent duplicate is explicitly unknown via the overflow flag.
# The cap covers the public real-style examples (about 55k ordinals) without
# allowing an arbitrarily large Python set to grow with the rollout.
MAX_ORDINAL_STATES = 65_536
MAX_U64 = (1 << 64) - 1
CORRUPTED_TOOL_NAME_SENTINEL = "<corrupted-tool-name>"


def _control_codepoints(value: str) -> list[int]:
    return sorted({
        ord(character)
        for character in value
        if ord(character) < 0x20 or ord(character) == 0x7F
    })


def _corrupted_tool_call_metadata(
    payload: dict[str, Any],
    offset: int,
) -> dict[str, Any] | None:
    """Return bounded evidence for control characters in a persisted tool name.

    The raw name is intentionally not copied into the diagnostic finding.  A
    malformed name is evidence of damaged history, not evidence of which tool
    the caller intended to invoke.
    """

    kind = payload.get("type")
    name = payload.get("name")
    if kind not in _CALL_FAMILIES or not isinstance(name, str):
        return None
    control_codepoints = _control_codepoints(name)
    if not control_codepoints:
        return None
    return {
        "offset": offset,
        "call_id": str(payload.get("call_id") or payload.get("id") or ""),
        "family": str(kind),
        "name_length": len(name),
        "control_codepoints": control_codepoints,
        "control_character_count": sum(
            1 for character in name
            if ord(character) < 0x20 or ord(character) == 0x7F
        ),
        "name_sha256": hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest(),
        "reason": "persisted tool-call name contains control characters",
    }


def _operational_schema_issue(payload: dict[str, Any], outer_type: object, offset: int) -> dict[str, Any] | None:
    """Return an issue for an operational envelope we cannot correlate.

    Ordinary future message types are intentionally tolerated.  A record
    advertising itself as a tool/call/output, or a future/event-named record
    with a stable identity in an operational envelope, must either use a
    known family or be treated as unknown evidence.
    """

    kind = payload.get("type")
    if outer_type in {"response_item", "event_msg"} and not isinstance(kind, str):
        return {
            "offset": offset,
            "outer_type": outer_type,
            "payload_type": None,
            "reason": "operational envelope has no payload type",
        }
    if not isinstance(kind, str):
        return None
    operational_identity = (
        payload.get("call_id")
        or (payload.get("id") if outer_type in _OPERATIONAL_ENVELOPES else None)
    )
    looks_operational = (
        kind in _KNOWN_OPERATIONAL_TYPES
        or kind.endswith("_call")
        or kind.endswith("_output")
        or "tool" in kind.lower()
        # A future/event-named record in a current operational envelope that
        # carries a stable identity materially participates in diagnosis even
        # when its type name does not advertise "call" or "tool".  Extra
        # metadata on a known record does not enter this path.
        or (
            bool(operational_identity)
            and (
                "event" in kind.lower()
                or kind.lower().startswith(("future_", "unknown_"))
            )
        )
    )
    if not looks_operational:
        return None
    if kind not in _KNOWN_OPERATIONAL_TYPES:
        return {"offset": offset, "outer_type": outer_type, "payload_type": kind, "reason": "unknown operational payload type"}
    call_id = payload.get("call_id") or payload.get("id")
    required_name = kind in _CALL_FAMILIES
    if not call_id:
        return {"offset": offset, "outer_type": outer_type, "payload_type": kind, "reason": "operational record has no call id"}
    if required_name and not payload.get("name"):
        return {"offset": offset, "outer_type": outer_type, "payload_type": kind, "reason": "tool call has no name"}
    return None


def _read_line_bounded(
    stream: Any,
    max_bytes: int = MAX_RECORD_BYTES,
    digest: Any | None = None,
) -> tuple[bytes, bool, int]:
    """Read one JSONL line without allowing an attacker-sized allocation.

    ``readline(size)`` caps the initial allocation; an oversized line is then
    drained in fixed chunks so hashing and offsets remain exact.
    """

    limit = max(1, int(max_bytes))
    line = stream.readline(limit + 1)
    if not line:
        return b"", False, 0
    if digest is not None:
        digest.update(line)
    total = len(line)
    if len(line) <= limit:
        return line, False, total
    oversized = True
    if line.endswith(b"\n"):
        return line, oversized, total
    ended_with_newline = False
    has_nul = b"\x00" in line
    while True:
        chunk = stream.readline(64 * 1024)
        if not chunk:
            break
        if b"\x00" in chunk:
            has_nul = True
        total += len(chunk)
        if digest is not None:
            digest.update(chunk)
        if chunk.endswith(b"\n"):
            ended_with_newline = True
            break
    if has_nul and b"\x00" not in line:
        line = line + b"\x00"
    if ended_with_newline and not line.endswith(b"\n"):
        line = line + b"\n"
    return line, oversized, total


def parse_transcript(
    path: str | Path,
    oversized_threshold: int = 1_000_000,
    max_events: int = 5000,
    max_record_bytes: int = MAX_RECORD_BYTES,
) -> ParseResult:
    source = Path(path).resolve()
    result = ParseResult(path=str(source), source_size=source.stat().st_size)
    digest = hashlib.sha256()
    calls: dict[str, list[dict[str, Any]]] = {}
    outputs: dict[str, list[dict[str, Any]]] = {}
    retired_ids: set[str] = set()
    retired_order: deque[str] = deque(maxlen=MAX_CORRELATION_STATES)
    last_compaction_index: int | None = None
    offset = 0
    event_tail: deque[TranscriptEvent] = deque()
    event_tail_sizes: deque[int] = deque()
    event_tail_bytes = 0
    invalid_seen = False
    ordinal_positions: dict[int, int] = {}
    last_ordinal: int | None = None
    last_ordinal_offset: int | None = None

    with source.open("rb") as stream:
        while True:
            start = offset
            line, line_oversized, consumed = _read_line_bounded(stream, max_record_bytes, digest)
            if not line:
                break
            offset += consumed
            complete_line = line.endswith(b"\n")
            has_nul = b"\x00" in line
            if line_oversized:
                if result.first_invalid_offset is None:
                    result.first_invalid_offset = start
                result.oversized_record_count += 1
                if has_nul:
                    record_classification = "MALFORMED"
                    corruption_class = "MALFORMED_RECORD"
                elif not complete_line:
                    record_classification = "TRUNCATED"
                    corruption_class = "TRUNCATED_TRANSCRIPT"
                else:
                    record_classification = "VALID_BUT_OVERSIZED"
                    corruption_class = "OVERSIZED_PAYLOAD"

                if len(result.oversized_records) < MAX_RETAINED_FINDINGS:
                    result.oversized_records.append(
                        {
                            "start_offset": start,
                            "end_offset": offset,
                            "byte_length": consumed,
                            "record_type": "unknown",
                            "classification": record_classification,
                            "reason": (
                                "record exceeds bounded processing limit (unterminated)"
                                if not complete_line
                                else "record exceeds bounded processing limit"
                            ),
                        }
                    )
                result.corruption_class = result.corruption_class or corruption_class
                # The remainder of a bounded line was drained by the helper;
                # there is no safe payload to parse or retain.
                invalid_seen = True
                break
            if has_nul:
                if result.first_invalid_offset is None:
                    result.first_invalid_offset = start
                result.corruption_class = "MALFORMED_RECORD"
                invalid_seen = True
                break
            try:
                record = json.loads(line)
                if not isinstance(record, dict):
                    raise ValueError("record must be a JSON object")
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
                if result.first_invalid_offset is None:
                    result.first_invalid_offset = start
                result.corruption_class = "TRUNCATED_TRANSCRIPT" if not complete_line and not invalid_seen else "MALFORMED_RECORD"
                invalid_seen = True
                break

            payload = record.get("payload") if isinstance(record.get("payload"), dict) else {}
            kind = _record_kind(record)

            # The first SessionMeta is the only safe mode discriminator.  The
            # upstream SessionMeta schema defaults an omitted history_mode to
            # legacy, so require an explicit paginated marker before applying
            # ordinal semantics.  A malformed or future mode is unknown, not
            # evidence of legacy semantics.
            if record.get("type") == "session_meta" and result.ordinal_mode is None:
                if "history_mode" not in payload:
                    result.ordinal_mode = "legacy"
                else:
                    history_mode = payload.get("history_mode")
                    result.ordinal_mode = history_mode if isinstance(history_mode, str) else "unknown"

            if result.ordinal_mode == "paginated":
                raw_ordinal = record.get("ordinal")
                if (
                    isinstance(raw_ordinal, int)
                    and not isinstance(raw_ordinal, bool)
                    and 0 <= raw_ordinal <= MAX_U64
                ):
                    ordinal = raw_ordinal
                    first_offset = ordinal_positions.get(ordinal)
                    if first_offset is not None or ordinal == last_ordinal:
                        result.ordinal_reuse_count += 1
                        if len(result.ordinal_reuse) < MAX_RETAINED_FINDINGS:
                            result.ordinal_reuse.append(
                                {
                                    "ordinal": ordinal,
                                    "first_offset": first_offset if first_offset is not None else last_ordinal_offset,
                                    "duplicate_offset": start,
                                    "reason": "persisted paginated ordinal was reused by another physical record",
                                }
                            )
                    elif len(ordinal_positions) < MAX_ORDINAL_STATES:
                        ordinal_positions[ordinal] = start
                    else:
                        result.ordinal_tracking_overflow = True
                    last_ordinal = ordinal
                    last_ordinal_offset = start
                elif len(result.operational_schema_issues) < MAX_RETAINED_FINDINGS:
                    result.operational_schema_issues.append(
                        {
                            "offset": start,
                            "outer_type": record.get("type"),
                            "reason": (
                                "paginated rollout record is missing an ordinal"
                                if raw_ordinal is None
                                else "paginated rollout ordinal is not a u64"
                            ),
                        }
                    )

            corrupted_tool_call = _corrupted_tool_call_metadata(payload, start)
            if corrupted_tool_call and len(result.corrupted_tool_calls) < MAX_RETAINED_FINDINGS:
                result.corrupted_tool_calls.append(corrupted_tool_call)
            is_oversized = _looks_like_large_inline_payload(line, kind, oversized_threshold)
            stored_payload = payload
            if is_oversized or len(line) > MAX_RETAINED_EVENT_BYTES:
                stored_payload = {
                    key: payload.get(key)
                    for key in ("type", "id", "call_id", "name", "role")
                    if key in payload
                }
                stored_payload["_bounded_payload"] = {
                    "byte_length": len(line),
                    "sha256": hashlib.sha256(line).hexdigest(),
                    "reason": "record exceeds bounded event retention limit",
                }
                if is_oversized:
                    stored_payload["_oversized_payload"] = {
                        "byte_length": len(line),
                        "sha256": hashlib.sha256(line).hexdigest(),
                    }
            if corrupted_tool_call:
                # Keep the parser's retained event and all later recovery
                # surfaces free of the raw decoded control characters. The
                # original name remains available only through bounded hash,
                # length, and codepoint metadata above.
                if stored_payload is payload:
                    stored_payload = dict(payload)
                stored_payload["name"] = CORRUPTED_TOOL_NAME_SENTINEL
            event = TranscriptEvent(start, offset, record.get("type"), stored_payload)
            result.valid_record_count += 1
            if not invalid_seen:
                result.last_valid_offset = offset
            if kind in result.record_types or len(result.record_types) < MAX_RECORD_TYPES:
                result.record_types[kind] += 1
            else:
                result.record_type_overflow = True
            event_tail.append(event)
            event_tail_sizes.append(min(len(line), MAX_RETAINED_EVENT_BYTES))
            event_tail_bytes += event_tail_sizes[-1]
            while len(event_tail) > max(1, int(max_events)) or event_tail_bytes > MAX_EVENT_TAIL_BYTES:
                event_tail.popleft()
                event_tail_bytes -= event_tail_sizes.popleft()
            if record.get("type") == "session_meta":
                result.session_metadata = _safe_session_metadata(payload)
            if is_oversized:
                if len(result.oversized_records) < MAX_RETAINED_FINDINGS:
                    result.oversized_records.append(
                        {
                            "start_offset": start,
                            "end_offset": offset,
                            "byte_length": len(line),
                            "record_type": kind,
                            "classification": "VALID_BUT_OVERSIZED",
                            "reason": "record/payload exceeds bounded processing threshold",
                        }
                    )
                result.oversized_record_count += 1
            if record.get("type") == "compacted":
                result.compacted = True
                last_compaction_index = result.valid_record_count
                replacement = payload.get("replacement_history")
                summary = payload.get("message") or payload.get("summary")
                prior_tool_events = [
                    item for item in list(event_tail)[-25:-1]
                    if item.payload.get("type") in {"function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output"}
                ]
                # A current-format compacted record with an explicitly empty replacement
                # history despite a recent durable operational tail is a conservative,
                # structural loss signal. Merely having later events is not.
                if replacement == [] and summary and prior_tool_events:
                    result.compaction_state_loss = True
                    if len(result.compaction_loss_evidence) < MAX_RETAINED_FINDINGS:
                        result.compaction_loss_evidence.append(
                            {
                                "compaction_offset": start,
                                "recent_operational_records": len(prior_tool_events),
                                "reason": "empty replacement_history omitted a recent durable operational tail",
                            }
                        )
                    else:
                        result.compaction_evidence_overflow = True
            elif payload.get("type") == "context_compacted":
                result.compacted = True
                last_compaction_index = result.valid_record_count
            elif last_compaction_index is not None and (record.get("type") in {"response_item", "event_msg"}):
                result.operational_events_after_compaction += 1

            schema_issue = _operational_schema_issue(payload, record.get("type"), start)
            if schema_issue:
                if len(result.operational_schema_issues) < MAX_RETAINED_FINDINGS:
                    result.operational_schema_issues.append(schema_issue)
            call_id, tool_name, arguments = _call_data(event)
            completion_id: str | None = None
            if call_id:
                malformed_args = False
                if isinstance(arguments, str):
                    try:
                        json.loads(arguments)
                    except json.JSONDecodeError:
                        # apply_patch and free-form custom tools legitimately use raw text.
                        malformed_args = tool_name not in {"apply_patch"} and arguments.lstrip().startswith(("{", "["))
                if malformed_args:
                    if len(result.malformed_tool_arguments) < MAX_RETAINED_FINDINGS:
                        result.malformed_tool_arguments.append({"offset": start, "call_id": call_id, "tool_name": tool_name})
                family = str(payload.get("type"))
                if call_id not in calls and call_id not in outputs:
                    if len(calls) + len(outputs) >= MAX_CORRELATION_STATES:
                        result.correlation_overflow = True
                    else:
                        calls[call_id] = []
                if call_id in retired_ids:
                    result.correlation_overflow = True
                    if len(result.correlation_ambiguities) < MAX_RETAINED_FINDINGS:
                        result.correlation_ambiguities.append(
                            {"call_id": call_id, "reason": "call id was reused after a completed correlation"}
                        )
                if call_id in calls:
                    occurrences = calls[call_id]
                    if len(occurrences) < MAX_OCCURRENCES_PER_ID:
                        occurrences.append(
                            {
                                "offset": start,
                                "call_id": call_id,
                                "tool_name": tool_name,
                                "arguments": arguments,
                                "family": family,
                                "occurrence": len(occurrences) + 1,
                            }
                        )
                    else:
                        result.correlation_overflow = True
            elif payload.get("type") in _OUTPUT_FAMILIES:
                completion_id = str(payload.get("call_id") or payload.get("id") or "")
                if completion_id:
                    if completion_id not in outputs:
                        if len(calls) + len(outputs) >= MAX_CORRELATION_STATES:
                            result.correlation_overflow = True
                        else:
                            outputs[completion_id] = []
                    if completion_id in outputs:
                        matching = outputs[completion_id]
                        if len(matching) < MAX_OCCURRENCES_PER_ID:
                            matching.append(
                                {
                                    "offset": start,
                                    "call_id": completion_id,
                                    "family": _OUTPUT_FAMILIES[str(payload.get("type"))],
                                }
                            )
                        else:
                            result.correlation_overflow = True

            # Retire one-to-one completed pairs immediately.  This keeps
            # memory bounded for long healthy rollouts instead of retaining a
            # dictionary entry for every historical tool call.
            for candidate_id in (call_id,) if call_id else ((completion_id,) if completion_id else ()):
                call_items = calls.get(candidate_id, [])
                output_items = outputs.get(candidate_id, [])
                if (
                    len(call_items) == 1
                    and len(output_items) == 1
                    and call_items[0]["family"] == output_items[0]["family"]
                ):
                    del calls[candidate_id]
                    del outputs[candidate_id]
                    if candidate_id not in retired_ids:
                        if len(retired_order) == MAX_CORRELATION_STATES:
                            retired_ids.discard(retired_order[0])
                        retired_order.append(candidate_id)
                        retired_ids.add(candidate_id)

    # Continue hashing remaining bytes without parsing after the first invalid record.
    with source.open("rb") as stream:
        stream.seek(offset)
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    result.sha256 = digest.hexdigest()
    result.events = list(event_tail)
    result.retained_event_bytes = event_tail_bytes
    unfinished: list[dict[str, Any]] = []
    unfinished_total = 0
    for call_id, occurrences in calls.items():
        matching_outputs = outputs.get(call_id, [])
        families = {item["family"] for item in occurrences}
        output_families = {item["family"] for item in matching_outputs}
        # A missing output is the ordinary interrupted-call case.  It is
        # represented as unfinished (unknown execution state), but is not a
        # correlation *ambiguity*.  Ambiguity starts when both sides exist
        # with duplicate occurrences or mismatched families.
        ambiguous = bool(matching_outputs) and (
            len(occurrences) != 1
            or len(matching_outputs) != 1
            or families != output_families
        )
        if not matching_outputs:
            # The call has no durable output yet.  This is an interrupted
            # action, not a safe completion.
            unfinished_total += len(occurrences)
            if len(unfinished) < MAX_RETAINED_FINDINGS:
                unfinished.extend(occurrences[: MAX_RETAINED_FINDINGS - len(unfinished)])
        elif ambiguous:
            if len(result.correlation_ambiguities) < MAX_RETAINED_FINDINGS:
                result.correlation_ambiguities.append(
                    {
                        "call_id": call_id,
                        "call_occurrences": len(occurrences),
                        "output_occurrences": len(matching_outputs),
                        "call_families": sorted(families),
                        "output_families": sorted(output_families),
                        "reason": "call/output correlation is not one-to-one",
                    }
                )
            unfinished_total += len(occurrences)
            if len(unfinished) < MAX_RETAINED_FINDINGS:
                unfinished.extend(occurrences[: MAX_RETAINED_FINDINGS - len(unfinished)])
        # Exactly one call and exactly one same-family output is the only
        # correlation we accept as completed.
    for output_id in outputs:
        if output_id not in calls:
            if len(result.correlation_ambiguities) < MAX_RETAINED_FINDINGS:
                result.correlation_ambiguities.append(
                    {"call_id": output_id, "call_occurrences": 0, "output_occurrences": len(outputs[output_id]), "reason": "output has no matching call"}
                )
    result.unfinished_tool_calls = unfinished
    result.unfinished_tool_call_count = unfinished_total
    if result.correlation_overflow and len(result.correlation_ambiguities) < MAX_RETAINED_FINDINGS:
        result.correlation_ambiguities.append(
            {"reason": "correlation state exceeded bounded memory limit", "max_states": MAX_CORRELATION_STATES}
        )
    if result.corrupted_tool_calls and result.corruption_class is None:
        result.corruption_class = "CORRUPTED_TOOL_CALL"
    elif result.malformed_tool_arguments and result.corruption_class is None:
        result.corruption_class = "MALFORMED_RECORD"
    elif result.oversized_records and result.corruption_class is None:
        result.corruption_class = "OVERSIZED_PAYLOAD"
    elif (result.correlation_ambiguities or result.operational_schema_issues) and result.corruption_class is None:
        result.corruption_class = "UNKNOWN_OPERATIONAL_SCHEMA"
    return result
