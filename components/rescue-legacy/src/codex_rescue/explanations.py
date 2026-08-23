from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class FindingExplanation:
    finding_code: str
    what_happened: str
    evidence_used: str
    what_is_still_healthy: str
    what_rescue_cannot_know: str
    risk: str
    safe_next_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_code": self.finding_code,
            "WHAT_HAPPENED": self.what_happened,
            "EVIDENCE_USED": self.evidence_used,
            "WHAT_IS_STILL_HEALTHY": self.what_is_still_healthy,
            "WHAT_RESCUE_CANNOT_KNOW": self.what_rescue_cannot_know,
            "RISK": self.risk,
            "SAFE_NEXT_ACTION": self.safe_next_action,
        }


EXPLANATIONS: dict[str, FindingExplanation] = {
    "HEALTHY": FindingExplanation(
        finding_code="HEALTHY",
        what_happened="No structural or persistence corruption detected in the rollout file.",
        evidence_used="Complete JSONL line parsing, record kind inspection, and boundary validation.",
        what_is_still_healthy="All recorded turns, tool calls, and lifecycle events are intact and readable.",
        what_rescue_cannot_know="Does not validate upstream desktop UI rendering, server-side sync, or semantic prompt completeness.",
        risk="LOW: Normal operations can proceed.",
        safe_next_action="Continue using the session normally or export diagnostic reports if needed.",
    ),
    "TRUNCATED_JSONL": FindingExplanation(
        finding_code="TRUNCATED_JSONL",
        what_happened="The rollout file ends abruptly without a trailing newline or with a partial JSON record at EOF.",
        evidence_used="Unterminated byte sequence observed at the final line of the JSONL rollout file.",
        what_is_still_healthy="All prior complete records up to the truncation point remain valid and durable.",
        what_rescue_cannot_know="Cannot know whether additional in-flight tokens or tool outputs were generated before the abrupt termination.",
        risk="MEDIUM: Resuming in Codex may fail to parse the trailing line or discard uncommitted progress.",
        safe_next_action="Salvage durable prior history with 'codex-rescue salvage' or generate a recovery plan.",
    ),
    "MALFORMED_JSONL": FindingExplanation(
        finding_code="MALFORMED_JSONL",
        what_happened="One or more intermediate records failed valid JSON parsing.",
        evidence_used="Syntax error encountered while deserializing JSON record bytes.",
        what_is_still_healthy="Other well-formed records in the rollout remain accessible.",
        what_rescue_cannot_know="Cannot infer original intended content of corrupted records.",
        risk="HIGH: Replay engine or Desktop sidebar will reject the entire session.",
        safe_next_action="Salvage well-formed records to a clean fork without modifying original session.",
    ),
    "LOST_TAIL_AFTER_COMPACTION": FindingExplanation(
        finding_code="LOST_TAIL_AFTER_COMPACTION",
        what_happened="A context compaction event was recorded, but post-compaction continuation turns were lost or corrupted.",
        evidence_used="Compaction event observed without subsequent expected turn records.",
        what_is_still_healthy="Pre-compaction history and compacted summary record are intact.",
        what_rescue_cannot_know="Whether the assistant finished generating subsequent turns before termination.",
        risk="MEDIUM: Conversation state appears frozen at compaction boundary.",
        safe_next_action="Fork a new session from the compacted checkpoint.",
    ),
    "MISSING_TOOL_OUTPUT": FindingExplanation(
        finding_code="MISSING_TOOL_OUTPUT",
        what_happened="A tool call record was initiated without a corresponding persisted tool output record before the turn ended.",
        evidence_used="Unpaired tool call identifier in the rollout sequence.",
        what_is_still_healthy="User message and preceding conversation turns are intact.",
        what_rescue_cannot_know="Cannot determine whether tool execution actually occurred or was aborted by the host/user.",
        risk="LOW/MEDIUM: Turn may appear incomplete or awaiting response in UI.",
        safe_next_action="Inspect writer status or fork conversation to retry the command.",
    ),
    "ACTIVE_WRITER_LOCK": FindingExplanation(
        finding_code="ACTIVE_WRITER_LOCK",
        what_happened="An active writer lock file or live process PID was detected holding this session.",
        evidence_used="Lock file presence and active OS process verification.",
        what_is_still_healthy="Rollout records on disk are durable and readable in read-only mode.",
        what_rescue_cannot_know="Cannot know when the active writer will flush buffers or release lock.",
        risk="CONCURRENCY: Writing or modifying the session while locked will cause data corruption.",
        safe_next_action="Perform read-only inspection only. Never delete active lock files automatically.",
    ),
    "SPLIT_BRAIN_PROJECTION": FindingExplanation(
        finding_code="SPLIT_BRAIN_PROJECTION",
        what_happened="SQLite projection cursor or item count diverges from the durable rollout filesystem records.",
        evidence_used="Comparison between SQLite thread row cursor and latest rollout ordinal.",
        what_is_still_healthy="Filesystem rollout remains canonical and intact.",
        what_rescue_cannot_know="Why the SQLite projection daemon failed to commit progress.",
        risk="LOW: Desktop sidebar may show stale titles or truncated history while rollout is complete.",
        safe_next_action="Rely on filesystem rollout as canonical source; rebuild or reproject if supported.",
    ),
    "ORPHAN_SUBAGENT": FindingExplanation(
        finding_code="ORPHAN_SUBAGENT",
        what_happened="Subagent session metadata references a parent session ID that cannot be resolved in the store.",
        evidence_used="Parent ID reference in subagent rollout without matching parent file in sessions store.",
        what_is_still_healthy="Subagent conversation transcript is independently readable.",
        what_rescue_cannot_know="Original parent workspace context or launch parameters.",
        risk="LOW: Subagent transcript is preserved but unlinked in hierarchy views.",
        safe_next_action="Use subagent transcript directly via 'codex-rescue salvage' or 'codex-rescue timeline'.",
    ),
    "UNINDEXED_SESSION": FindingExplanation(
        finding_code="UNINDEXED_SESSION",
        what_happened="Rollout file exists on disk but is absent from the SQLite threads inventory index.",
        evidence_used="Filesystem discovery found rollout file; SQLite lookup returned no matching thread row.",
        what_is_still_healthy="Rollout transcript is completely intact on disk.",
        what_rescue_cannot_know="Why Codex failed to register the session in its local database index.",
        risk="LOW: Session will not appear in sidebar UI but file is not corrupted.",
        safe_next_action="Access session directly by file path or salvage into a newly indexed session.",
    ),
    "WORKSPACE_PATH_MISMATCH": FindingExplanation(
        finding_code="WORKSPACE_PATH_MISMATCH",
        what_happened="Saved workspace path in rollout does not match current host operating system path format.",
        evidence_used="Saved path family differs from current runtime environment.",
        what_is_still_healthy="Session transcript and tool history are completely unaffected.",
        what_rescue_cannot_know="Whether target repository is mounted at translated path.",
        risk="LOW: Purely environmental association issue.",
        safe_next_action="Use 'codex-rescue workspace <session>' to view deterministic path translation.",
    ),
    "OVERSIZED_PAYLOAD": FindingExplanation(
        finding_code="OVERSIZED_PAYLOAD",
        what_happened="A single JSONL record exceeds safe payload threshold.",
        evidence_used="Record byte length measured during bounded line read.",
        what_is_still_healthy="All other conversation records are intact.",
        what_rescue_cannot_know="Semantic necessity of the oversized data.",
        risk="MEDIUM: May cause memory pressure or UI lag during playback.",
        safe_next_action="Salvage with truncated payloads or view storage analysis via 'codex-rescue storage'.",
    ),
    "VALID_BUT_OVERSIZED": FindingExplanation(
        finding_code="VALID_BUT_OVERSIZED",
        what_happened="A complete and well-formed record exceeds bounded reader or processing limits (e.g. >16 MiB).",
        evidence_used="Bounded line scan observed complete record exceeding size limits without syntax or truncation errors.",
        what_is_still_healthy="Record syntax is intact; prior records remain fully durable and readable.",
        what_rescue_cannot_know="Whether full in-memory deserialization of the giant payload is needed by downstream tools.",
        risk="MEDIUM: Processing may exceed memory budgets in downstream tools.",
        safe_next_action="Use bounded inspection or salvage with omitted heavy payloads.",
    ),
    "OVERSIZED_RECORD": FindingExplanation(
        finding_code="OVERSIZED_RECORD",
        what_happened="One or more records exceed the bounded reader allocation ceiling.",
        evidence_used="Line size measurement during streaming bounded scan.",
        what_is_still_healthy="Durable stream prefix up to the oversized record boundary.",
        what_rescue_cannot_know="Full in-memory structure without expanding bounded allocation limits.",
        risk="MEDIUM: Processing bounded stream preserves memory safety.",
        safe_next_action="Review oversized record offsets and perform bounded inspection.",
    ),
    "MALFORMED_RECORD": FindingExplanation(
        finding_code="MALFORMED_RECORD",
        what_happened="A record in the rollout failed valid JSON decoding or contained embedded control/NUL corruptions.",
        evidence_used="Syntax error or NUL byte encountered during record parsing.",
        what_is_still_healthy="All well-formed records prior to the malformed record.",
        what_rescue_cannot_know="The intended contents of the corrupted record.",
        risk="HIGH: Replay engines and UI readers will reject the rollout.",
        safe_next_action="Salvage durable prefix to a clean fork without modifying original session.",
    ),
    "TRUNCATED_TRANSCRIPT": FindingExplanation(
        finding_code="TRUNCATED_TRANSCRIPT",
        what_happened="The rollout ended abruptly without a trailing newline or with an incomplete record at EOF.",
        evidence_used="Unterminated byte sequence at end of file.",
        what_is_still_healthy="All complete records prior to the truncation point.",
        what_rescue_cannot_know="Whether in-flight tokens were lost before flush.",
        risk="MEDIUM: Parsing incomplete tail record fails in strict readers.",
        safe_next_action="Salvage intact prior records with 'codex-rescue salvage'.",
    ),
}


def get_explanation(finding_code: str) -> FindingExplanation:
    code = finding_code.upper().strip()
    if code in EXPLANATIONS:
        return EXPLANATIONS[code]
    return FindingExplanation(
        finding_code=code,
        what_happened=f"Diagnostic finding '{code}' was recorded during analysis.",
        evidence_used="Persisted session metadata and structural parsing checks.",
        what_is_still_healthy="Uncorrupted portions of the transcript remain readable.",
        what_rescue_cannot_know="Unrecognized finding code has no specialized domain heuristic.",
        risk="UNKNOWN: Treat conservatively.",
        safe_next_action="Review raw session evidence and perform non-destructive inspection.",
    )
