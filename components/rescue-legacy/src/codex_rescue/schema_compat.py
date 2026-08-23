from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from .transcript import ParseResult


# Explicit compatibility only.  These are current/historical protocol records
# that Alpha4's conservative name heuristic can otherwise mistake for unknown
# operational schemas.  Unknown future state-bearing records remain untouched
# and therefore fail closed.
KNOWN_EVENT_MSG_TYPES = {
    "mcp_tool_call_begin",
    "mcp_tool_call_end",
    "view_image_tool_call",
    "dynamic_tool_call_request",
    "dynamic_tool_call_response",
}

KNOWN_RESPONSE_ITEM_TYPES = {
    "additional_tools",
    "message",
    "agent_message",
    "reasoning",
    "local_shell_call",
    "function_call",
    "tool_search_call",
    "function_call_output",
    "custom_tool_call",
    "custom_tool_call_output",
    "tool_search_output",
    "web_search_call",
    "image_generation_call",
    "compaction",
    "context_compaction",
}


@dataclass(frozen=True)
class SchemaCompatibilityReport:
    recognized_compatibility_count: int
    recognized_types: dict[str, int]
    unknown_operational_count: int
    unknown_operational_types: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "recognized_compatibility_count": self.recognized_compatibility_count,
            "recognized_types": self.recognized_types,
            "unknown_operational_count": self.unknown_operational_count,
            "unknown_operational_types": self.unknown_operational_types,
        }


def _known_issue(issue: dict[str, Any]) -> bool:
    outer = issue.get("outer_type")
    payload_type = issue.get("payload_type")
    if not isinstance(payload_type, str):
        return False
    if outer == "event_msg" and payload_type in KNOWN_EVENT_MSG_TYPES:
        return issue.get("reason") == "unknown operational payload type"
    if outer == "response_item" and payload_type in KNOWN_RESPONSE_ITEM_TYPES:
        return issue.get("reason") == "unknown operational payload type"
    return False


def apply_schema_compatibility(parsed: ParseResult) -> SchemaCompatibilityReport:
    """Remove only explicit known-schema false positives from Alpha4 results.

    This mutates the in-memory ParseResult only; no source data is changed.
    The report intentionally aggregates types/counts and never includes payloads.
    """

    recognized: Counter[str] = Counter()
    remaining: list[dict[str, Any]] = []
    for issue in parsed.operational_schema_issues:
        if _known_issue(issue):
            recognized[str(issue.get("payload_type"))] += 1
        else:
            remaining.append(issue)
    parsed.operational_schema_issues = remaining
    if (
        parsed.corruption_class == "UNKNOWN_OPERATIONAL_SCHEMA"
        and not parsed.operational_schema_issues
        and not parsed.correlation_ambiguities
    ):
        parsed.corruption_class = None

    unknown: Counter[str] = Counter()
    for issue in parsed.operational_schema_issues:
        payload_type = issue.get("payload_type")
        unknown[str(payload_type) if payload_type is not None else "<missing>"] += 1
    for ambiguity in parsed.correlation_ambiguities:
        unknown["<correlation_ambiguity>"] += 1
    return SchemaCompatibilityReport(
        recognized_compatibility_count=sum(recognized.values()),
        recognized_types=dict(sorted(recognized.items())),
        unknown_operational_count=sum(unknown.values()),
        unknown_operational_types=dict(sorted(unknown.items())),
    )


__all__ = [
    "KNOWN_EVENT_MSG_TYPES",
    "KNOWN_RESPONSE_ITEM_TYPES",
    "SchemaCompatibilityReport",
    "apply_schema_compatibility",
]
