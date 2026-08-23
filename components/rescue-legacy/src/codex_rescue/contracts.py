from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field
from typing import Any

SCHEMA_VERSION = 1


class ExitCode(enum.IntEnum):
    SUCCESS = 0             # Healthy / successful operation
    WARNINGS_FOUND = 1      # Non-critical findings or warnings present
    ACTIONABLE_FINDINGS = 2  # Actionable/repairable diagnostic findings detected
    INCOMPLETE_OR_UNSUPPORTED = 3  # Opaque schema, capped scan, or unsupported configuration
    UNSAFE_TO_MODIFY = 4    # Active writer lock, precondition failure, or unprovable repair
    INVALID_INPUT = 5       # Invalid CLI arguments, missing path, or malformed flag
    INTERNAL_FAILURE = 6    # Internal unhandled error or unexpected exception


@dataclass
class Envelope:
    schema_version: int = SCHEMA_VERSION
    tool_version: str = "0.1.0a7.dev"
    command: str = ""
    status: str = "SUCCESS"
    session: str | None = None
    findings: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    confidence: str = "HIGH"
    safety: dict[str, Any] = field(default_factory=dict)
    incomplete: bool = False
    incomplete_reason: str | None = None
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        if self.session is None:
            del res["session"]
        if self.incomplete_reason is None:
            del res["incomplete_reason"]
        if self.data is None:
            del res["data"]
        return res
