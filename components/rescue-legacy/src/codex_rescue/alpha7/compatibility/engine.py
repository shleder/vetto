from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from codex_rescue.alpha7.invariants import InvariantCheckResult, InvariantEngine, InvariantStatus

import enum


class CompatibilityVerdict(str, enum.Enum):
    SUPPORTED = "SUPPORTED"
    BEST_EFFORT = "BEST_EFFORT"
    READ_ONLY_ONLY = "READ_ONLY_ONLY"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


SUPPORTED_ROLLOUT_SCHEMAS: Set[int] = {1, 2}
SUPPORTED_SQLITE_SCHEMAS: Set[int] = {1, 2, 3}


@dataclass
class CompatibilityReport:
    verdict: str
    rollout_schema_version: int
    sqlite_schema_version: int
    rollout_schema_known: bool
    sqlite_schema_known: bool
    read_only_supported: bool
    mutation_schema_compatible: bool
    app_server_supported: bool
    mutation_allowed: bool = False  # Always False at compatibility level; mutation requires operational proof gate
    mutation_hold_reason: str = "DIRECT_DERIVED_MUTATION_HOLD"
    read_only_diagnosis_allowed: bool = True
    rejection_reason: Optional[str] = None
    invariants: List[InvariantCheckResult] = field(default_factory=list)

    @property
    def rollout_schema_supported(self) -> bool:
        return self.rollout_schema_known

    @property
    def sqlite_schema_supported(self) -> bool:
        return self.sqlite_schema_known

    def to_dict(self) -> Dict[str, Any]:
        return {
            "verdict": self.verdict,
            "rollout_schema_version": self.rollout_schema_version,
            "sqlite_schema_version": self.sqlite_schema_version,
            "rollout_schema_known": self.rollout_schema_known,
            "sqlite_schema_known": self.sqlite_schema_known,
            "rollout_schema_supported": self.rollout_schema_known,
            "sqlite_schema_supported": self.sqlite_schema_known,
            "read_only_supported": self.read_only_supported,
            "mutation_schema_compatible": self.mutation_schema_compatible,
            "app_server_supported": self.app_server_supported,
            "mutation_allowed": self.mutation_allowed,
            "mutation_hold_reason": self.mutation_hold_reason,
            "read_only_diagnosis_allowed": self.read_only_diagnosis_allowed,
            "rejection_reason": self.rejection_reason,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
        }


class CompatibilityEngine:
    """Evaluates compatibility between Codex Rescue Alpha7 and environment schemas.

    IMPORTANT: Schema compatibility alone establishes read-only support.
    It does NOT grant mutation permission (mutation_allowed=False).
    """

    @staticmethod
    def evaluate(
        rollout_schema: int = 1,
        sqlite_schema: int = 1,
        app_server_protocol: str = "v1",
    ) -> CompatibilityReport:
        rollout_ok = rollout_schema in SUPPORTED_ROLLOUT_SCHEMAS
        sqlite_ok = sqlite_schema in SUPPORTED_SQLITE_SCHEMAS
        app_ok = app_server_protocol in ("v1", "v2")
        schema_compatible = rollout_ok and sqlite_ok

        invariants = []
        inv_rollout = InvariantEngine.check_schema_support(
            rollout_schema, SUPPORTED_ROLLOUT_SCHEMAS, is_mutation_operation=False
        )
        invariants.append(inv_rollout)

        inv_sqlite = InvariantEngine.check_schema_support(
            sqlite_schema, SUPPORTED_SQLITE_SCHEMAS, is_mutation_operation=False
        )
        invariants.append(inv_sqlite)

        rejection_reason = None
        if not schema_compatible:
            if not rollout_ok:
                rejection_reason = f"UNKNOWN_ROLLOUT_SCHEMA_{rollout_schema}"
            elif not sqlite_ok:
                rejection_reason = f"UNKNOWN_SQLITE_SCHEMA_{sqlite_schema}"

        if rollout_ok and sqlite_ok and app_ok:
            verdict = CompatibilityVerdict.SUPPORTED.value
        elif rollout_ok and sqlite_ok:
            verdict = CompatibilityVerdict.BEST_EFFORT.value
        elif rollout_ok:
            verdict = CompatibilityVerdict.READ_ONLY_ONLY.value
        else:
            verdict = CompatibilityVerdict.UNSUPPORTED.value

        return CompatibilityReport(
            verdict=verdict,
            rollout_schema_version=rollout_schema,
            sqlite_schema_version=sqlite_schema,
            rollout_schema_known=rollout_ok,
            sqlite_schema_known=sqlite_ok,
            read_only_supported=rollout_ok,
            mutation_schema_compatible=schema_compatible,
            app_server_supported=app_ok,
            mutation_allowed=False,  # Mutation gate fails closed; HOLD
            mutation_hold_reason="DIRECT_DERIVED_MUTATION_HOLD: Operation-level verification gate required",
            read_only_diagnosis_allowed=True,
            rejection_reason=rejection_reason,
            invariants=invariants,
        )
