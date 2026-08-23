from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set


class InvariantId(str, enum.Enum):
    INV_001 = "INV-001"  # Every physical source record or relevant byte region must be accounted for
    INV_002 = "INV-002"  # Canonical rollout may not change during derived-state-only recovery
    INV_003 = "INV-003"  # No mutation under active writer unless explicitly proven writer-safe
    INV_004 = "INV-004"  # Unknown or incomplete source integrity blocks mutation
    INV_005 = "INV-005"  # Every mutation requires a verified rollback path
    INV_006 = "INV-006"  # Derived-state divergence alone does not imply source corruption
    INV_007 = "INV-007"  # Unknown schema disables mutation by default
    INV_008 = "INV-008"  # Verification failure causes rollback or leaves explicit unresolved status
    INV_009 = "INV-009"  # --yes cannot bypass safety checks
    INV_010 = "INV-010"  # --no-prompt cannot bypass safety checks
    INV_011 = "INV-011"  # Privacy-safe artifact must pass redaction validation before SHAREABLE status
    INV_012 = "INV-012"  # No missing source data may be reconstructed by guessing
    INV_013 = "INV-013"  # Upstream-only failure must not be presented as locally repaired
    INV_014 = "INV-014"  # Partial scan cannot produce HEALTHY verdict
    INV_015 = "INV-015"  # Repair planning must revalidate assumptions immediately before mutation


class InvariantStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    BLOCKED = "BLOCKED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass
class InvariantCheckResult:
    invariant_id: InvariantId
    status: InvariantStatus
    message: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.status in (InvariantStatus.PASS, InvariantStatus.NOT_APPLICABLE)


@dataclass
class InvariantEvaluation:
    checks: List[InvariantCheckResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(c.passed for c in self.checks)

    @property
    def failures(self) -> List[InvariantCheckResult]:
        return [c for c in self.checks if not c.passed]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "all_passed": self.all_passed,
            "checks": [
                {
                    "id": c.invariant_id.value,
                    "status": c.status.value,
                    "message": c.message,
                    "evidence": c.evidence,
                }
                for c in self.checks
            ],
            "failures": [
                {
                    "id": c.invariant_id.value,
                    "status": c.status.value,
                    "message": c.message,
                }
                for c in self.failures
            ],
        }


class InvariantEngine:
    """Central Alpha7 Formal Invariant Verification Engine."""

    @staticmethod
    def check_source_accounting(
        total_bytes: int,
        scanned_bytes: int,
        unclassified_bytes: int = 0,
        malformed_bytes: int = 0,
    ) -> InvariantCheckResult:
        """INV-001 & INV-014: Every byte must be accounted for; partial scan cannot be HEALTHY."""
        if scanned_bytes < total_bytes:
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_014,
                status=InvariantStatus.FAIL,
                message=f"Partial scan detected: scanned {scanned_bytes}/{total_bytes} bytes.",
                evidence={"total_bytes": total_bytes, "scanned_bytes": scanned_bytes},
            )
        if unclassified_bytes > 0:
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_001,
                status=InvariantStatus.FAIL,
                message=f"Unclassified bytes present ({unclassified_bytes} bytes).",
                evidence={"unclassified_bytes": unclassified_bytes},
            )
        return InvariantCheckResult(
            invariant_id=InvariantId.INV_001,
            status=InvariantStatus.PASS,
            message="All source bytes cleanly accounted for.",
            evidence={"total_bytes": total_bytes, "scanned_bytes": scanned_bytes},
        )

    @staticmethod
    def check_source_immutability(
        initial_hash: str,
        current_hash: str,
        is_derived_recovery: bool = True,
    ) -> InvariantCheckResult:
        """INV-002: Canonical rollout may not change during derived-state recovery."""
        if is_derived_recovery and initial_hash != current_hash:
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_002,
                status=InvariantStatus.FAIL,
                message=f"Source hash mutated during derived recovery: {initial_hash} -> {current_hash}",
                evidence={"initial_hash": initial_hash, "current_hash": current_hash},
            )
        return InvariantCheckResult(
            invariant_id=InvariantId.INV_002,
            status=InvariantStatus.PASS,
            message="Source immutability verified.",
            evidence={"hash": current_hash},
        )

    @staticmethod
    def check_active_writer(
        has_active_writer: bool,
        writer_pid: Optional[int] = None,
        is_mutation_operation: bool = False,
    ) -> InvariantCheckResult:
        """INV-003: No mutation under active writer."""
        if has_active_writer and is_mutation_operation:
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_003,
                status=InvariantStatus.FAIL,
                message=f"Mutation blocked: active writer detected (PID: {writer_pid}).",
                evidence={"active_writer": True, "writer_pid": writer_pid},
            )
        return InvariantCheckResult(
            invariant_id=InvariantId.INV_003,
            status=InvariantStatus.PASS,
            message="No conflicting active writer." if not has_active_writer else "Active writer present (read-only mode).",
            evidence={"has_active_writer": has_active_writer, "writer_pid": writer_pid},
        )

    @staticmethod
    def check_schema_support(
        schema_version: int,
        supported_versions: Set[int],
        is_mutation_operation: bool = False,
    ) -> InvariantCheckResult:
        """INV-007: Unknown schema disables mutation by default."""
        if schema_version not in supported_versions:
            status = InvariantStatus.FAIL if is_mutation_operation else InvariantStatus.BLOCKED
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_007,
                status=status,
                message=f"Unsupported/unknown schema version {schema_version}. Mutation disabled.",
                evidence={"schema_version": schema_version, "supported_versions": list(supported_versions)},
            )
        return InvariantCheckResult(
            invariant_id=InvariantId.INV_007,
            status=InvariantStatus.PASS,
            message=f"Schema version {schema_version} is supported.",
            evidence={"schema_version": schema_version},
        )

    @staticmethod
    def check_flags_cannot_bypass_safety(
        yes_flag: bool,
        no_prompt_flag: bool,
        blocked_reason: Optional[str] = None,
    ) -> InvariantCheckResult:
        """INV-009 & INV-010: --yes and --no-prompt cannot bypass safety."""
        if blocked_reason and (yes_flag or no_prompt_flag):
            return InvariantCheckResult(
                invariant_id=InvariantId.INV_009 if yes_flag else InvariantId.INV_010,
                status=InvariantStatus.FAIL,
                message=f"Safety checks cannot be bypassed by --yes or --no-prompt: {blocked_reason}",
                evidence={"yes": yes_flag, "no_prompt": no_prompt_flag, "blocked_reason": blocked_reason},
            )
        return InvariantCheckResult(
            invariant_id=InvariantId.INV_009,
            status=InvariantStatus.PASS,
            message="Safety invariants honored.",
            evidence={"yes": yes_flag, "no_prompt": no_prompt_flag},
        )
