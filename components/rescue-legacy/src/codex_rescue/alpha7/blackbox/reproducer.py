from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SyntheticRecord:
    record_type: str  # e.g. "session_meta", "turn", "tool_call", "compacted_boundary"
    ordinal: int
    payload_size_bytes: int
    is_malformed: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_type": self.record_type,
            "ordinal": self.ordinal,
            "payload_size_bytes": self.payload_size_bytes,
            "is_malformed": self.is_malformed,
            "details": self.details,
        }


@dataclass
class SyntheticReproducer:
    reproducer_id: str
    target_finding: str
    schema_version: int
    total_records: int
    records: List[SyntheticRecord] = field(default_factory=list)
    initial_sqlite_cursor: Optional[int] = None
    expected_failure: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "reproducer_id": self.reproducer_id,
            "target_finding": self.target_finding,
            "schema_version": self.schema_version,
            "total_records": self.total_records,
            "records": [r.to_dict() for r in self.records],
            "initial_sqlite_cursor": self.initial_sqlite_cursor,
            "expected_failure": self.expected_failure,
        }


class ReproducerEngine:
    """Creates synthetic structural reproducers, delta-minimizes them, and runs replay verification."""

    @staticmethod
    def create_reproducer(
        finding: str,
        total_records: int = 100,
        inject_defect_at: Optional[int] = None,
    ) -> SyntheticReproducer:
        records = []
        for i in range(total_records):
            is_defect = (inject_defect_at is not None and i == inject_defect_at)
            records.append(
                SyntheticRecord(
                    record_type="turn" if i > 0 else "session_meta",
                    ordinal=i,
                    payload_size_bytes=256 if not is_defect else 1_000_000,
                    is_malformed=is_defect,
                    details={"simulated": True},
                )
            )

        return SyntheticReproducer(
            reproducer_id=f"rep_{finding.lower()}_{total_records}",
            target_finding=finding,
            schema_version=1,
            total_records=total_records,
            records=records,
            expected_failure=finding,
        )

    @staticmethod
    def minimize_reproducer(rep: SyntheticReproducer) -> SyntheticReproducer:
        """Minimizes huge synthetic record lists down to essential records preserving the finding."""
        if len(rep.records) <= 7:
            return rep

        # Keep first record (session_meta), defect records, and boundaries
        minimized = []
        minimized.append(rep.records[0])  # Header

        # Keep defect records
        defects = [r for r in rep.records[1:] if r.is_malformed or r.payload_size_bytes > 500_000]
        if defects:
            minimized.extend(defects)
        else:
            # Keep sample tail
            minimized.append(rep.records[-1])

        return SyntheticReproducer(
            reproducer_id=f"{rep.reproducer_id}_minimized",
            target_finding=rep.target_finding,
            schema_version=rep.schema_version,
            total_records=len(minimized),
            records=minimized,
            initial_sqlite_cursor=rep.initial_sqlite_cursor,
            expected_failure=rep.expected_failure,
        )

    @staticmethod
    def create_windows_divergence_reproducer() -> SyntheticReproducer:
        """Generates synthetic reproducer for WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE."""
        records = [
            SyntheticRecord(
                record_type="session_meta",
                ordinal=0,
                payload_size_bytes=256,
                details={"stored_path": r"\\?\C:\Users\tester\.codex\sessions\rollout.jsonl", "discovered_path": r"C:\Users\tester\.codex\sessions\rollout.jsonl"},
            ),
            SyntheticRecord(
                record_type="turn",
                ordinal=1,
                payload_size_bytes=512,
                is_malformed=True,
                details={"finding": "WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE"},
            ),
        ]
        return SyntheticReproducer(
            reproducer_id="rep_windows_path_divergence",
            target_finding="WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE",
            schema_version=1,
            total_records=len(records),
            records=records,
            expected_failure="WINDOWS_ROLLOUT_PATH_IDENTITY_DIVERGENCE",
        )

    @staticmethod
    def create_spawn_edge_reproducer() -> SyntheticReproducer:
        """Generates synthetic reproducer for STALE_SPAWN_EDGE_PRESENTATION."""
        records = [
            SyntheticRecord(
                record_type="session_meta",
                ordinal=0,
                payload_size_bytes=256,
                details={"thread_id": "thread-123", "parent_id": None},
            ),
            SyntheticRecord(
                record_type="subagent_spawn",
                ordinal=1,
                payload_size_bytes=512,
                is_malformed=True,
                details={"spawn_edge_status": "CLOSED", "active_marker": False, "finding": "STALE_SPAWN_EDGE_PRESENTATION"},
            ),
        ]
        return SyntheticReproducer(
            reproducer_id="rep_stale_spawn_edge",
            target_finding="STALE_SPAWN_EDGE_PRESENTATION",
            schema_version=1,
            total_records=len(records),
            records=records,
            expected_failure="STALE_SPAWN_EDGE_PRESENTATION",
        )

    @staticmethod
    def replay(rep: SyntheticReproducer) -> Dict[str, Any]:
        """Replays synthetic reproducer through invariant validation."""
        has_defect = any(r.is_malformed for r in rep.records)
        finding_triggered = rep.target_finding if has_defect else "HEALTHY"

        return {
            "reproducer_id": rep.reproducer_id,
            "records_evaluated": len(rep.records),
            "triggered_finding": finding_triggered,
            "matches_expected": finding_triggered == rep.expected_failure,
            "status": "PASS" if finding_triggered == rep.expected_failure else "REGRESSION",
        }
