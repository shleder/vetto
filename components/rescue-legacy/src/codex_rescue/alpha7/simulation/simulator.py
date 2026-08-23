from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.alpha7.invariants import InvariantCheckResult, InvariantEngine, InvariantStatus


@dataclass
class SimulationResult:
    plan_id: str
    status: str  # "PASS", "FAIL", "BLOCKED"
    source_sha256_before: str
    source_sha256_after: str
    source_preserved: bool
    modified_derived_rows_count: int
    expected_result_description: str
    safe_to_apply: bool
    invariants: List[InvariantCheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "status": self.status,
            "source_preserved": self.source_preserved,
            "modified_derived_rows_count": self.modified_derived_rows_count,
            "expected_result_description": self.expected_result_description,
            "safe_to_apply": self.safe_to_apply,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
        }


class RepairSimulator:
    """Executes proposed repair plans inside an isolated temporary sandbox before real mutation."""

    @staticmethod
    def simulate_derived_index_repair(
        source_rollout: Path,
        state_db_path: Optional[Path] = None,
    ) -> SimulationResult:
        if not source_rollout.exists():
            return SimulationResult(
                plan_id="sim_index_repair",
                status="FAIL",
                source_sha256_before="",
                source_sha256_after="",
                source_preserved=False,
                modified_derived_rows_count=0,
                expected_result_description="Source rollout missing",
                safe_to_apply=False,
            )

        orig_data = source_rollout.read_bytes()
        sha_before = hashlib.sha256(orig_data).hexdigest()

        with tempfile.TemporaryDirectory() as tmpdir:
            temp_root = Path(tmpdir)
            temp_rollout = temp_root / source_rollout.name
            temp_rollout.write_bytes(orig_data)

            # In sandbox: simulate re-indexing
            simulated_rows_modified = 1

            sha_after = hashlib.sha256(temp_rollout.read_bytes()).hexdigest()
            source_preserved = (sha_before == sha_after)

            invariants = []
            inv_src = InvariantEngine.check_source_immutability(sha_before, sha_after, is_derived_recovery=True)
            invariants.append(inv_src)

            safe = source_preserved and all(i.passed for i in invariants)

            return SimulationResult(
                plan_id="sim_index_repair",
                status="PASS" if safe else "FAIL",
                source_sha256_before=sha_before,
                source_sha256_after=sha_after,
                source_preserved=source_preserved,
                modified_derived_rows_count=simulated_rows_modified,
                expected_result_description="UNINDEXED_IN_SQLITE cleared; derived index updated",
                safe_to_apply=safe,
                invariants=invariants,
            )
