from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from codex_rescue.alpha7.invariants import (
    InvariantCheckResult,
    InvariantEngine,
    InvariantEvaluation,
    InvariantId,
    InvariantStatus,
)
from codex_rescue.alpha7.recovery.backup import BackupEngine, BackupManifest, compute_file_sha256_streaming
from codex_rescue.alpha7.simulation.simulator import RepairSimulator, SimulationResult
from codex_rescue.alpha7.surfaces.desktop import DesktopAdapter, WriterStatus
from codex_rescue.thread_identity import resolve_thread_identity


def compute_file_sha256(path: Path) -> str:
    """Computes SHA-256 hash using streaming 64KB chunks to preserve bounded memory."""
    return compute_file_sha256_streaming(path)


@dataclass
class TableSchemaFingerprint:
    name: str
    columns: List[Dict[str, Any]]
    primary_keys: List[str]
    not_null_columns: List[str]


@dataclass
class SchemaFingerprint:
    db_name: str
    user_version: int
    tables: Dict[str, TableSchemaFingerprint]
    fingerprint_hash: str

    @staticmethod
    def compute(db_path: Path) -> Optional[SchemaFingerprint]:
        if not db_path.exists() or db_path.stat().st_size == 0:
            return None
        try:
            uri = f"file:{db_path.resolve()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1.0)
            try:
                conn.execute("PRAGMA query_only=ON")
                cur = conn.cursor()
                cur.execute("PRAGMA user_version")
                uv = int(cur.fetchone()[0])
                cur.execute("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
                table_names = [str(r[0]) for r in cur.fetchall() if not str(r[0]).startswith("sqlite_")]
                tables: Dict[str, TableSchemaFingerprint] = {}
                h = hashlib.sha256()
                h.update(f"uv:{uv};".encode("utf-8"))

                for t in table_names:
                    cur.execute(f"PRAGMA table_info('{t}')")
                    cols = []
                    pks = []
                    nns = []
                    for row in cur.fetchall():
                        c_info = {
                            "cid": row[0],
                            "name": row[1],
                            "type": row[2],
                            "notnull": row[3],
                            "dflt_value": row[4],
                            "pk": row[5],
                        }
                        cols.append(c_info)
                        if row[5]:
                            pks.append(row[1])
                        if row[3]:
                            nns.append(row[1])
                        h.update(f"{t}.{row[1]}:{row[2]}:{row[3]}:{row[5]};".encode("utf-8"))
                    tables[t] = TableSchemaFingerprint(
                        name=t, columns=cols, primary_keys=pks, not_null_columns=nns
                    )

                return SchemaFingerprint(
                    db_name=db_path.name,
                    user_version=uv,
                    tables=tables,
                    fingerprint_hash=h.hexdigest(),
                )
            finally:
                conn.close()
        except Exception:
            return None


@dataclass
class TransactionResult:
    operation_id: str
    status: str  # "REPAIRED", "ROLLED_BACK", "ROLLBACK_FAILED", "BLOCKED", "STALE_PLAN", "VERIFY_FAILED"
    initial_source_sha256: str
    final_source_sha256: str
    source_preserved: bool
    backup_manifest: Optional[BackupManifest] = None
    applied_mutations_count: int = 0
    message: str = ""
    invariants: List[InvariantCheckResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "status": self.status,
            "source_preserved": self.source_preserved,
            "initial_source_sha256": self.initial_source_sha256,
            "final_source_sha256": self.final_source_sha256,
            "applied_mutations_count": self.applied_mutations_count,
            "message": self.message,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
        }


class TransactionalRepairEngine:
    """Atomic, reversible repair engine for derived SQLite state with real writer guards, schema fingerprinting, and streaming hashing."""

    def __init__(self, codex_home: Optional[Path] = None):
        self.codex_home = codex_home or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex"))
        self.backup_engine = BackupEngine(self.codex_home / "backups")
        self.desktop_adapter = DesktopAdapter(self.codex_home)

    def execute_derived_index_repair(
        self,
        session_file: Path,
        state_db_name: str = "state_5.sqlite",
        proven_metadata: Optional[Dict[str, Any]] = None,
    ) -> TransactionResult:
        op_id = f"tx_{int(time.time()*1000)}"
        invariants: List[InvariantCheckResult] = []

        if not session_file.exists():
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256="",
                final_source_sha256="",
                source_preserved=False,
                message=f"Session file not found: {session_file}",
            )

        # 1. Snapshot precondition & initial source hash via streaming
        sha_before = compute_file_sha256(session_file)
        ident = resolve_thread_identity(session_file)
        session_id = ident.thread_id
        if not session_id:
            inv_id = InvariantCheckResult(
                invariant_id=InvariantId.INV_004,
                status=InvariantStatus.FAIL,
                message=f"Mutation blocked: unresolved ThreadId for {session_file.name}",
            )
            invariants.append(inv_id)
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message=f"Mutation blocked: unresolved logical ThreadId for {session_file.name}",
                invariants=invariants,
            )

        # 2. Check active writer precondition (INV-003) - Fail-closed on ACTIVE or UNKNOWN
        writer_status = self.desktop_adapter.detect_writer_status()
        if writer_status != WriterStatus.INACTIVE_CONFIRMED:
            inv_writer = InvariantCheckResult(
                invariant_id=InvariantId.INV_003,
                status=InvariantStatus.FAIL,
                message=f"Mutation blocked: active writer status is {writer_status.value}",
            )
            invariants.append(inv_writer)
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message=f"Mutation blocked: writer state is {writer_status.value} (fail-closed guard)",
                invariants=invariants,
            )

        inv_writer = InvariantCheckResult(
            invariant_id=InvariantId.INV_003,
            status=InvariantStatus.PASS,
            message="No active Codex writer processes detected.",
        )
        invariants.append(inv_writer)

        # 3. Simulate repair in isolated temp sandbox (INV-015)
        sim_res = RepairSimulator.simulate_derived_index_repair(session_file)
        invariants.extend(sim_res.invariants)
        if not sim_res.safe_to_apply:
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message="Sandbox simulation failed safety invariants.",
                invariants=invariants,
            )

        # 4. Schema Fingerprint & Direct Mutation Gate (INV-007, INV-012)
        # PROHIBITION: Do NOT create a synthetic state_5.sqlite or threads table if none exists!
        target_db = self.codex_home / state_db_name
        target_exists_initially = target_db.exists()

        if not target_exists_initially:
            # Target DB is absent. Do not manufacture synthetic state DB.
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message="Mutation blocked: Target state database does not exist. Hand-crafted DB creation is prohibited (refer to CODEX_DERIVED_STATE_RECOVERY_CONTRACT.md).",
                invariants=invariants,
            )

        fingerprint = SchemaFingerprint.compute(target_db)
        if fingerprint is None or "threads" not in fingerprint.tables:
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message="Mutation blocked: Target database schema is unverified or threads table is missing.",
                invariants=invariants,
            )

        threads_table = fingerprint.tables["threads"]

        # 5. Authoritative Metadata Proof Check (INV-012)
        # Check if an existing row with this ID is already present (NEVER use INSERT OR REPLACE to overwrite)
        try:
            conn_check = sqlite3.connect(str(target_db), timeout=2.0)
            try:
                cur_c = conn_check.cursor()
                cur_c.execute("SELECT id FROM threads WHERE id = ?", (session_id,))
                if cur_c.fetchone():
                    return TransactionResult(
                        operation_id=op_id,
                        status="BLOCKED",
                        initial_source_sha256=sha_before,
                        final_source_sha256=sha_before,
                        source_preserved=True,
                        message=f"Mutation blocked: Thread ID '{session_id}' already exists in threads table (destructive replacement prohibited).",
                        invariants=invariants,
                    )
            finally:
                conn_check.close()
        except Exception as e:
            return TransactionResult(
                operation_id=op_id,
                status="BLOCKED",
                initial_source_sha256=sha_before,
                final_source_sha256=sha_before,
                source_preserved=True,
                message=f"Failed to check existing thread index: {e}",
                invariants=invariants,
            )

        # Vetto's universal recovery contract is copy-only. Even a schema that
        # appears compatible cannot prove every vendor-derived field or future
        # migration invariant, so production SQLite writes stop here.
        return TransactionResult(
            operation_id=op_id,
            status="BLOCKED",
            initial_source_sha256=sha_before,
            final_source_sha256=sha_before,
            source_preserved=True,
            applied_mutations_count=0,
            message=(
                "DIRECT_DERIVED_STATE_MUTATION_DISABLED: vendor SQLite state is "
                "read-only; use snapshot, salvage, portable export/import, or "
                "restore-to-copy instead."
            ),
            invariants=invariants,
        )
