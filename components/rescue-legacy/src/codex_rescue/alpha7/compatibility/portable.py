from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from codex_rescue.alpha7.graph import PathNamespace, detect_path_namespace
from codex_rescue.alpha7.invariants import (
    InvariantCheckResult,
    InvariantEngine,
    InvariantEvaluation,
    InvariantId,
    InvariantStatus,
)
from codex_rescue.alpha7.recovery.salvage_stream import SourceStatus, StreamSalvageEngine
from codex_rescue.alpha7.simulation.transaction import SchemaFingerprint, compute_file_sha256


from codex_rescue.thread_identity import resolve_thread_identity


@dataclass
class PortableManifest:
    package_version: str
    rollout_filename: str
    rollout_sha256: str
    rollout_bytes: int
    created_at: float
    source_platform: str
    source_namespace: str
    session_id: Optional[str] = None
    thread_id: Optional[str] = None
    rollout_id: Optional[str] = None
    identity_status: str = "UNKNOWN"  # RESOLVED, UNRESOLVED, CONFLICT
    identity_confidence: str = "UNKNOWN"
    identity_conflict: bool = False
    source_integrity: str = SourceStatus.HEALTHY  # HEALTHY, VALID_BUT_OVERSIZED, CORRUPTED, TRUNCATED_TRANSCRIPT
    records_count: int = 0
    package_classification: str = "SAFE_MIGRATION_PACKAGE"  # SAFE_MIGRATION_PACKAGE, FORENSIC_PACKAGE
    archive_state: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_version": self.package_version,
            "session_id": self.session_id,
            "thread_id": self.thread_id,
            "rollout_id": self.rollout_id,
            "rollout_filename": self.rollout_filename,
            "rollout_sha256": self.rollout_sha256,
            "rollout_bytes": self.rollout_bytes,
            "created_at": self.created_at,
            "source_platform": self.source_platform,
            "source_namespace": self.source_namespace,
            "source_integrity": self.source_integrity,
            "identity_status": self.identity_status,
            "identity_confidence": self.identity_confidence,
            "identity_conflict": self.identity_conflict,
            "records_count": self.records_count,
            "package_classification": self.package_classification,
            "archive_state": self.archive_state,
            "metadata": self.metadata,
        }


@dataclass
class ImportPlan:
    session_id: Optional[str]
    target_rollout_path: str
    conflict_detected: bool
    conflict_reason: Optional[str]
    safe_to_import: bool
    requires_remapping: bool
    package_classification: str = "SAFE_MIGRATION_PACKAGE"
    stage: str = "VALIDATED"  # VALIDATED, STAGED, SOURCE_COPIED, INDEX_VISIBLE, SURFACE_VISIBLE, VERIFIED, BLOCKED
    invariants: List[InvariantCheckResult] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return self.safe_to_import

    @property
    def has_conflict(self) -> bool:
        return self.conflict_detected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_rollout_path": self.target_rollout_path,
            "conflict_detected": self.conflict_detected,
            "conflict_reason": self.conflict_reason,
            "safe_to_import": self.safe_to_import,
            "requires_remapping": self.requires_remapping,
            "package_classification": self.package_classification,
            "stage": self.stage,
            "invariants": [
                {"id": i.invariant_id.value, "status": i.status.value, "message": i.message}
                for i in self.invariants
            ],
        }


class PortableSessionEngine:
    """Exports and imports portable session packages using canonical integrity scans and secure archive validation."""

    @staticmethod
    def export_session(
        session_path: Path,
        output_zip_path: Path,
        metadata: Optional[Dict[str, Any]] = None,
        workspace_path: Optional[str] = None,
        is_archived: bool = False,
    ) -> PortableManifest:
        if not session_path.exists():
            raise FileNotFoundError(f"Session file not found: {session_path}")

        # 1. Canonical source scan
        salvage_engine = StreamSalvageEngine()
        salvage_res = salvage_engine.scan_file(session_path)

        sha = compute_file_sha256(session_path)
        file_size = session_path.stat().st_size
        
        ident = resolve_thread_identity(session_path)
        thread_id = ident.thread_id
        rollout_id = ident.filename_rollout_id
        session_id = thread_id

        meta = dict(metadata or {})
        if workspace_path:
            meta["workspace_path"] = workspace_path

        # If identity is unresolved or has conflict, migration is strictly blocked (forensic only)
        identity_status = "CONFLICT" if ident.conflict else ("RESOLVED" if thread_id else "UNRESOLVED")
        if thread_id is None or ident.conflict:
            classification = "FORENSIC_PACKAGE"
        else:
            classification = (
                "SAFE_MIGRATION_PACKAGE"
                if salvage_res.is_migration_safe
                else "FORENSIC_PACKAGE"
            )

        ns = detect_path_namespace(session_path)
        manifest = PortableManifest(
            package_version="1.0",
            session_id=session_id,
            thread_id=thread_id,
            rollout_id=rollout_id,
            identity_status=identity_status,
            identity_confidence=ident.confidence,
            identity_conflict=ident.conflict,
            rollout_filename=session_path.name,
            rollout_sha256=sha,
            rollout_bytes=file_size,
            created_at=time.time(),
            source_platform=os.name,
            source_namespace=ns.value,
            source_integrity=salvage_res.source_status,
            records_count=salvage_res.valid_records_count + salvage_res.oversized_records_count,
            package_classification=classification,
            archive_state=is_archived,
            metadata=meta,
        )

        output_zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(output_zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", json.dumps(manifest.to_dict(), indent=2))
            zf.write(session_path, arcname=session_path.name)

        return manifest

    @staticmethod
    def validate_zip_security(zf: zipfile.ZipFile) -> None:
        """Enforces canonical archive entry security and zip bomb protection."""
        seen_names: Set[str] = set()
        total_uncompressed = 0
        total_compressed = 0

        for info in zf.infolist():
            name = info.filename
            # Normalize and reject path traversal attacks
            if "\x00" in name:
                raise ValueError(f"Zip entry contains NUL byte: {name}")
            if ".." in name.replace("\\", "/").split("/"):
                raise ValueError(f"Zip path traversal detected: {name}")
            if name.startswith("/") or name.startswith("\\"):
                raise ValueError(f"Absolute zip entry detected: {name}")
            if len(name) > 1 and name[1] == ":":
                raise ValueError(f"Windows drive path detected in zip: {name}")
            if name.startswith("//") or name.startswith("\\\\"):
                raise ValueError(f"UNC path detected in zip: {name}")

            norm_name = name.replace("\\", "/").lower()
            if norm_name in seen_names:
                raise ValueError(f"Duplicate zip entry detected: {name}")
            seen_names.add(norm_name)

            total_uncompressed += info.file_size
            total_compressed += info.compress_size or 1

        # Zip bomb protection: max ratio 100x and max size 5GB
        if total_uncompressed > 5 * 1024 * 1024 * 1024:
            raise ValueError("Oversized uncompressed archive (>5GB)")
        if total_uncompressed > 100 * total_compressed and total_uncompressed > 10 * 1024 * 1024:
            raise ValueError(f"Zip bomb expansion ratio exceeded: {total_uncompressed}/{total_compressed}")

    @staticmethod
    def inspect_package(package_zip_path: Path) -> PortableManifest:
        if not package_zip_path.exists():
            raise FileNotFoundError(f"Package not found: {package_zip_path}")

        try:
            with zipfile.ZipFile(package_zip_path, "r") as zf:
                # 1. Security validation of zip entries
                PortableSessionEngine.validate_zip_security(zf)

                if "manifest.json" not in zf.namelist():
                    raise ValueError("Package missing manifest.json")

                manifest_info = zf.getinfo("manifest.json")
                if manifest_info.file_size > 1024 * 1024:
                    raise ValueError("Oversized manifest.json (>1MB)")

                manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))

                # 2. Verify declared payload exists
                fname = manifest_data["rollout_filename"]
                if fname not in zf.namelist():
                    raise ValueError(f"Package missing declared rollout file: {fname}")

                # 3. Stream hash payload to verify integrity without full memory materialization
                calc_sha = hashlib.sha256()
                with zf.open(fname) as z_in:
                    while True:
                        chunk = z_in.read(65536)
                        if not chunk:
                            break
                        calc_sha.update(chunk)

                if calc_sha.hexdigest() != manifest_data["rollout_sha256"]:
                    raise ValueError("Package integrity check failed: SHA-256 mismatch")

                return PortableManifest(**manifest_data)
        except zipfile.BadZipFile as e:
            raise ValueError(f"Corrupt or invalid zip archive: {e}")

    @staticmethod
    def plan_import(
        package_zip_path: Path,
        target_codex_home: Path,
    ) -> ImportPlan:
        manifest = PortableSessionEngine.inspect_package(package_zip_path)
        invariants: List[InvariantCheckResult] = []

        # Check source integrity: forensic packages cannot be imported as standard migration (INV-004)
        is_safe_pkg = (manifest.package_classification == "SAFE_MIGRATION_PACKAGE") and (
            manifest.source_integrity in (SourceStatus.HEALTHY, SourceStatus.VALID_BUT_OVERSIZED)
        )
        inv_src = InvariantCheckResult(
            invariant_id=InvariantId.INV_004,
            status=InvariantStatus.PASS if is_safe_pkg else InvariantStatus.FAIL,
            message="Source package integrity is migration-safe." if is_safe_pkg else f"Source package integrity is {manifest.source_integrity} ({manifest.package_classification}); migration blocked.",
        )
        invariants.append(inv_src)

        target_dir = (
            target_codex_home / "archived_sessions"
            if manifest.archive_state
            else target_codex_home / "sessions"
        )
        target_file = target_dir / manifest.rollout_filename

        conflict = False
        reason = None
        if target_file.exists():
            conflict = True
            reason = f"Target session file already exists: {target_file}"

        safe = is_safe_pkg and not conflict

        return ImportPlan(
            session_id=manifest.session_id,
            target_rollout_path=str(target_file),
            conflict_detected=conflict,
            conflict_reason=reason,
            safe_to_import=safe,
            requires_remapping=(manifest.source_platform != os.name),
            package_classification=manifest.package_classification,
            invariants=invariants,
        )

    @staticmethod
    def execute_import(
        package_zip_path: Path,
        target_codex_home: Path,
        plan: Optional[ImportPlan] = None,
        dry_run: bool = False,
        stage_only: bool = False,
    ) -> Dict[str, Any]:
        active_plan = plan or PortableSessionEngine.plan_import(package_zip_path, target_codex_home)
        if not active_plan.safe_to_import:
            return {
                "success": False,
                "action": "BLOCKED",
                "stage": "BLOCKED",
                "reason": active_plan.conflict_reason or "Import preconditions not satisfied",
                "index_visible": False,
                "surface_visible": False,
            }

        if dry_run:
            return {
                "success": True,
                "action": "DRY_RUN_PASSED",
                "stage": "VALIDATED",
                "plan": active_plan.to_dict(),
                "index_visible": False,
                "surface_visible": False,
            }

        manifest = PortableSessionEngine.inspect_package(package_zip_path)
        
        # Staging path in Rescue staging area
        staging_dir = target_codex_home / ".rescue_staging"
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_target = staging_dir / manifest.rollout_filename

        # 1. Stream write payload to staging target
        try:
            with zipfile.ZipFile(package_zip_path, "r") as zf:
                with zf.open(manifest.rollout_filename) as src, staged_target.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=65536)
        except Exception as e:
            if staged_target.exists():
                try:
                    staged_target.unlink()
                except Exception:
                    pass
            return {
                "success": False,
                "action": "ROLLED_BACK",
                "stage": "BLOCKED",
                "reason": f"Failed to extract rollout payload: {e}",
                "index_visible": False,
                "surface_visible": False,
            }

        # 2. Verify extracted file hash
        extracted_sha = compute_file_sha256(staged_target)
        if extracted_sha != manifest.rollout_sha256:
            if staged_target.exists():
                try:
                    staged_target.unlink()
                except Exception:
                    pass
            return {
                "success": False,
                "action": "ROLLED_BACK",
                "stage": "BLOCKED",
                "reason": "Extracted file hash verification failed",
                "index_visible": False,
                "surface_visible": False,
            }

        if stage_only:
            return {
                "success": True,
                "action": "STAGED",
                "stage": "STAGED",
                "session_id": manifest.session_id,
                "target_path": str(staged_target),
                "index_visible": False,
                "surface_visible": False,
            }

        # 3. Live Codex import contract:
        # Without a supported, official Codex session registration API,
        # copying a JSONL is NOT INDEX_VISIBLE or SURFACE_VISIBLE.
        # Direct derived SQLite mutation remains HOLD.
        # Live import fails closed with IMPORT_BLOCKED.
        return {
            "success": False,
            "action": "IMPORT_BLOCKED",
            "stage": "STAGED",
            "reason": "NO_SUPPORTED_CODEX_REGISTRATION_PATH",
            "session_id": manifest.session_id,
            "staging_path": str(staged_target),
            "index_visible": False,
            "surface_visible": False,
            "note": "Session payload staged and verified; live Codex registration blocked because no supported registration path exists.",
        }
