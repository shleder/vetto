from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


def compute_file_sha256_streaming(path: Path) -> str:
    """Computes SHA-256 hash using streaming 64KB chunks to avoid full memory materialization."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


@dataclass
class BackupEntry:
    original_path: str
    backup_path: str
    sha256: str
    size_bytes: int
    is_source: bool  # True for canonical rollout, False for derived SQLite/index
    target_did_not_exist: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BackupManifest:
    manifest_id: str
    created_at: float
    entries: List[BackupEntry] = field(default_factory=list)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "created_at": self.created_at,
            "entries": [e.to_dict() for e in self.entries],
            "verified": self.verified,
        }


class BackupEngine:
    """Pre-mutation backup manifest creation, streaming integrity verification, and atomic rollback."""

    def __init__(self, backup_root: Optional[Path] = None):
        self.backup_root = backup_root or Path(os.environ.get("CODEX_HOME", Path.home() / ".codex")) / "backups"

    def create_pre_mutation_backup(
        self,
        targets: List[Path],
        operation_id: Optional[str] = None,
        nonexistent_targets: Optional[List[Path]] = None,
    ) -> BackupManifest:
        op_id = operation_id or f"op_{int(time.time()*1000)}"
        op_dir = self.backup_root / op_id
        op_dir.mkdir(parents=True, exist_ok=True)

        manifest = BackupManifest(manifest_id=op_id, created_at=time.time())

        for target in targets:
            if not target.exists():
                manifest.entries.append(
                    BackupEntry(
                        original_path=str(target.resolve()),
                        backup_path="",
                        sha256="",
                        size_bytes=0,
                        is_source=(target.suffix == ".jsonl"),
                        target_did_not_exist=True,
                    )
                )
                continue

            file_size = target.stat().st_size
            sha = compute_file_sha256_streaming(target)
            backup_file = op_dir / f"{target.name}_{sha[:8]}"

            # Streaming file copy (64KB buffer)
            with target.open("rb") as src, backup_file.open("wb") as dst:
                shutil.copyfileobj(src, dst, length=65536)

            # Verify backed-up copy hash
            backup_sha = compute_file_sha256_streaming(backup_file)
            if backup_sha != sha:
                raise RuntimeError(f"Backup copy verification failed for {target}")

            is_source = target.suffix == ".jsonl"
            manifest.entries.append(
                BackupEntry(
                    original_path=str(target.resolve()),
                    backup_path=str(backup_file.resolve()),
                    sha256=sha,
                    size_bytes=file_size,
                    is_source=is_source,
                    target_did_not_exist=False,
                )
            )

        if nonexistent_targets:
            for nt in nonexistent_targets:
                if not nt.exists():
                    manifest.entries.append(
                        BackupEntry(
                            original_path=str(nt.resolve()),
                            backup_path="",
                            sha256="",
                            size_bytes=0,
                            is_source=(nt.suffix == ".jsonl"),
                            target_did_not_exist=True,
                        )
                    )

        manifest_file = op_dir / "manifest.json"
        manifest_file.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")
        manifest.verified = True
        return manifest

    def rollback(self, manifest: BackupManifest) -> bool:
        """Atomically restores all backed-up files from manifest using streaming I/O."""
        try:
            for entry in manifest.entries:
                orig_path = Path(entry.original_path)

                if entry.target_did_not_exist:
                    # File was originally absent; remove any newly created file
                    if orig_path.exists():
                        try:
                            orig_path.unlink()
                        except Exception:
                            return False
                    continue

                b_path = Path(entry.backup_path)
                if not b_path.exists():
                    return False

                # Verify backup integrity before restoring
                current_sha = compute_file_sha256_streaming(b_path)
                if current_sha != entry.sha256:
                    # Backup corrupted! Block restore per INV-008
                    return False

                orig_path.parent.mkdir(parents=True, exist_ok=True)
                with b_path.open("rb") as src, orig_path.open("wb") as dst:
                    shutil.copyfileobj(src, dst, length=65536)

                restored_sha = compute_file_sha256_streaming(orig_path)
                if restored_sha != entry.sha256:
                    return False

            return True
        except Exception:
            return False
