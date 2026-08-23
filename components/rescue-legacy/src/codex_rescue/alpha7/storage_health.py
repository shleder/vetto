from __future__ import annotations

import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from codex_rescue.thread_identity import resolve_thread_identity


@dataclass
class LargeRolloutInfo:
    filename: str
    bytes: int
    thread_id: Optional[str] = None
    rollout_id: Optional[str] = None
    is_archived: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class StorageHealthLimits:
    max_files: int = 50_000
    max_bytes: int = 50 * 1024 * 1024 * 1024  # 50GB
    large_file_threshold_bytes: int = 50 * 1024 * 1024  # 50MB
    oversized_record_threshold_bytes: int = 16 * 1024 * 1024  # 16MB
    timeout_sec: float = 10.0


@dataclass
class StorageHealthReport:
    codex_home_bytes: Optional[int] = None
    codex_home_bytes_status: str = "MEASURED"  # MEASURED, ESTIMATED, UNKNOWN
    sessions_count: int = 0
    archived_sessions_count: int = 0
    rollout_bytes_total: int = 0
    large_rollouts: List[LargeRolloutInfo] = field(default_factory=list)
    oversized_record_candidates: List[Dict[str, Any]] = field(default_factory=list)
    duplicate_physical_sources: List[Dict[str, Any]] = field(default_factory=list)
    unreadable_regions: List[Dict[str, Any]] = field(default_factory=list)
    state_db_sizes: Dict[str, int] = field(default_factory=dict)
    scan_truncated: bool = False
    truncated_by_limit: bool = False
    duration_sec: float = 0.0
    limits: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "codex_home_bytes": self.codex_home_bytes,
            "codex_home_bytes_status": self.codex_home_bytes_status,
            "sessions_count": self.sessions_count,
            "archived_sessions_count": self.archived_sessions_count,
            "rollout_bytes_total": self.rollout_bytes_total,
            "large_rollouts": [r.to_dict() for r in self.large_rollouts],
            "oversized_record_candidates": self.oversized_record_candidates,
            "duplicate_physical_sources": self.duplicate_physical_sources,
            "unreadable_regions": self.unreadable_regions,
            "state_db_sizes": self.state_db_sizes,
            "scan_truncated": self.scan_truncated,
            "truncated_by_limit": self.truncated_by_limit,
            "duration_sec": self.duration_sec,
            "limits": self.limits,
        }


class StorageHealthEngine:
    """Bounded, streaming product diagnostic engine for CODEX_HOME storage and scalability.

    Strictly read-only: does not perform deletions, modifications, or cleanups.
    Does not materialize large JSONL files entirely in memory.
    """

    @staticmethod
    def scan_oversized_records_streaming(
        fpath: Path,
        threshold_bytes: int = 16 * 1024 * 1024,
        max_scan_bytes: int = 100 * 1024 * 1024,
    ) -> tuple[int, int]:
        """Streams up to max_scan_bytes using a 64KB buffer, counting bytes per newline.

        Returns (max_record_bytes, count_of_records_over_threshold).
        Zero whole-line materialization in memory.
        """
        max_record = 0
        oversized_count = 0
        current_len = 0
        total_scanned = 0

        with open(fpath, "rb") as fh:
            while total_scanned < max_scan_bytes:
                chunk = fh.read(65536)
                if not chunk:
                    break
                total_scanned += len(chunk)
                idx = 0
                while True:
                    nl_pos = chunk.find(b"\n", idx)
                    if nl_pos == -1:
                        current_len += len(chunk) - idx
                        if current_len > max_record:
                            max_record = current_len
                        break
                    else:
                        current_len += nl_pos - idx
                        if current_len > max_record:
                            max_record = current_len
                        if current_len >= threshold_bytes:
                            oversized_count += 1
                        current_len = 0
                        idx = nl_pos + 1

        if current_len > max_record:
            max_record = current_len
        if current_len >= threshold_bytes:
            oversized_count += 1

        return max_record, oversized_count

    @staticmethod
    def scan_codex_home(
        codex_home: Path,
        limits: Optional[StorageHealthLimits] = None,
    ) -> StorageHealthReport:
        lim = limits or StorageHealthLimits()
        start_t = time.time()

        report = StorageHealthReport(
            limits={
                "max_files": lim.max_files,
                "max_bytes": lim.max_bytes,
                "large_file_threshold_bytes": lim.large_file_threshold_bytes,
                "oversized_record_threshold_bytes": lim.oversized_record_threshold_bytes,
                "timeout_sec": lim.timeout_sec,
            }
        )

        if not codex_home.exists() or not codex_home.is_dir():
            report.codex_home_bytes_status = "UNKNOWN"
            report.duration_sec = round(time.time() - start_t, 3)
            return report

        total_home_bytes = 0
        total_files_scanned = 0
        is_truncated = False
        seen_hashes: Dict[str, List[str]] = {}

        # 1. State databases scan (state_5.sqlite, goals_1.sqlite, logs_2.sqlite, etc.)
        for db_file in codex_home.glob("*.sqlite*"):
            try:
                st = db_file.stat()
                report.state_db_sizes[db_file.name] = st.st_size
                total_home_bytes += st.st_size
            except OSError:
                report.unreadable_regions.append({"path": str(db_file), "error": "Unreadable state DB"})

        # 2. Sessions and archived sessions scanning (bounded streaming)
        scan_dirs = [
            (codex_home / "sessions", False),
            (codex_home / "archived_sessions", True),
        ]

        for sdir, is_archived in scan_dirs:
            if not sdir.exists():
                continue

            try:
                for root, _, files in os.walk(str(sdir)):
                    for fname in files:
                        total_files_scanned += 1
                        if (
                            total_files_scanned > lim.max_files
                            or total_home_bytes > lim.max_bytes
                            or (time.time() - start_t) > lim.timeout_sec
                        ):
                            is_truncated = True
                            break

                        fpath = Path(root) / fname
                        try:
                            st = fpath.stat()
                            fsize = st.st_size
                            total_home_bytes += fsize

                            if fname.endswith(".jsonl"):
                                report.rollout_bytes_total += fsize
                                if is_archived:
                                    report.archived_sessions_count += 1
                                else:
                                    report.sessions_count += 1

                                # Track physical duplicates by 64KB prefix hash + size
                                try:
                                    with open(fpath, "rb") as fh:
                                        sample = fh.read(65536)
                                        sample_sha = hashlib.sha256(sample).hexdigest()
                                        hash_key = f"{sample_sha}:{fsize}"
                                        if hash_key in seen_hashes:
                                            seen_hashes[hash_key].append(str(fpath))
                                        else:
                                            seen_hashes[hash_key] = [str(fpath)]
                                except Exception:
                                    pass

                                # Resolve identity without stem fallback
                                ident = resolve_thread_identity(fpath)

                                # Check large rollout
                                if fsize >= lim.large_file_threshold_bytes:
                                    report.large_rollouts.append(
                                        LargeRolloutInfo(
                                            filename=fname,
                                            bytes=fsize,
                                            thread_id=ident.thread_id,
                                            rollout_id=ident.filename_rollout_id,
                                            is_archived=is_archived,
                                        )
                                    )

                                # Bounded streaming check for oversized records
                                if fsize >= lim.oversized_record_threshold_bytes:
                                    try:
                                        max_rec, over_cnt = StorageHealthEngine.scan_oversized_records_streaming(
                                            fpath,
                                            threshold_bytes=lim.oversized_record_threshold_bytes,
                                        )
                                        if over_cnt > 0 or max_rec >= lim.oversized_record_threshold_bytes:
                                            report.oversized_record_candidates.append(
                                                {
                                                    "filename": fname,
                                                    "bytes": fsize,
                                                    "thread_id": ident.thread_id,
                                                    "max_record_bytes": max_rec,
                                                    "oversized_records_count": over_cnt,
                                                }
                                            )
                                    except Exception:
                                        pass
                        except OSError as e:
                            report.unreadable_regions.append({"path": str(fpath), "error": str(e)})

                    if is_truncated:
                        break
            except Exception as e:
                report.unreadable_regions.append({"path": str(sdir), "error": str(e)})

        # Record physical duplicate sources sharing prefix hash + size
        for hkey, paths in seen_hashes.items():
            if len(paths) > 1:
                h_sha, h_bytes = hkey.split(":")
                report.duplicate_physical_sources.append(
                    {
                        "prefix_sha256": h_sha,
                        "bytes": int(h_bytes),
                        "paths": paths,
                    }
                )

        report.codex_home_bytes = total_home_bytes
        report.codex_home_bytes_status = "ESTIMATED" if is_truncated else "MEASURED"
        report.scan_truncated = is_truncated
        report.truncated_by_limit = is_truncated
        report.duration_sec = round(time.time() - start_t, 3)

        return report
