from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple


def compute_file_sha256_streaming(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class RecordClassification:
    VALID = "VALID"
    VALID_BUT_OVERSIZED = "VALID_BUT_OVERSIZED"
    MALFORMED_RECORD = "MALFORMED_RECORD"
    TRUNCATED_TRANSCRIPT = "TRUNCATED_TRANSCRIPT"
    UNCLASSIFIED_BYTES = "UNCLASSIFIED_BYTES"
    INVALID_UTF8 = "INVALID_UTF8"


class SourceStatus:
    HEALTHY = "HEALTHY"
    VALID_BUT_OVERSIZED = "VALID_BUT_OVERSIZED"
    TRUNCATED_TRANSCRIPT = "TRUNCATED_TRANSCRIPT"
    CORRUPTED = "CORRUPTED"
    INCOMPLETE_SCAN = "INCOMPLETE_SCAN"


@dataclass
class StreamSalvageResult:
    total_bytes: int = 0
    scanned_bytes: int = 0
    valid_records_count: int = 0
    oversized_records_count: int = 0
    malformed_records_count: int = 0
    invalid_utf8_count: int = 0
    unclassified_bytes: int = 0
    has_truncated_tail: bool = False
    valid_prefix_bytes: int = 0
    largest_record_bytes: int = 0
    source_status: str = SourceStatus.HEALTHY

    @property
    def is_migration_safe(self) -> bool:
        """Returns True only if all records are valid with 0 malformed records and 0 truncation."""
        return self.source_status in (SourceStatus.HEALTHY, SourceStatus.VALID_BUT_OVERSIZED)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_bytes": self.total_bytes,
            "scanned_bytes": self.scanned_bytes,
            "valid_records_count": self.valid_records_count,
            "oversized_records_count": self.oversized_records_count,
            "malformed_records_count": self.malformed_records_count,
            "invalid_utf8_count": self.invalid_utf8_count,
            "unclassified_bytes": self.unclassified_bytes,
            "has_truncated_tail": self.has_truncated_tail,
            "valid_prefix_bytes": self.valid_prefix_bytes,
            "largest_record_bytes": self.largest_record_bytes,
            "source_status": self.source_status,
            "is_migration_safe": self.is_migration_safe,
        }


class StreamSalvageEngine:
    """Canonical bounded, memory-efficient JSONL salvage scanner for Codex Rescue."""

    def __init__(self, oversized_threshold: int = 1_000_000, chunk_size: int = 65536):
        self.oversized_threshold = oversized_threshold
        self.chunk_size = chunk_size

    def scan_file(self, file_path: Path) -> StreamSalvageResult:
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        total_size = file_path.stat().st_size
        with open(file_path, "rb") as f:
            return self.scan_stream(f, total_size=total_size)

    def scan_stream(self, stream: Any, total_size: Optional[int] = None) -> StreamSalvageResult:
        result = StreamSalvageResult(total_bytes=total_size or 0)
        valid_prefix_offset = 0
        is_still_clean_prefix = True
        line_no = 0

        while True:
            line = stream.readline()
            if not line:
                break

            line_len = len(line)
            result.scanned_bytes += line_len
            line_no += 1

            if line_len > result.largest_record_bytes:
                result.largest_record_bytes = line_len

            stripped = line.strip()
            if not stripped:
                if is_still_clean_prefix:
                    valid_prefix_offset = result.scanned_bytes
                continue

            if b"\x00" in line:
                result.malformed_records_count += 1
                is_still_clean_prefix = False
                continue

            # Strict UTF-8 decoding without errors="replace"
            try:
                decoded = stripped.decode("utf-8")
            except UnicodeDecodeError:
                result.invalid_utf8_count += 1
                result.malformed_records_count += 1
                is_still_clean_prefix = False
                continue

            try:
                parsed = json.loads(decoded)
                if line_len > self.oversized_threshold:
                    result.oversized_records_count += 1
                else:
                    result.valid_records_count += 1

                if is_still_clean_prefix:
                    valid_prefix_offset = result.scanned_bytes

            except Exception:
                # Check if this malformed record occurs at EOF (tail truncation)
                is_at_eof = (total_size is not None and result.scanned_bytes == total_size)
                if is_at_eof or getattr(stream, "peek", lambda: b"")() == b"":
                    result.has_truncated_tail = True
                else:
                    result.malformed_records_count += 1
                is_still_clean_prefix = False

        result.valid_prefix_bytes = valid_prefix_offset
        if total_size is not None:
            result.unclassified_bytes = max(0, total_size - result.scanned_bytes)
        else:
            result.total_bytes = result.scanned_bytes

        # Determine normalized canonical status
        if result.malformed_records_count > 0:
            result.source_status = SourceStatus.CORRUPTED
        elif result.has_truncated_tail:
            result.source_status = SourceStatus.TRUNCATED_TRANSCRIPT
        elif result.unclassified_bytes > 0:
            result.source_status = SourceStatus.INCOMPLETE_SCAN
        elif result.oversized_records_count > 0:
            result.source_status = SourceStatus.VALID_BUT_OVERSIZED
        else:
            result.source_status = SourceStatus.HEALTHY

        return result

    def salvage_to_target(self, source_path: Path, target_path: Path) -> SalvageManifest:
        """Salvages valid prefix of damaged transcript to explicit target without in-place mutation."""
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {source_path}")
        if source_path.resolve() == target_path.resolve():
            raise ValueError("Salvage target must not be the same as the source file (in-place mutation forbidden).")

        scan_result = self.scan_file(source_path)
        source_sha = compute_file_sha256_streaming(source_path)

        target_path.parent.mkdir(parents=True, exist_ok=True)
        salvaged_bytes = 0
        with open(source_path, "rb") as src, open(target_path, "wb") as dst:
            if scan_result.valid_prefix_bytes > 0:
                remaining = scan_result.valid_prefix_bytes
                while remaining > 0:
                    chunk_to_read = min(self.chunk_size, remaining)
                    buf = src.read(chunk_to_read)
                    if not buf:
                        break
                    dst.write(buf)
                    salvaged_bytes += len(buf)
                    remaining -= len(buf)

        target_sha = compute_file_sha256_streaming(target_path) if salvaged_bytes > 0 else ""

        return SalvageManifest(
            source_path=str(source_path.resolve()),
            target_path=str(target_path.resolve()),
            source_sha256=source_sha,
            target_sha256=target_sha,
            source_total_bytes=scan_result.total_bytes,
            salvaged_bytes=salvaged_bytes,
            valid_records_count=scan_result.valid_records_count,
            oversized_records_count=scan_result.oversized_records_count,
            malformed_records_count=scan_result.malformed_records_count,
            source_status=scan_result.source_status,
        )

    def salvage_forensic_session(
        self,
        source_path: Path,
        target_path: Path,
        recovered_tail_events: Optional[List[Dict[str, Any]]] = None,
    ) -> SalvageManifest:
        """Forensically salvages valid records and safely appends recovered tail events (e.g. lost_tail_after_compaction).

        Strictly read-only on source_path; writes output exclusively to target_path.
        """
        manifest = self.salvage_to_target(source_path, target_path)
        if recovered_tail_events:
            additional_bytes = 0
            additional_records = 0
            with open(target_path, "a", encoding="utf-8") as dst:
                marker = {
                    "type": "rescue_recovered_tail",
                    "payload": {
                        "provenance": "codex-rescue-forensic-salvage",
                        "recovered_records": len(recovered_tail_events),
                    },
                }
                marker_line = json.dumps(marker, ensure_ascii=False) + "\n"
                dst.write(marker_line)
                additional_bytes += len(marker_line.encode("utf-8"))
                for event in recovered_tail_events:
                    line = json.dumps(event, ensure_ascii=False) + "\n"
                    dst.write(line)
                    additional_bytes += len(line.encode("utf-8"))
                    additional_records += 1
            manifest.salvaged_bytes += additional_bytes
            manifest.valid_records_count += additional_records
            manifest.target_sha256 = compute_file_sha256_streaming(target_path)
        return manifest


@dataclass
class SalvageManifest:
    source_path: str
    target_path: str
    source_sha256: str
    target_sha256: str
    source_total_bytes: int
    salvaged_bytes: int
    valid_records_count: int
    oversized_records_count: int
    malformed_records_count: int
    source_status: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_path": self.source_path,
            "target_path": self.target_path,
            "source_sha256": self.source_sha256,
            "target_sha256": self.target_sha256,
            "source_total_bytes": self.source_total_bytes,
            "salvaged_bytes": self.salvaged_bytes,
            "valid_records_count": self.valid_records_count,
            "oversized_records_count": self.oversized_records_count,
            "malformed_records_count": self.malformed_records_count,
            "source_status": self.source_status,
        }
