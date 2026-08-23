from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .discovery_alpha5 import discover_sessions
from .doctor import doctor_session
from .evidence import collect_session_evidence
from .redact import sanitize_path
from .thread_identity import parse_rollout_filename


def compute_file_fingerprint(p: Path) -> dict[str, Any] | None:
    try:
        stat = p.stat()
        mtime_ns = getattr(stat, "st_mtime_ns", int(stat.st_mtime * 1e9))
        size = stat.st_size

        h = hashlib.sha256()
        with open(p, "rb") as f:
            head = f.read(4096)
            h.update(head)
            if size > 8192:
                f.seek(max(0, size - 4096))
                tail = f.read(4096)
                h.update(tail)
            elif size > 4096:
                tail = f.read(size - 4096)
                h.update(tail)

        sample_hash = h.hexdigest()
        return {
            "mtime_ns": mtime_ns,
            "size": size,
            "sample_hash": sample_hash,
            "mtime": stat.st_mtime,
        }
    except Exception:
        return None


def _filename_thread_id(path: Path) -> str | None:
    parsed = parse_rollout_filename(path)
    return parsed.thread_id if parsed else None


@dataclass
class BatchDoctorSummary:
    sessions_scanned: int = 0
    healthy: int = 0
    warnings_findings: int = 0
    unsupported: int = 0
    scan_failures: int = 0
    results: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def render_text(self) -> str:
        lines = [
            "Batch Doctor Analysis Summary\n",
            f"Sessions Scanned:    {self.sessions_scanned}",
            f"Healthy:             {self.healthy}",
            f"Warnings/Findings:   {self.warnings_findings}",
            f"Unsupported/Opaque:  {self.unsupported}",
            f"Scan Failures:       {self.scan_failures}",
            "\nSession Results:",
        ]
        for r in self.results:
            status_flag = r.get("status", "UNKNOWN")
            session_ref = r.get("session_id") or "UNKNOWN"
            findings_str = f" [{', '.join(r.get('findings', []))}]" if r.get("findings") else ""
            lines.append(f"  * {session_ref:<36} {status_flag}{findings_str}")
        return "\n".join(lines)


def run_doctor_all(
    codex_home: Path | str | None = None,
    limit: int = 500,
    oversized_threshold: int = 1_000_000,
) -> BatchDoctorSummary:
    home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"
    summary = BatchDoctorSummary()

    if not home.exists():
        return summary

    session_paths: list[Path] = []
    for pat in ("sessions/*.jsonl", "archived_sessions/*.jsonl", "subagents/*.jsonl", "*.jsonl"):
        session_paths.extend(home.glob(pat))

    unique_paths = sorted(list({p.resolve() for p in session_paths}))[:limit]

    for p in unique_paths:
        summary.sessions_scanned += 1
        try:
            doc_res = doctor_session(p, oversized_threshold=oversized_threshold)
            res_dict = doc_res.to_dict() if hasattr(doc_res, "to_dict") else dict(doc_res)
            st = str(res_dict.get("status", "UNKNOWN"))
            identity = res_dict.get("thread_identity") if isinstance(res_dict.get("thread_identity"), dict) else {}
            session_id = identity.get("thread_id")

            if st == "HEALTHY":
                summary.healthy += 1
            elif st in ("UNSUPPORTED", "OPAQUE"):
                summary.unsupported += 1
            elif st in ("CORRUPT", "UNKNOWN_CORRUPTION", "UNREADABLE", "MALFORMED_RECORD", "TRUNCATED_TRANSCRIPT", "CORRUPTED_TOOL_CALL"):
                summary.scan_failures += 1
            else:
                summary.warnings_findings += 1

            summary.results.append({
                "session_id": session_id,
                "path": sanitize_path(p),
                "status": st,
                "findings": res_dict.get("findings", []),
            })
        except Exception as e:
            summary.scan_failures += 1
            summary.results.append({
                "session_id": _filename_thread_id(p),
                "path": sanitize_path(p),
                "status": "SCAN_EXCEPTION",
                "findings": ["SCAN_READ_ERROR"],
                "error": str(e),
            })

    return summary


def run_doctor_changed(
    codex_home: Path | str | None = None,
    cache_path: Path | str | None = None,
    oversized_threshold: int = 1_000_000,
) -> BatchDoctorSummary:
    home = Path(codex_home).resolve() if codex_home else Path.home() / ".codex"
    c_file = Path(cache_path) if cache_path else home / ".cache_doctor.json"

    cache_data: dict[str, Any] = {}
    if c_file.exists():
        try:
            raw = json.loads(c_file.read_text(encoding="utf-8"))
            if raw.get("version") == 3 and isinstance(raw.get("entries"), dict):
                cache_data = raw["entries"]
        except Exception:
            cache_data = {}

    summary = BatchDoctorSummary()
    session_paths: list[Path] = []
    if home.exists():
        for pat in ("sessions/*.jsonl", "archived_sessions/*.jsonl", "subagents/*.jsonl", "*.jsonl"):
            session_paths.extend(home.glob(pat))

    unique_paths = sorted(list({p.resolve() for p in session_paths}))
    new_cache: dict[str, Any] = {}
    now = time.time()

    for p in unique_paths:
        summary.sessions_scanned += 1
        p_str = str(p.resolve())
        fp = compute_file_fingerprint(p)

        cached_entry = cache_data.get(p_str)
        is_cache_valid = (
            fp is not None
            and (now - fp.get("mtime", 0.0) >= 2.0)
            and cached_entry is not None
            and cached_entry.get("mtime_ns") == fp["mtime_ns"]
            and cached_entry.get("size") == fp["size"]
            and cached_entry.get("sample_hash") == fp["sample_hash"]
            and "status" in cached_entry
            and "session_id" in cached_entry
        )

        if is_cache_valid and cached_entry:
            st = cached_entry["status"]
            findings = cached_entry.get("findings", [])
            session_id = cached_entry.get("session_id")
            new_cache[p_str] = cached_entry
        else:
            try:
                doc_res = doctor_session(p, oversized_threshold=oversized_threshold)
                res_dict = doc_res.to_dict() if hasattr(doc_res, "to_dict") else dict(doc_res)
                st = str(res_dict.get("status", "UNKNOWN"))
                findings = res_dict.get("findings", [])
                identity = res_dict.get("thread_identity") if isinstance(res_dict.get("thread_identity"), dict) else {}
                session_id = identity.get("thread_id")
            except Exception:
                st = "SCAN_EXCEPTION"
                findings = ["SCAN_READ_ERROR"]
                session_id = _filename_thread_id(p)

            if fp:
                new_cache[p_str] = {
                    "mtime_ns": fp["mtime_ns"],
                    "size": fp["size"],
                    "sample_hash": fp["sample_hash"],
                    "mtime": fp["mtime"],
                    "status": st,
                    "findings": findings,
                    "session_id": session_id,
                }

        if st == "HEALTHY":
            summary.healthy += 1
        elif st in ("UNSUPPORTED", "OPAQUE"):
            summary.unsupported += 1
        elif st in ("CORRUPT", "UNKNOWN_CORRUPTION", "UNREADABLE", "SCAN_EXCEPTION", "MALFORMED_RECORD", "TRUNCATED_TRANSCRIPT", "CORRUPTED_TOOL_CALL"):
            summary.scan_failures += 1
        else:
            summary.warnings_findings += 1

        summary.results.append({
            "session_id": session_id,
            "path": sanitize_path(p),
            "status": st,
            "findings": findings,
        })

    try:
        c_file.parent.mkdir(parents=True, exist_ok=True)
        c_file.write_text(
            json.dumps({"version": 3, "entries": new_cache}, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except Exception:
        pass

    return summary
