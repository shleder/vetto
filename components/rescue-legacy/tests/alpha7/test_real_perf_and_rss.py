from __future__ import annotations

import io
import os
import platform
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from codex_rescue.alpha7.compatibility.portable import PortableSessionEngine
from codex_rescue.alpha7.recovery.backup import BackupEngine
from codex_rescue.alpha7.recovery.salvage_stream import StreamSalvageEngine
from codex_rescue.alpha7.simulation.transaction import compute_file_sha256


def get_current_rss_mb() -> float:
    """Returns current process Resident Set Size (RSS) in megabytes."""
    system = platform.system()
    if system == "Linux":
        try:
            with open("/proc/self/status", "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        return float(parts[1]) / 1024.0
        except Exception:
            pass
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss / 1024.0
        except Exception:
            return 0.0
    elif system == "Darwin":
        try:
            import resource
            usage = resource.getrusage(resource.RUSAGE_SELF)
            return usage.ru_maxrss / (1024.0 * 1024.0)
        except Exception:
            return 0.0
    elif system == "Windows":
        try:
            import ctypes
            from ctypes import wintypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", wintypes.DWORD),
                    ("PageFaultCount", wintypes.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            fn = ctypes.windll.psapi.GetProcessMemoryInfo
            fn.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESS_MEMORY_COUNTERS), wintypes.DWORD]
            fn.restype = wintypes.BOOL
            if fn(handle, ctypes.byref(counters), ctypes.sizeof(counters)):
                return counters.WorkingSetSize / (1024.0 * 1024.0)
        except Exception:
            return 0.0
    return 0.0


class RSSSampler:
    """Samples process RSS every 5-10ms during execution to capture true peak memory."""

    def __init__(self, interval_sec: float = 0.005):
        self.interval = interval_sec
        self._running = False
        self.baseline_mb = 0.0
        self.peak_mb = 0.0
        self.final_mb = 0.0
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        self.baseline_mb = get_current_rss_mb()
        self.peak_mb = self.baseline_mb
        self._running = True
        self._thread = threading.Thread(target=self._sample_loop, daemon=True, name="RSSMonitor")
        self._thread.start()

    def _sample_loop(self) -> None:
        while self._running:
            cur = get_current_rss_mb()
            if cur > self.peak_mb:
                self.peak_mb = cur
            time.sleep(self.interval)

    def stop(self) -> dict:
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.2)
        self.final_mb = get_current_rss_mb()
        if self.final_mb > self.peak_mb:
            self.peak_mb = self.final_mb
        return {
            "baseline_mb": self.baseline_mb,
            "peak_mb": self.peak_mb,
            "final_mb": self.final_mb,
            "peak_delta_mb": max(0.0, self.peak_mb - self.baseline_mb),
        }


class RealPerfAndRSSTests(unittest.TestCase):
    def test_10mb_streaming_rss_measured(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bench_10mb.jsonl"
            line = '{"turn": 1, "data": "' + ("A" * 1024) + '"}\n'
            target_bytes = 10 * 1024 * 1024
            written = 0
            with open(f, "w", encoding="utf-8") as out:
                while written < target_bytes:
                    out.write(line)
                    written += len(line)

            sampler = RSSSampler()
            sampler.start()
            t0 = time.perf_counter()
            engine = StreamSalvageEngine()
            res = engine.scan_file(f)
            t1 = time.perf_counter()
            mem = sampler.stop()

            elapsed = t1 - t0
            self.assertEqual(res.source_status, "HEALTHY")
            self.assertEqual(res.unclassified_bytes, 0)
            print(f"\n[BENCH 10MB] Bytes: {written}, Time: {elapsed:.3f}s, Baseline: {mem['baseline_mb']:.1f}MB, Peak: {mem['peak_mb']:.1f}MB, Final: {mem['final_mb']:.1f}MB, Records: {res.valid_records_count}")

    def test_100mb_streaming_rss_measured(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bench_100mb.jsonl"
            line = '{"turn": 1, "data": "' + ("B" * 4096) + '"}\n'
            target_bytes = 100 * 1024 * 1024
            written = 0
            with open(f, "w", encoding="utf-8") as out:
                while written < target_bytes:
                    out.write(line)
                    written += len(line)

            sampler = RSSSampler()
            sampler.start()
            t0 = time.perf_counter()
            engine = StreamSalvageEngine()
            res = engine.scan_file(f)
            t1 = time.perf_counter()
            mem = sampler.stop()

            elapsed = t1 - t0
            self.assertEqual(res.source_status, "HEALTHY")
            self.assertEqual(res.unclassified_bytes, 0)
            print(f"[BENCH 100MB] Bytes: {written}, Time: {elapsed:.3f}s, Baseline: {mem['baseline_mb']:.1f}MB, Peak: {mem['peak_mb']:.1f}MB, Final: {mem['final_mb']:.1f}MB, Records: {res.valid_records_count}")
            if mem["baseline_mb"] > 0:
                self.assertLess(mem["peak_delta_mb"], 50.0, "Sampled peak memory exceeds bounded streaming gate on 100MB!")

    def test_500mb_streaming_rss_measured(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "bench_500mb.jsonl"
            line = '{"turn": 1, "data": "' + ("C" * 16384) + '"}\n'
            target_bytes = 500 * 1024 * 1024
            written = 0
            with open(f, "w", encoding="utf-8") as out:
                while written < target_bytes:
                    out.write(line)
                    written += len(line)

            sampler = RSSSampler()
            sampler.start()
            t0 = time.perf_counter()
            engine = StreamSalvageEngine()
            res = engine.scan_file(f)
            t1 = time.perf_counter()
            mem = sampler.stop()

            elapsed = t1 - t0
            self.assertEqual(res.source_status, "HEALTHY")
            self.assertEqual(res.unclassified_bytes, 0)
            print(f"[BENCH 500MB] Bytes: {written}, Time: {elapsed:.3f}s, Baseline: {mem['baseline_mb']:.1f}MB, Peak: {mem['peak_mb']:.1f}MB, Final: {mem['final_mb']:.1f}MB, Records: {res.valid_records_count}")
            if mem["baseline_mb"] > 0:
                self.assertLess(mem["peak_delta_mb"], 50.0, "Sampled peak memory exceeds bounded streaming gate on 500MB!")

    def test_1gb_streaming_volume_measured(self):
        """Simulates 1GB+ stream scan using chunked stream generator to verify bounded memory."""
        chunk = ('{"turn": 1, "data": "' + ("D" * 65500) + '"}\n').encode("utf-8")
        chunk_len = len(chunk)
        total_records = 16384  # 16384 * ~65KB = ~1.07 GB
        total_bytes = total_records * chunk_len

        class Chunked1GBStream(io.RawIOBase):
            def __init__(self, total_bytes: int, chunk: bytes):
                self.total = total_bytes
                self.delivered = 0
                self.chunk = chunk

            def readable(self) -> bool:
                return True

            def readinto(self, b) -> int:
                if self.delivered >= self.total:
                    return 0
                rem = self.total - self.delivered
                offset = self.delivered % len(self.chunk)
                chunk_rem = len(self.chunk) - offset
                to_copy = min(len(b), chunk_rem, rem)
                b[:to_copy] = self.chunk[offset : offset + to_copy]
                self.delivered += to_copy
                return to_copy

        stream = io.BufferedReader(Chunked1GBStream(total_bytes, chunk))

        sampler = RSSSampler()
        sampler.start()
        t0 = time.perf_counter()
        engine = StreamSalvageEngine()
        res = engine.scan_stream(stream, total_size=total_bytes)
        t1 = time.perf_counter()
        mem = sampler.stop()

        elapsed = t1 - t0
        self.assertEqual(res.source_status, "HEALTHY")
        self.assertEqual(res.valid_records_count, total_records)
        print(f"[BENCH 1GB STREAM] Bytes: {total_bytes}, Time: {elapsed:.3f}s, Baseline: {mem['baseline_mb']:.1f}MB, Peak: {mem['peak_mb']:.1f}MB, Final: {mem['final_mb']:.1f}MB, Records: {res.valid_records_count}")
        if mem["baseline_mb"] > 0:
            self.assertLess(mem["peak_delta_mb"], 50.0, "Sampled peak memory exceeds bounded streaming gate on 1GB!")

    def test_500mb_backup_streaming_bounded_memory(self):
        """Verifies that BackupEngine copies 500MB without materializing file in memory."""
        with tempfile.TemporaryDirectory() as td:
            src_file = Path(td) / "large_rollout.jsonl"
            line = '{"turn": 1, "data": "' + ("E" * 16384) + '"}\n'
            target_bytes = 500 * 1024 * 1024
            written = 0
            with open(src_file, "w", encoding="utf-8") as out:
                while written < target_bytes:
                    out.write(line)
                    written += len(line)

            b_engine = BackupEngine(Path(td) / "backups")
            sampler = RSSSampler()
            sampler.start()
            t0 = time.perf_counter()
            manifest = b_engine.create_pre_mutation_backup([src_file])
            t1 = time.perf_counter()
            mem = sampler.stop()

            elapsed = t1 - t0
            self.assertTrue(manifest.verified)
            print(f"[BENCH 500MB BACKUP] Bytes: {written}, Time: {elapsed:.3f}s, Baseline: {mem['baseline_mb']:.1f}MB, Peak: {mem['peak_mb']:.1f}MB, Final: {mem['final_mb']:.1f}MB")
            if mem["baseline_mb"] > 0:
                self.assertLess(mem["peak_delta_mb"], 50.0, "BackupEngine memory growth exceeded bounded streaming limit!")


if __name__ == "__main__":
    unittest.main()
