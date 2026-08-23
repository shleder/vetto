"""Tier 1: Feature Area 7 - Win32 Handle Sharing & Locking Mechanics."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import sys
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
_SRC_DIR = _REPO_ROOT / "src"
_E2E_DIR = _REPO_ROOT / "tests" / "e2e"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))
if str(_E2E_DIR) not in sys.path:
    sys.path.insert(0, str(_E2E_DIR))

from codex_rescue.discovery import lightweight_scan
from codex_rescue.doctor import doctor_session
from codex_rescue.transcript import parse_transcript
from common import MockGitRepo, SyntheticRolloutGenerator, TempSessionWorkspace, Win32LockContext


class TestArea7Win32LocksFeatures(unittest.TestCase):
    """End-to-end feature tests for Win32 file sharing modes, byte-range locks, and handle bounds."""

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle sharing requires Windows")
    def test_e2e_t1_win32_file_share_read_scan(self) -> None:
        """Verify lightweight scan succeeds when file is concurrently open with FILE_SHARE_READ."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("share-read-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ,
                share_mode=Win32LockContext.FILE_SHARE_READ,
            ):
                summary = lightweight_scan(p)
                self.assertIsNotNone(summary)
                self.assertEqual(summary.session_id, "share-read-001")

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle sharing requires Windows")
    def test_e2e_t1_win32_file_share_write_read(self) -> None:
        """Verify doctor succeeds when file is open with FILE_SHARE_READ | FILE_SHARE_WRITE."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "share-write-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Prompt"),
                        SyntheticRolloutGenerator.make_agent_msg("Done"),
                    ],
                )
                with Win32LockContext(
                    p,
                    desired_access=Win32LockContext.GENERIC_WRITE,
                    share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_WRITE,
                ):
                    res = doctor_session(p)
                    self.assertEqual(res.status, "HEALTHY")

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle sharing requires Windows")
    def test_e2e_t1_win32_exclusive_lock_fails_closed(self) -> None:
        """Verify exclusive open (share_mode=0) causes reader to fail closed with PermissionError."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("exclusive-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ | Win32LockContext.GENERIC_WRITE,
                share_mode=0,  # Exclusive
            ):
                with self.assertRaises(PermissionError):
                    doctor_session(p)

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle sharing requires Windows")
    def test_e2e_t1_win32_byte_range_lock_shared(self) -> None:
        """Verify shared byte-range lock via LockFileEx allows reading transcript."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("byte-lock-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ,
                share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_WRITE,
            ) as lock_ctx:
                lock_ctx.lock_range(0, 128, exclusive=False)
                try:
                    parsed = parse_transcript(str(p))
                    self.assertGreater(parsed.valid_record_count, 0)
                finally:
                    lock_ctx.unlock_range(0, 128)

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle leak test requires Windows")
    def test_e2e_t1_win32_handle_closure_no_leak(self) -> None:
        """Verify handle lifetimes remain bounded (delta handles <= 1) across repeated diagnostics."""
        kernel32 = ctypes.windll.kernel32
        proc = kernel32.GetCurrentProcess()

        def _count() -> int:
            cnt = wintypes.DWORD()
            kernel32.GetProcessHandleCount(proc, ctypes.byref(cnt))
            return cnt.value

        with TempSessionWorkspace() as ws:
            p = ws.create_session("handle-leak-001")
            # Warm-up run
            doctor_session(p)

            initial_handles = _count()
            for _ in range(50):
                doctor_session(p)
            final_handles = _count()

            self.assertLessEqual(final_handles - initial_handles, 1)


if __name__ == "__main__":
    unittest.main()
