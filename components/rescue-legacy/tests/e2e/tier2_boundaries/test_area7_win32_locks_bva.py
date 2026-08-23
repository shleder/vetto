"""Tier 2: Feature Area 7 BVA - Win32 Handle Sharing & Locking Boundary Value Analysis."""
from __future__ import annotations

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


class TestArea7Win32LocksBVA(unittest.TestCase):
    """Boundary and corner case tests for Win32 handles, lock contention, and error codes."""

    @unittest.skipUnless(sys.platform == "win32", "Win32 handle sharing requires Windows")
    def test_e2e_t2_win32_file_share_delete_open(self) -> None:
        """Verify lightweight_scan succeeds when file is open with FILE_SHARE_DELETE."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("share-del-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ,
                share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_DELETE,
            ):
                summary = lightweight_scan(p)
                self.assertIsNotNone(summary)
                self.assertEqual(summary.session_id, "share-del-001")

    @unittest.skipUnless(sys.platform == "win32", "Win32 byte-range locking requires Windows")
    def test_e2e_t2_win32_locked_tail_boundary(self) -> None:
        """Verify exclusive byte-range lock on tail bytes is handled safely without hanging."""
        with TempSessionWorkspace() as ws:
            records = [
                SyntheticRolloutGenerator.make_session_meta(session_id="locked-tail"),
                SyntheticRolloutGenerator.make_user_msg("First prompt"),
                SyntheticRolloutGenerator.make_agent_msg("First response"),
            ]
            p = ws.create_session("locked-tail", records=records)
            file_size = p.stat().st_size

            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ | Win32LockContext.GENERIC_WRITE,
                share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_WRITE,
            ) as lock_ctx:
                lock_ctx.lock_range(max(0, file_size - 20), 20, exclusive=True)
                try:
                    try:
                        parsed = parse_transcript(str(p))
                        self.assertIsNotNone(parsed)
                    except (PermissionError, OSError):
                        pass
                finally:
                    lock_ctx.unlock_range(max(0, file_size - 20), 20)

    @unittest.skipUnless(sys.platform == "win32", "Win32 error 32 test requires Windows")
    def test_e2e_t2_win32_error_32_sharing_violation(self) -> None:
        """Verify exclusive handle acquisition causes PermissionError on concurrent open."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("error32-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ | Win32LockContext.GENERIC_WRITE,
                share_mode=0,
            ):
                with self.assertRaises(PermissionError) as ctx:
                    with open(p, "rb"):
                        pass
                self.assertTrue(isinstance(ctx.exception, PermissionError))

    @unittest.skipUnless(sys.platform == "win32", "Win32 error 33 test requires Windows")
    def test_e2e_t2_win32_error_33_lock_violation(self) -> None:
        """Verify overlapping LockFileEx on same byte range returns WinError 33."""
        with TempSessionWorkspace() as ws:
            p = ws.create_session("error33-001")
            with Win32LockContext(
                p,
                desired_access=Win32LockContext.GENERIC_READ | Win32LockContext.GENERIC_WRITE,
                share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_WRITE,
            ) as lock1:
                lock1.lock_range(0, 100, exclusive=True)
                try:
                    with Win32LockContext(
                        p,
                        desired_access=Win32LockContext.GENERIC_READ | Win32LockContext.GENERIC_WRITE,
                        share_mode=Win32LockContext.FILE_SHARE_READ | Win32LockContext.FILE_SHARE_WRITE,
                    ) as lock2:
                        with self.assertRaises(OSError) as ctx:
                            lock2.lock_range(0, 100, exclusive=True)
                        self.assertEqual(getattr(ctx.exception, "winerror", None), 33)
                finally:
                    lock1.unlock_range(0, 100)

    @unittest.skipUnless(sys.platform == "win32", "Win32 exclusive lock test requires Windows")
    def test_e2e_t2_win32_exclusive_write_lock_rejects_reader(self) -> None:
        """Verify exclusive write lock blocks doctor reader safely."""
        with MockGitRepo() as git_repo:
            with TempSessionWorkspace() as ws:
                p = ws.create_session(
                    "excl-write-001",
                    records=[
                        SyntheticRolloutGenerator.make_session_meta(cwd=str(git_repo.root)),
                        SyntheticRolloutGenerator.make_user_msg("Valid start"),
                    ],
                )
                with Win32LockContext(
                    p,
                    desired_access=Win32LockContext.GENERIC_WRITE,
                    share_mode=0,
                ):
                    with self.assertRaises(PermissionError):
                        doctor_session(p)


if __name__ == "__main__":
    unittest.main()
