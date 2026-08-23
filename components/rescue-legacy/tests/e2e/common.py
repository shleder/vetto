"""Shared E2E test utilities, fixture generators, and mock environments.

Provides:
- SyntheticRolloutGenerator: Deterministic JSONL generation for standard and adversarial events.
- TempSessionWorkspace: Isolated scratch workspaces mimicking ~/.codex/sessions.
- MockGitRepo: Isolated Git repositories with branch, staged/unstaged, index-flag, and detached-head control.
- Win32LockContext: Platform-aware Win32 handle sharing and byte-range locking.
- AsyncRolloutWriter: Concurrent background streaming / mutation injector.
- Cryptographic tree hashing and CLI runners.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

# Ensure src/ is in sys.path
_SRC_DIR = Path(__file__).resolve().parent.parent.parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))


def _safe_rmtree(path: Path | str) -> None:
    """Remove a directory tree safely on Windows even if read-only files exist."""
    p = Path(path)
    if not p.exists():
        return

    def _onerror(func: Callable[..., Any], file_path: str, excinfo: Any) -> None:
        try:
            os.chmod(file_path, stat.S_IWRITE)
            func(file_path)
        except Exception:
            pass

    shutil.rmtree(p, onerror=_onerror)


def compute_tree_sha256(root_dir: Path | str) -> str:
    """Compute a deterministic SHA-256 tree digest across all files in a directory."""
    root = Path(root_dir).resolve()
    if not root.exists():
        return ""
    hasher = hashlib.sha256()
    for dirpath, _, filenames in sorted(os.walk(root)):
        for fname in sorted(filenames):
            fpath = Path(dirpath) / fname
            rel_path = fpath.relative_to(root).as_posix()
            hasher.update(rel_path.encode("utf-8"))
            try:
                content = fpath.read_bytes()
                hasher.update(hashlib.sha256(content).digest())
            except OSError:
                pass
    return hasher.hexdigest()


class SyntheticRolloutGenerator:
    """Generator for syntactically valid and adversarial Codex JSONL streams."""

    @staticmethod
    def make_session_meta(
        session_id: str = "sess-e2e-001",
        cwd: str = "C:/test/repo",
        originator: str = "codex_cli",
        cli_version: str = "0.1.0a5",
        timestamp: str = "2026-08-14T20:00:00.000Z",
    ) -> dict[str, Any]:
        return {
            "type": "session_meta",
            "payload": {
                "id": session_id,
                "session_id": session_id,
                "cwd": cwd,
                "originator": originator,
                "cli_version": cli_version,
                "timestamp": timestamp,
            },
        }

    @staticmethod
    def make_user_msg(content: str = "Please fix the failing tests.") -> dict[str, Any]:
        return {
            "type": "event_msg",
            "payload": {
                "type": "user_message",
                "message": content,
            },
        }

    @staticmethod
    def make_agent_msg(content: str = "I will inspect the workspace.") -> dict[str, Any]:
        return {
            "type": "response_item",
            "payload": {
                "type": "agent_message",
                "message": content,
            },
        }

    @staticmethod
    def make_func_call(
        call_id: str = "call_001",
        name: str = "shell_command",
        arguments: str | dict[str, Any] = '{"cmd": "pytest"}',
    ) -> dict[str, Any]:
        args_val = json.dumps(arguments) if isinstance(arguments, dict) else str(arguments)
        return {
            "type": "response_item",
            "payload": {
                "type": "function_call",
                "call_id": call_id,
                "name": name,
                "arguments": args_val,
            },
        }

    @staticmethod
    def make_func_output(
        call_id: str = "call_001",
        output: str = "1 passed in 0.05s",
    ) -> dict[str, Any]:
        return {
            "type": "response_item",
            "payload": {
                "type": "function_call_output",
                "call_id": call_id,
                "output": output,
            },
        }

    @staticmethod
    def make_custom_call(
        call_id: str = "cust_001",
        name: str = "custom_linter",
        arguments: str | dict[str, Any] = '{"rules": ["all"]}',
    ) -> dict[str, Any]:
        args_val = json.dumps(arguments) if isinstance(arguments, dict) else str(arguments)
        return {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call",
                "call_id": call_id,
                "name": name,
                "arguments": args_val,
            },
        }

    @staticmethod
    def make_custom_output(
        call_id: str = "cust_001",
        output: str = "All rules passed.",
    ) -> dict[str, Any]:
        return {
            "type": "response_item",
            "payload": {
                "type": "custom_tool_call_output",
                "call_id": call_id,
                "output": output,
            },
        }

    @staticmethod
    def make_search_call(
        call_id: str = "srch_001",
        query: str = "def solve",
    ) -> dict[str, Any]:
        return {
            "type": "response_item",
            "payload": {
                "type": "tool_search_call",
                "call_id": call_id,
                "query": query,
            },
        }

    @staticmethod
    def make_search_output(
        call_id: str = "srch_001",
        results: str = "matches found",
    ) -> dict[str, Any]:
        return {
            "type": "response_item",
            "payload": {
                "type": "tool_search_output",
                "call_id": call_id,
                "output": results,
            },
        }

    @staticmethod
    def make_compacted(
        summary: str = "Compacted conversation history.",
        replacement_history: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if replacement_history is None:
            replacement_history = [
                {"type": "user_message", "message": "Initial task"},
                {"type": "agent_message", "message": "Done with first step"},
            ]
        return {
            "type": "compacted",
            "payload": {
                "summary": summary,
                "replacement_history": replacement_history,
            },
        }

    @classmethod
    def create_rollout(
        cls,
        records: list[dict[str, Any]],
        line_ending: bytes = b"\n",
        prepend_bom: bool = False,
        raw_suffix: bytes = b"",
    ) -> bytes:
        """Serialize record list to JSONL byte stream with optional BOM and suffix."""
        buf = bytearray()
        if prepend_bom:
            buf.extend(b"\xef\xbb\xbf")
        for rec in records:
            buf.extend(json.dumps(rec, separators=(",", ":")).encode("utf-8"))
            buf.extend(line_ending)
        if raw_suffix:
            buf.extend(raw_suffix)
        return bytes(buf)


class TempSessionWorkspace:
    """Context manager providing an isolated Codex home directory."""

    def __init__(self, prefix: str = "codex_e2e_ws_") -> None:
        self.temp_dir = tempfile.mkdtemp(prefix=prefix)
        self.root = Path(self.temp_dir).resolve()
        self.sessions_dir = self.root / "sessions"
        self.archived_dir = self.root / "archived_sessions"
        self.sessions_dir.mkdir(parents=True, exist_ok=True)
        self.archived_dir.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> "TempSessionWorkspace":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        _safe_rmtree(self.root)

    def create_session(
        self,
        session_id: str,
        records: list[dict[str, Any]] | None = None,
        content_bytes: bytes | None = None,
        date_path: str = "2026/08/14",
        archived: bool = False,
        mtime: float | None = None,
    ) -> Path:
        """Create a rollout JSONL file under the appropriate directory hierarchy."""
        base = self.archived_dir if archived else self.sessions_dir
        target_dir = base / date_path
        target_dir.mkdir(parents=True, exist_ok=True)
        file_path = target_dir / f"rollout-{session_id}.jsonl"

        if content_bytes is not None:
            file_path.write_bytes(content_bytes)
        elif records is not None:
            file_path.write_bytes(SyntheticRolloutGenerator.create_rollout(records))
        else:
            default_records = [
                SyntheticRolloutGenerator.make_session_meta(session_id=session_id),
                SyntheticRolloutGenerator.make_user_msg(f"Test prompt for {session_id}"),
                SyntheticRolloutGenerator.make_agent_msg("Ready"),
            ]
            file_path.write_bytes(SyntheticRolloutGenerator.create_rollout(default_records))

        if mtime is not None:
            os.utime(file_path, (mtime, mtime))

        return file_path

    def create_raw_file(self, rel_path: str, content_bytes: bytes) -> Path:
        target = self.root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content_bytes)
        return target


class MockGitRepo:
    """Context manager providing an isolated deterministic Git repository."""

    def __init__(self, prefix: str = "codex_e2e_git_") -> None:
        self.temp_dir = tempfile.mkdtemp(prefix=prefix)
        self.root = Path(self.temp_dir).resolve()
        self._init_git()

    def __enter__(self) -> "MockGitRepo":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.cleanup()

    def cleanup(self) -> None:
        _safe_rmtree(self.root)

    def _env(self) -> dict[str, str]:
        env = dict(os.environ)
        env["GIT_AUTHOR_NAME"] = "Codex Tester"
        env["GIT_AUTHOR_EMAIL"] = "tester@codex-rescue.local"
        env["GIT_COMMITTER_NAME"] = "Codex Tester"
        env["GIT_COMMITTER_EMAIL"] = "tester@codex-rescue.local"
        env["GIT_CONFIG_GLOBAL"] = os.devnull
        env["GIT_CONFIG_SYSTEM"] = os.devnull
        return env

    def _git(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=str(self.root),
            capture_output=True,
            text=True,
            check=True,
            env=self._env(),
        )

    def _init_git(self) -> None:
        self._git(["init"])
        self._git(["config", "user.name", "Codex Tester"])
        self._git(["config", "user.email", "tester@codex-rescue.local"])
        readme = self.root / "README.md"
        readme.write_text("# Test Repo\n", encoding="utf-8")
        self._git(["add", "README.md"])
        self._git(["commit", "-m", "Initial commit"])

    def commit_file(self, rel_path: str, content: str, msg: str = "Commit update") -> str:
        fpath = self.root / rel_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        self._git(["add", rel_path])
        self._git(["commit", "-m", msg])
        res = self._git(["rev-parse", "HEAD"])
        return res.stdout.strip()

    def modify_file(self, rel_path: str, content: str) -> None:
        fpath = self.root / rel_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")

    def stage_file(self, rel_path: str) -> None:
        self._git(["add", rel_path])

    def untracked_file(self, rel_path: str, content: str) -> Path:
        fpath = self.root / rel_path
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        return fpath

    def delete_file(self, rel_path: str) -> None:
        fpath = self.root / rel_path
        if fpath.exists():
            fpath.unlink()

    def set_assume_unchanged(self, rel_path: str) -> None:
        self._git(["update-index", "--assume-unchanged", rel_path])

    def set_skip_worktree(self, rel_path: str) -> None:
        self._git(["update-index", "--skip-worktree", rel_path])

    def detach_head(self) -> str:
        head_sha = self.get_head_sha()
        self._git(["checkout", "--detach", head_sha])
        return head_sha

    def get_head_sha(self) -> str:
        res = self._git(["rev-parse", "HEAD"])
        return res.stdout.strip()


class Win32LockContext:
    """Context manager acquiring Win32 CreateFileW handles and LockFileEx locks."""

    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x40000000
    FILE_SHARE_READ = 0x00000001
    FILE_SHARE_WRITE = 0x00000002
    FILE_SHARE_DELETE = 0x00000004
    OPEN_EXISTING = 3
    FILE_ATTRIBUTE_NORMAL = 0x80
    LOCKFILE_FAIL_IMMEDIATELY = 0x00000001
    LOCKFILE_EXCLUSIVE_LOCK = 0x00000002

    def __init__(
        self,
        path: Path | str,
        desired_access: int = GENERIC_READ,
        share_mode: int = FILE_SHARE_READ | FILE_SHARE_WRITE,
    ) -> None:
        self.path = str(Path(path).resolve())
        self.desired_access = desired_access
        self.share_mode = share_mode
        self.handle = None

    def __enter__(self) -> "Win32LockContext":
        if sys.platform != "win32":
            return self

        kernel32 = ctypes.windll.kernel32
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        self.handle = kernel32.CreateFileW(
            self.path,
            self.desired_access,
            self.share_mode,
            None,
            self.OPEN_EXISTING,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if self.handle == INVALID_HANDLE_VALUE:
            err = kernel32.GetLastError()
            raise ctypes.WinError(err)
        return self

    def lock_range(self, offset: int, length: int, exclusive: bool = True) -> None:
        if sys.platform != "win32" or not self.handle:
            return

        kernel32 = ctypes.windll.kernel32
        flags = self.LOCKFILE_FAIL_IMMEDIATELY | (self.LOCKFILE_EXCLUSIVE_LOCK if exclusive else 0)

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", wintypes.LPVOID),
                ("InternalHigh", wintypes.LPVOID),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        ov = OVERLAPPED()
        ov.Offset = offset & 0xFFFFFFFF
        ov.OffsetHigh = (offset >> 32) & 0xFFFFFFFF

        success = kernel32.LockFileEx(
            self.handle,
            flags,
            0,
            length & 0xFFFFFFFF,
            (length >> 32) & 0xFFFFFFFF,
            ctypes.byref(ov),
        )
        if not success:
            err = kernel32.GetLastError()
            raise ctypes.WinError(err)

    def unlock_range(self, offset: int, length: int) -> None:
        if sys.platform != "win32" or not self.handle:
            return

        kernel32 = ctypes.windll.kernel32

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", wintypes.LPVOID),
                ("InternalHigh", wintypes.LPVOID),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        ov = OVERLAPPED()
        ov.Offset = offset & 0xFFFFFFFF
        ov.OffsetHigh = (offset >> 32) & 0xFFFFFFFF

        success = kernel32.UnlockFileEx(
            self.handle,
            0,
            length & 0xFFFFFFFF,
            (length >> 32) & 0xFFFFFFFF,
            ctypes.byref(ov),
        )
        if not success:
            err = kernel32.GetLastError()
            raise ctypes.WinError(err)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if sys.platform == "win32" and self.handle:
            ctypes.windll.kernel32.CloseHandle(self.handle)
            self.handle = None


class AsyncRolloutWriter:
    """Asynchronous background worker appending or streaming data to a file."""

    def __init__(self, target_path: Path | str) -> None:
        self.target_path = Path(target_path)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def start_streaming(
        self,
        chunks: list[bytes],
        interval_sec: float = 0.05,
    ) -> None:
        def _worker() -> None:
            with open(self.target_path, "ab", buffering=0) as f:
                for chunk in chunks:
                    if self._stop_event.is_set():
                        break
                    f.write(chunk)
                    f.flush()
                    time.sleep(interval_sec)

        self._stop_event.clear()
        self._thread = threading.Thread(target=_worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)


def run_cli_command(
    args: list[str],
    env: dict[str, str] | None = None,
    cwd: str | None = None,
) -> tuple[int, str, str]:
    """Execute codex-rescue CLI subcommand via python -m codex_rescue.cli."""
    cmd_env = dict(os.environ)
    cmd_env["PYTHONPATH"] = str(_SRC_DIR)
    if env:
        cmd_env.update(env)

    proc = subprocess.run(
        [sys.executable, "-m", "codex_rescue.cli", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=cmd_env,
    )
    return proc.returncode, proc.stdout, proc.stderr
