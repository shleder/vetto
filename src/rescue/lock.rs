//! Inter-process advisory session locking for concurrent rescue operations.
//!
//! Provides cross-platform non-blocking file locking with lease management,
//! stale lock detection (via PID liveness probing and lease expiration),
//! exponential backoff retries, and clean RAII unlock guards.
//!
//! - Linux: Open File Description locks (`F_OFD_SETLK`) with fallback to `flock`.
//! - macOS: `flock(LOCK_EX | LOCK_NB)`.
//! - Windows: `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

pub const DEFAULT_LEASE_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_LOCK_FILENAME: &str = ".vetto_repair.lock";

/// Lockfile payload storing process lease information.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockMetadata {
    pub pid: u32,
    pub acquired_at: u64,
    pub lease_timeout_ms: u64,
}

impl LockMetadata {
    pub fn is_expired(&self) -> bool {
        let now = now_unix_secs();
        let timeout_secs = (self.lease_timeout_ms / 1000).max(1);
        now > self.acquired_at.saturating_add(timeout_secs)
    }
}

/// RAII Guard that releases the underlying OS file lock and cleans up the
/// lockfile on drop.
pub struct SessionLockGuard {
    lock_file: File,
    lock_path: PathBuf,
    metadata: LockMetadata,
}

impl std::fmt::Debug for SessionLockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionLockGuard")
            .field("lock_path", &self.lock_path)
            .field("metadata", &self.metadata)
            .finish()
    }
}

impl SessionLockGuard {
    /// Attempt to acquire an advisory exclusive lock immediately without blocking.
    pub fn try_acquire(lock_path: &Path, lease_timeout_ms: u64) -> Result<Self> {
        if let Some(parent) = lock_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create lock directory {}", parent.display()))?;
        }

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(lock_path)
            .with_context(|| format!("open lockfile {}", lock_path.display()))?;

        match try_os_lock(&file) {
            Ok(true) => {
                let metadata = LockMetadata {
                    pid: std::process::id(),
                    acquired_at: now_unix_secs(),
                    lease_timeout_ms,
                };
                write_lock_metadata(&mut file, &metadata)?;
                Ok(Self {
                    lock_file: file,
                    lock_path: lock_path.to_path_buf(),
                    metadata,
                })
            }
            Ok(false) => {
                // OS lock failed. Inspect existing lease metadata to check if stale.
                let mut content = String::new();
                let _ = file.read_to_string(&mut content);
                if let Ok(meta) = serde_json::from_str::<LockMetadata>(&content) {
                    if !is_process_alive(meta.pid) || meta.is_expired() {
                        // Stale lock detected; wait briefly and try once more.
                        thread::sleep(Duration::from_millis(50));
                        if try_os_lock(&file)? {
                            let metadata = LockMetadata {
                                pid: std::process::id(),
                                acquired_at: now_unix_secs(),
                                lease_timeout_ms,
                            };
                            write_lock_metadata(&mut file, &metadata)?;
                            return Ok(Self {
                                lock_file: file,
                                lock_path: lock_path.to_path_buf(),
                                metadata,
                            });
                        }
                    }
                }
                bail!("lock on {} is held by another process", lock_path.display())
            }
            Err(err) => Err(err),
        }
    }

    /// Acquire the advisory lock, retrying with exponential backoff up to `max_wait`.
    pub fn acquire_with_timeout(
        lock_path: &Path,
        lease_timeout_ms: u64,
        max_wait: Duration,
    ) -> Result<Self> {
        let start = std::time::Instant::now();
        let mut backoff = Duration::from_millis(10);
        let max_backoff = Duration::from_millis(500);

        loop {
            match Self::try_acquire(lock_path, lease_timeout_ms) {
                Ok(guard) => return Ok(guard),
                Err(_) if start.elapsed() < max_wait => {
                    thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                }
                Err(err) => {
                    bail!(
                        "timed out after {:?} attempting to acquire lock on {}: {}",
                        start.elapsed(),
                        lock_path.display(),
                        err
                    );
                }
            }
        }
    }

    pub fn metadata(&self) -> &LockMetadata {
        &self.metadata
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

impl Drop for SessionLockGuard {
    fn drop(&mut self) {
        let _ = unlock_os_lock(&self.lock_file);
        let _ = fs::remove_file(&self.lock_path);
    }
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn write_lock_metadata(file: &mut File, metadata: &LockMetadata) -> Result<()> {
    file.set_len(0).context("truncate lockfile")?;
    file.seek(SeekFrom::Start(0)).context("seek lockfile")?;
    let payload = serde_json::to_vec_pretty(metadata).context("serialize lock metadata")?;
    file.write_all(&payload).context("write lock metadata")?;
    file.sync_all().context("sync lock metadata")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Platform OS file locking
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn try_os_lock(file: &File) -> Result<bool> {
    const F_OFD_SETLK: libc::c_int = 37;
    let fd = file.as_raw_fd();
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_WRLCK as i16;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;

    let res = unsafe { libc::fcntl(fd, F_OFD_SETLK, &fl) };
    if res == 0 {
        return Ok(true);
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EACCES || errno == libc::EAGAIN || errno == libc::EBUSY {
        return Ok(false);
    }
    // If OFD locks return EINVAL (older kernel or unsupported filesystem), fallback to flock.
    if errno == libc::EINVAL || errno == libc::ENOSYS {
        let flock_res = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        if flock_res == 0 {
            return Ok(true);
        }
        let flock_err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if flock_err == libc::EWOULDBLOCK || flock_err == libc::EAGAIN {
            return Ok(false);
        }
    }
    bail!(
        "fcntl(F_OFD_SETLK) failed: {}",
        std::io::Error::last_os_error()
    )
}

#[cfg(target_os = "linux")]
fn unlock_os_lock(file: &File) -> Result<()> {
    const F_OFD_SETLK: libc::c_int = 37;
    let fd = file.as_raw_fd();
    let mut fl: libc::flock = unsafe { std::mem::zeroed() };
    fl.l_type = libc::F_UNLCK as i16;
    fl.l_whence = libc::SEEK_SET as i16;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = 0;
    unsafe {
        let _ = libc::fcntl(fd, F_OFD_SETLK, &fl);
        let _ = libc::flock(fd, libc::LOCK_UN);
    }
    Ok(())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn try_os_lock(file: &File) -> Result<bool> {
    let fd = file.as_raw_fd();
    let res = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
    if res == 0 {
        return Ok(true);
    }
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    if errno == libc::EWOULDBLOCK || errno == libc::EAGAIN {
        return Ok(false);
    }
    bail!("flock failed: {}", std::io::Error::last_os_error())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn unlock_os_lock(file: &File) -> Result<()> {
    let fd = file.as_raw_fd();
    unsafe {
        let _ = libc::flock(fd, libc::LOCK_UN);
    }
    Ok(())
}

#[cfg(windows)]
mod win_lock {
    use std::os::windows::io::RawHandle;

    pub const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x00000002;
    pub const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x00000001;
    pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    pub const STILL_ACTIVE: u32 = 259;
    pub const ERROR_LOCK_VIOLATION: u32 = 33;

    #[repr(C)]
    pub struct OVERLAPPED {
        pub internal: usize,
        pub internal_high: usize,
        pub offset: u32,
        pub offset_high: u32,
        pub h_event: usize,
    }

    extern "system" {
        pub fn LockFileEx(
            hFile: RawHandle,
            dwFlags: u32,
            dwReserved: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;

        pub fn UnlockFileEx(
            hFile: RawHandle,
            dwReserved: u32,
            nNumberOfBytesToUnlockLow: u32,
            nNumberOfBytesToUnlockHigh: u32,
            lpOverlapped: *mut OVERLAPPED,
        ) -> i32;

        pub fn OpenProcess(
            dwDesiredAccess: u32,
            bInheritHandle: i32,
            dwProcessId: u32,
        ) -> RawHandle;

        pub fn GetExitCodeProcess(hProcess: RawHandle, lpExitCode: *mut u32) -> i32;

        pub fn CloseHandle(hObject: RawHandle) -> i32;
    }
}

#[cfg(windows)]
fn try_os_lock(file: &File) -> Result<bool> {
    let handle = file.as_raw_handle();
    let mut overlapped: win_lock::OVERLAPPED = unsafe { std::mem::zeroed() };
    let flags = win_lock::LOCKFILE_EXCLUSIVE_LOCK | win_lock::LOCKFILE_FAIL_IMMEDIATELY;
    let res = unsafe {
        win_lock::LockFileEx(
            handle,
            flags,
            0,
            1,
            0,
            &mut overlapped as *mut win_lock::OVERLAPPED,
        )
    };
    if res != 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(win_lock::ERROR_LOCK_VIOLATION as i32) {
        return Ok(false);
    }
    bail!("LockFileEx failed: {}", err)
}

#[cfg(windows)]
fn unlock_os_lock(file: &File) -> Result<()> {
    let handle = file.as_raw_handle();
    let mut overlapped: win_lock::OVERLAPPED = unsafe { std::mem::zeroed() };
    unsafe {
        win_lock::UnlockFileEx(
            handle,
            0,
            1,
            0,
            &mut overlapped as *mut win_lock::OVERLAPPED,
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn try_os_lock(_file: &File) -> Result<bool> {
    Ok(true)
}

#[cfg(not(any(unix, windows)))]
fn unlock_os_lock(_file: &File) -> Result<()> {
    Ok(())
}

// ---------------------------------------------------------------------------
// PID Liveness probe
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    let res = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if res == 0 {
        true
    } else {
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        err == libc::EPERM
    }
}

#[cfg(windows)]
pub fn is_process_alive(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    unsafe {
        let handle = win_lock::OpenProcess(win_lock::PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut exit_code: u32 = 0;
        let ok = win_lock::GetExitCodeProcess(handle, &mut exit_code);
        win_lock::CloseHandle(handle);
        ok != 0 && exit_code == win_lock::STILL_ACTIVE
    }
}

#[cfg(not(any(unix, windows)))]
pub fn is_process_alive(_pid: u32) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_lock_path(tag: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "vetto-lock-{}-{}-{}.lock",
            tag,
            std::process::id(),
            nonce
        ))
    }

    #[test]
    fn acquires_and_releases_session_lock() {
        let path = temp_lock_path("basic");
        {
            let guard = SessionLockGuard::try_acquire(&path, 30_000).expect("acquire lock");
            assert_eq!(guard.metadata().pid, std::process::id());
            assert!(path.exists());

            // Contention: second acquire on same path fails
            let err = SessionLockGuard::try_acquire(&path, 30_000).expect_err("contention");
            assert!(err.to_string().contains("held by another process"));
        }
        // After drop, lockfile can be acquired again
        let guard2 = SessionLockGuard::try_acquire(&path, 30_000).expect("re-acquire lock");
        assert_eq!(guard2.metadata().pid, std::process::id());
    }

    #[test]
    fn detects_stale_pid_and_reclaims_lock() {
        let path = temp_lock_path("stale");
        // Write a fake stale lock from an impossible PID (e.g. 9999999)
        let stale_meta = LockMetadata {
            pid: 9_999_999,
            acquired_at: now_unix_secs().saturating_sub(100),
            lease_timeout_ms: 10_000,
        };
        fs::write(&path, serde_json::to_string_pretty(&stale_meta).unwrap()).unwrap();

        // Should successfully acquire because PID is dead/lease expired
        let guard = SessionLockGuard::try_acquire(&path, 30_000).expect("reclaim stale");
        assert_eq!(guard.metadata().pid, std::process::id());
    }

    #[test]
    fn acquire_with_timeout_succeeds_after_release() {
        let path = temp_lock_path("timeout");
        let guard = SessionLockGuard::try_acquire(&path, 30_000).expect("first lock");

        let handle = std::thread::spawn({
            let path = path.clone();
            move || {
                std::thread::sleep(Duration::from_millis(50));
                drop(guard);
            }
        });

        let guard2 = SessionLockGuard::acquire_with_timeout(&path, 30_000, Duration::from_secs(2))
            .expect("acquire with timeout");
        assert_eq!(guard2.metadata().pid, std::process::id());
        handle.join().unwrap();
    }
}
