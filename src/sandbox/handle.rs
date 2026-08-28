//! Spawn contract + supervision handle shared by every backend.

use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
use crate::sandbox::linux::proctrack;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, OwnedHandle};

/// How the agent's stdio is wired.
#[derive(Debug, Clone, Copy)]
#[cfg(unix)]
pub enum StdioMode {
    /// Interactive: child talks to a PTY slave (statusline mode).
    Pty { slave_fd: RawFd },
    /// Headless: stdout/stderr dup2'd onto these pipe write ends (full
    /// dashboard mode). The parent keeps the read ends.
    Captured { stdout_w: RawFd, stderr_w: RawFd },
    /// Agent inherits vetto's own stdio (`--tui=none`, CI piping).
    Inherit,
}

/// Windows currently relies on the process model's default console/stdio
/// behavior; its experimental API requires `inheritHandles = FALSE`, so a
/// captured-mode implementation must add an explicit HANDLE-list path before
/// exposing it here.
#[derive(Debug, Clone, Copy)]
#[cfg(windows)]
pub enum StdioMode {
    Inherit,
}

#[derive(Debug, Clone)]
pub struct SpawnOptions {
    pub agent_cmd: Vec<String>,
    pub cwd: PathBuf,
    pub env_extra: HashMap<String, String>,
    pub stdio: StdioMode,
}

/// How vetto kills the whole tree when the session ends or vetto dies.
pub enum KillStrategy {
    /// Tier FULL: dropping this pipe makes the inner PID-1 supervisor
    /// kill(-1, SIGKILL) the entire pidns; the kernel then reaps the rest.
    #[cfg(target_os = "linux")]
    PidNsPipe(std::os::unix::io::OwnedFd),
    /// FS-ONLY / macOS: kill(-pgid) plus SIGKILL to the direct child.
    ///
    /// On Linux (FS-ONLY), `sweep` additionally runs a bounded best-effort
    /// sweep after the group kill: descendants that escaped via setsid() are
    /// reparented to vetto (child sub-reaper) and get SIGKILLed there. On
    /// macOS `sweep` is false and behavior is unchanged.
    #[cfg(unix)]
    ProcessGroup { pid: i32, pgid: i32, sweep: bool },
    /// Windows Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
    #[cfg(windows)]
    JobObject {
        /// Closing the Job Object kills the complete process tree.
        job: OwnedHandle,
        /// Retained process handle makes wait/exit-code collection reliable
        /// even after the process has exited and its PID is reusable.
        process: OwnedHandle,
    },
}

pub struct SandboxHandle {
    /// Outer-visible root process identifier (Unix waitpid target; Windows
    /// diagnostics/identity only—the retained process HANDLE is authoritative
    /// for waiting there).
    pub root_pid: u32,
    pub strategy: Option<KillStrategy>,
}

impl SandboxHandle {
    /// Suspend the sandboxed process tree without releasing its kill
    /// strategy. This is used by the interactive dashboards' pause control;
    /// it is deliberately best-effort on platforms where a group signal is
    /// unavailable and never falls back to running outside the sandbox.
    pub fn pause(&mut self) {
        #[cfg(unix)]
        {
            match self.strategy.as_ref() {
                #[cfg(target_os = "linux")]
                Some(KillStrategy::PidNsPipe(_)) => unsafe {
                    libc::kill(self.root_pid as i32, libc::SIGSTOP);
                },
                #[cfg(unix)]
                Some(KillStrategy::ProcessGroup { pid, pgid, .. }) => unsafe {
                    libc::kill(-*pgid, libc::SIGSTOP);
                    libc::kill(*pid, libc::SIGSTOP);
                },
                None => {}
            }
        }
    }

    /// Resume a tree previously suspended by [`Self::pause`].
    pub fn resume(&mut self) {
        #[cfg(unix)]
        {
            match self.strategy.as_ref() {
                #[cfg(target_os = "linux")]
                Some(KillStrategy::PidNsPipe(_)) => unsafe {
                    libc::kill(self.root_pid as i32, libc::SIGCONT);
                },
                #[cfg(unix)]
                Some(KillStrategy::ProcessGroup { pid, pgid, .. }) => unsafe {
                    libc::kill(-*pgid, libc::SIGCONT);
                    libc::kill(*pid, libc::SIGCONT);
                },
                None => {}
            }
        }
    }

    /// Non-blocking poll: Some(exit_code) once the process is gone.
    pub fn try_wait(&mut self) -> Option<i32> {
        #[cfg(unix)]
        {
            let pid = self.root_pid as i32;
            let mut status = 0i32;
            // SAFETY: plain waitpid with WNOHANG on our own child.
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                Some(decode_status(status))
            } else if r == 0 {
                None
            } else if errno() == libc::ECHILD {
                Some(-1)
            } else {
                None
            }
        }
        #[cfg(windows)]
        {
            windows_try_wait(self.strategy.as_ref())
        }
    }

    /// Block until the sandboxed agent exits; returns its exit code
    /// (negative for death-by-signal).
    pub fn wait(&mut self) -> i32 {
        #[cfg(unix)]
        {
            let pid = self.root_pid as i32;
            loop {
                let mut status = 0i32;
                let r = unsafe { libc::waitpid(pid, &mut status, 0) };
                if r == pid {
                    return decode_status(status);
                }
                if r < 0 && errno() != libc::EINTR {
                    return -1;
                }
            }
        }
        #[cfg(windows)]
        {
            windows_wait(self.strategy.as_ref())
        }
    }

    /// Kill everything inside the sandbox. Safe to call multiple times.
    pub fn terminate(&mut self) {
        if let Some(strategy) = self.strategy.take() {
            match strategy {
                #[cfg(target_os = "linux")]
                KillStrategy::PidNsPipe(fd) => drop(fd), // EOF => inner init kills all
                #[cfg(unix)]
                KillStrategy::ProcessGroup { pid, pgid, sweep } => {
                    // SAFETY: group + direct-child SIGKILL on the sandbox we
                    // spawned.
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                    }
                    // Linux FS-ONLY only: after the group kill, sweep the
                    // reparented orphan descendants (setsid escapers) that
                    // the group signal cannot reach. macOS keeps the
                    // historical behavior unchanged.
                    #[cfg(target_os = "linux")]
                    if sweep {
                        proctrack::sweep_reparented(
                            proctrack::SWEEP_BUDGET_MS,
                            self.root_pid as i32,
                        );
                    }
                    #[cfg(not(target_os = "linux"))]
                    let _ = sweep;
                }
                #[cfg(windows)]
                KillStrategy::JobObject { job, process } => {
                    // Drop the job first so kill-on-close is armed while the
                    // process handle is still valid, then release the wait
                    // handle.
                    drop(job);
                    drop(process);
                }
            }
        }
    }
}

impl Drop for SandboxHandle {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(unix)]
fn decode_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -libc::WTERMSIG(status)
    } else {
        -1
    }
}

#[cfg(unix)]
fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(windows)]
const WINDOWS_WAIT_OBJECT_0: u32 = 0;
#[cfg(windows)]
const WINDOWS_WAIT_FAILED: u32 = 0xffff_ffff;
#[cfg(windows)]
const WINDOWS_INFINITE: u32 = 0xffff_ffff;
#[cfg(windows)]
type WindowsHandle = *mut std::ffi::c_void;

#[cfg(windows)]
#[link(name = "kernel32")]
#[allow(non_snake_case)]
extern "system" {
    fn WaitForSingleObject(handle: WindowsHandle, milliseconds: u32) -> u32;
    fn GetExitCodeProcess(handle: WindowsHandle, exit_code: *mut u32) -> i32;
}

#[cfg(windows)]
fn windows_exit_code(handle: &OwnedHandle) -> i32 {
    let mut code = 1u32;
    // SAFETY: handle is a live process HANDLE and code points to local storage.
    if unsafe { GetExitCodeProcess(handle.as_raw_handle().cast(), &mut code) } == 0 {
        -1
    } else {
        code as i32
    }
}

#[cfg(windows)]
fn windows_try_wait(strategy: Option<&KillStrategy>) -> Option<i32> {
    let KillStrategy::JobObject { process, .. } = strategy?;
    // SAFETY: handle is a live process HANDLE; zero timeout is non-blocking.
    match unsafe { WaitForSingleObject(process.as_raw_handle().cast(), 0) } {
        WINDOWS_WAIT_OBJECT_0 => Some(windows_exit_code(process)),
        WINDOWS_WAIT_FAILED => None,
        _ => None,
    }
}

#[cfg(windows)]
fn windows_wait(strategy: Option<&KillStrategy>) -> i32 {
    let Some(KillStrategy::JobObject { process, .. }) = strategy else {
        return -1;
    };
    // SAFETY: handle is a live process HANDLE and INFINITE is the documented
    // blocking wait value.
    if unsafe { WaitForSingleObject(process.as_raw_handle().cast(), WINDOWS_INFINITE) }
        == WINDOWS_WAIT_OBJECT_0
    {
        windows_exit_code(process)
    } else {
        -1
    }
}
