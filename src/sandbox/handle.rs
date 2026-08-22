//! Spawn contract + supervision handle shared by every backend.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

/// How the agent's stdio is wired.
#[derive(Debug, Clone, Copy)]
pub enum StdioMode {
    /// Interactive: child talks to a PTY slave (statusline mode).
    Pty { slave_fd: RawFd },
    /// Headless: stdout/stderr dup2'd onto these pipe write ends (full
    /// dashboard mode). The parent keeps the read ends.
    Captured { stdout_w: RawFd, stderr_w: RawFd },
    /// Agent inherits vetto's own stdio (`--tui=none`, CI piping).
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
    PidNsPipe(std::os::unix::io::OwnedFd),
    /// FS-ONLY / macOS: kill(-pgid) plus SIGKILL to the direct child.
    /// Honest limit (FS-ONLY): grandchildren that setsid() away survive.
    ProcessGroup { pid: i32, pgid: i32 },
}

pub struct SandboxHandle {
    /// Outer-visible process to waitpid() on.
    pub root_pid: u32,
    pub strategy: Option<KillStrategy>,
}

impl SandboxHandle {
    /// Non-blocking poll: Some(exit_code) once the process is gone.
    pub fn try_wait(&mut self) -> Option<i32> {
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

    /// Block until the sandboxed agent exits; returns its exit code
    /// (negative for death-by-signal).
    pub fn wait(&mut self) -> i32 {
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

    /// Kill everything inside the sandbox. Safe to call multiple times.
    pub fn terminate(&mut self) {
        if let Some(strategy) = self.strategy.take() {
            match strategy {
                KillStrategy::PidNsPipe(fd) => drop(fd), // EOF => inner init kills all
                KillStrategy::ProcessGroup { pid, pgid } => {
                    unsafe {
                        libc::kill(-pgid, libc::SIGKILL);
                        libc::kill(pid, libc::SIGKILL);
                    }
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

fn decode_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -libc::WTERMSIG(status)
    } else {
        -1
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
