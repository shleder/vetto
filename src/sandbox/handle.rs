//! Spawn contract + supervision handle shared by every backend.

use std::collections::HashMap;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

/// How the agent's stdio is wired.
#[derive(Debug, Clone, Copy)]
pub enum StdioMode {
    /// Interactive: child talks to a PTY slave (statusline mode).
    Pty { slave_fd: RawFd },
    /// Headless: stdout/stderr captured through pipes (full dashboard mode).
    Captured,
}

#[derive(Debug, Clone)]
pub struct SpawnOptions {
    pub agent_cmd: Vec<String>,
    pub cwd: PathBuf,
    pub env_extra: HashMap<String, String>,
    pub stdio: StdioMode,
}

impl SpawnOptions {
    pub fn new(agent_cmd: Vec<String>, cwd: PathBuf, stdio: StdioMode) -> Self {
        Self {
            agent_cmd,
            cwd,
            env_extra: HashMap::new(),
            stdio,
        }
    }
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
    if unsafe { libc::WIFEXITED(status) } {
        unsafe { libc::WEXITSTATUS(status) }
    } else if unsafe { libc::WIFSIGNALED(status) } {
        -unsafe { libc::WTERMSIG(status) }
    } else {
        -1
    }
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
