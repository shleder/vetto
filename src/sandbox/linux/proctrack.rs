//! Linux child-process tracking for the FS-ONLY tier: the sub-reaper
//! registration plus the bounded orphan sweep.
//!
//! FS-ONLY runs the agent WITHOUT a PID namespace. The agent's process group
//! is killed with `kill(-pgid)` at teardown, but any descendant that called
//! `setsid()` lives in its own session and survives that signal. The closing
//! mechanism is:
//!
//! 1. Before the fork, vetto registers itself as a child sub-reaper
//!    (`PR_SET_CHILD_SUBREAPER`, see `crate::multi::isolation`). When the
//!    agent child terminates, surviving descendants are reparented to vetto
//!    instead of init.
//! 2. After the group kill, [`sweep_reparented`] scans `/proc` for live
//!    processes whose PPid is vetto, SIGKILLs them (except the root pid,
//!    which `SandboxHandle::wait` reaps) and reaps their exit statuses.
//! 3. Because `supervise` exits through `std::process::exit` (which skips
//!    `Drop`), the normal-exit path never runs `SandboxHandle::terminate`.
//!    [`arm_exit_sweep`] registers an `atexit` handler as the safety net so
//!    a normally-exiting session still sweeps its reparented escapers.
//!
//! The sweep is bounded and best-effort: if the sub-reaper prctl failed, if
//! an orphan sits in uninterruptible sleep past the deadline, or if a
//! reparenting cascade outlives the budget, escapers can still survive. This
//! is honest degradation from the FULL tier, where the PID namespace kills
//! everything in the kernel.

use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Upper bound for one sweep. Cascades deeper than this can escape; the
/// budget keeps teardown latency bounded even against hostile process trees.
pub const SWEEP_BUDGET_MS: u64 = 2_000;

/// Pause between `/proc` scans while waiting for the root to terminate or
/// for reparenting to become visible.
const SWEEP_POLL: Duration = Duration::from_millis(10);

// (root_pid, pgid) of the FS-ONLY sandbox, armed once per process.
static FS_GUARD: OnceLock<(i32, i32)> = OnceLock::new();

/// Register the process-exit safety net for the FS-ONLY sandbox.
///
/// The handler kills the sandbox process group and runs one bounded sweep.
/// On the normal exit path this is the ONLY teardown that runs (supervise
/// uses `std::process::exit`, which does not run `Drop`); on the timeout and
/// TUI paths the same work happens through `SandboxHandle::terminate` and
/// the exit-time re-run is an idempotent no-op. Call this AFTER the last
/// fork in the process so forked children never inherit an armed handler
/// (execve clears it anyway).
pub fn arm_exit_sweep(root_pid: i32, pgid: i32) {
    if FS_GUARD.set((root_pid, pgid)).is_err() {
        return; // already armed for this process
    }
    // SAFETY: the handler is a plain extern "C" fn whose only state is the
    // static guard above.
    unsafe { libc::atexit(exit_sweep) };
}

extern "C" fn exit_sweep() {
    let Some(&(root_pid, pgid)) = FS_GUARD.get() else {
        return;
    };
    // SAFETY: kill targets the sandbox process group recorded at spawn time.
    // An empty or already-dead group returns ESRCH, which is ignored.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    // Never kill(root_pid) here: on the normal path the root was already
    // reaped by wait(), and its pid may in principle have been reused. The
    // group kill and the sweep (which skips the root pid) are sufficient.
    sweep_reparented(SWEEP_BUDGET_MS, root_pid);
}

/// Kill and reap every reparented orphan descendant of this process.
///
/// Loop until the deadline: scan `/proc` for live processes whose PPid is
/// our pid (excluding `root_pid`, whose exit status belongs to
/// `SandboxHandle::wait`), SIGKILL each survivor and reap it with a targeted
/// `waitpid`. Targeted reaping — never `waitpid(-1)` — guarantees the root
/// pid's exit status is never consumed out from under `wait`. Returns the
/// number of SIGKILL signals delivered (zombies included; their kill is a
/// no-op that precedes the reaping).
pub fn sweep_reparented(deadline_ms: u64, root_pid: i32) -> usize {
    // SAFETY: scalar getpid.
    let me = unsafe { libc::getpid() } as u32;
    let deadline = Instant::now() + Duration::from_millis(deadline_ms);
    let mut killed = 0usize;
    loop {
        let candidates = scan_children(me, root_pid);
        if candidates.is_empty() {
            // Orphans become visible only after their parent terminates:
            // reparenting happens at termination, so once the root is a
            // zombie (or gone), everything below it has already been adopted
            // by us and an empty scan means the tree is clear. While the
            // root is still dying, keep polling.
            if root_settled(root_pid, me) {
                return killed;
            }
        } else {
            for pid in candidates {
                // SAFETY: SIGKILL to a pid that is, at scan time, a direct
                // child of this process (PPid == getpid()).
                if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                    killed += 1;
                }
                let mut status = 0i32;
                // SAFETY: non-blocking waitpid on our own child. 0 (still
                // dying) and ECHILD (already reaped) are expected races.
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
        }
        if Instant::now() >= deadline {
            return killed;
        }
        std::thread::sleep(SWEEP_POLL);
    }
}

/// Every live or zombie process whose PPid is `me`, excluding `exclude_pid`.
fn scan_children(me: u32, exclude_pid: i32) -> Vec<i32> {
    let mut children = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return children;
    };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if pid <= 0 || pid == exclude_pid {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
            continue; // vanished between readdir and read: not a candidate
        };
        if ppid_from_status(&status) == Some(me) {
            children.push(pid);
        }
    }
    children
}

/// True when the root can no longer produce new orphans: the process is gone
/// (reaped, or never existed), its pid was reused by a non-child, or it is a
/// zombie — at termination the kernel already reparented its children.
fn root_settled(root_pid: i32, me: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{root_pid}/status")) else {
        return true;
    };
    if ppid_from_status(&status) != Some(me) {
        return true;
    }
    state_letter(&status) == Some('Z')
}

/// Parse the `PPid:` field out of a `/proc/<pid>/status` body.
pub fn ppid_from_status(status_text: &str) -> Option<u32> {
    for line in status_text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Parse the single-letter process state (`State:\tZ (zombie)`).
fn state_letter(status_text: &str) -> Option<char> {
    for line in status_text.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("State:") {
            return rest.trim_start().chars().next();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ppid_is_parsed_from_proc_status_body() {
        let status = "Name:\tsleep\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t4242\n\
                      Ngid:\t0\nPid:\t4242\nPPid:\t1337\nTracerPid:\t0\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(ppid_from_status(status), Some(1337));
    }

    #[test]
    fn ppid_of_pid_one_is_parsed() {
        let status = "Name:\tsystemd\nState:\tS (sleeping)\nPPid:\t0\n";
        assert_eq!(ppid_from_status(status), Some(0));
    }

    #[test]
    fn missing_or_malformed_ppid_is_none() {
        assert_eq!(ppid_from_status("Name:\tx\nState:\tR (running)\n"), None);
        assert_eq!(ppid_from_status(""), None);
        assert_eq!(ppid_from_status("PPid:\tnot-a-number\n"), None);
        // Only an exact field match counts; a longer field name is ignored.
        assert_eq!(ppid_from_status("PPidTracer:\t5\n"), None);
    }

    #[test]
    fn indented_ppid_line_is_still_found() {
        let status = "Name:\tsleep\n  PPid:  99\n";
        assert_eq!(ppid_from_status(status), Some(99));
    }

    #[test]
    fn state_letter_reads_the_first_state_char() {
        assert_eq!(state_letter("State:\tZ (zombie)\n"), Some('Z'));
        assert_eq!(state_letter("State:\tS (sleeping)\n"), Some('S'));
        assert_eq!(state_letter("Name:\tx\n"), None);
    }
}
