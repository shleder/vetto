//! macOS host-observed verification + tree sweep for the production boundary.
//!
//! The [`SandboxBackend`](crate::verify_ng::sandbox_backend::SandboxBackend)
//! boundary only *reports* enforcement; this module *observes* it from the
//! host without trusting any child output:
//!
//! - Process isolation: the Seatbelt child is placed in a new process group
//!   (`setpgid(0, 0)` in `super`), so `getpgid(child) == child` observed
//!   from the host proves the containment the killer later signals.
//! - Tree containment: after the wait, `kill(-pgid, SIGKILL)` + a bounded
//!   poll for group death proves no group member survived. `setsid`
//!   escapers leave the group and are the documented macOS gap (no pidns,
//!   no sub-reaper): a surviving group member fails the sweep closed.
//! - Filesystem/network isolation and resource limits have no per-process
//!   macOS indicator (Seatbelt denials are invisible to the host, there is
//!   no seccomp status and no remote-rlimit API), so they stay at
//!   `Enforced` — installed without error, effect proven behaviorally by
//!   the adversarial tests — never `Verified`.
//!
//! Best-effort signals (`kill` on an already-dead tree) are harmless and
//! ignored; only the post-sweep liveness check decides clean vs. dirty.

use crate::verify_ng::sandbox_backend::HostVerification;

/// Host-observed state of a live macOS production child.
///
/// Only `pgroup_separate` is observable here; every other flag stays false
/// so the corresponding capability remains `Enforced`, never `Verified`.
pub fn verify_child_host(pid: u32) -> HostVerification {
    let mut out = HostVerification::none();
    if pid == 0 {
        return out;
    }
    // SAFETY: scalar-only getpgid on our own child pid.
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    out.pgroup_separate = pgid == pid as libc::pid_t && pgid > 0;
    out
}

/// Best-effort tree sweep for one macOS production child: SIGKILL the
/// process group and the leader, then poll (bounded) for group death.
///
/// Returns true only when no group member is observable afterwards. A
/// short-lived child that already exited and was reaped also reports clean
/// (group gone, leader gone) — the sweep proves absence of survivors, not
/// that a kill was needed.
pub fn sweep_tree(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }
    // SAFETY: getpgid on our own (possibly reaped) child pid; ESRCH (-1)
    // simply means the leader is already gone.
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    // SAFETY: signals addressed only at our own sandbox tree; ESRCH on an
    // already-dead tree is ignored.
    unsafe {
        if pgid > 0 {
            libc::kill(-pgid, libc::SIGKILL);
        }
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
    for _ in 0..20 {
        if tree_gone(pid, pgid) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    tree_gone(pid, pgid)
}

/// True when neither the group nor the leader is observable anymore.
/// Reaps a zombie leader opportunistically (WNOHANG) so a waited-but-unreaped
/// exit does not read as a survivor.
fn tree_gone(pid: u32, pgid: libc::pid_t) -> bool {
    // SAFETY: kill(., 0) liveness probes on our own tree only.
    let group_gone = if pgid > 0 {
        unsafe { libc::kill(-pgid, 0) } != 0
    } else {
        true
    };
    let mut status = 0i32;
    // SAFETY: plain waitpid with WNOHANG on our own child.
    let r = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
    let leader_reaped_or_gone =
        r == pid as libc::pid_t || (r < 0 && is_esrch_or_echild());
    let leader_dead =
        leader_reaped_or_gone || unsafe { libc::kill(pid as libc::pid_t, 0) } != 0;
    group_gone && leader_dead
}

fn is_esrch_or_echild() -> bool {
    matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(code) if code == libc::ESRCH || code == libc::ECHILD
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pid_is_never_verified_or_clean() {
        let v = verify_child_host(0);
        assert!(!v.pgroup_separate);
        assert!(!v.all_observed());
        assert!(!sweep_tree(0));
    }

    #[test]
    fn foreign_pid_is_not_our_group() {
        // Our own pid lives in the test harness group, not in a group it
        // leads — unless the harness itself is a group leader, in which
        // case this asserts nothing false, only consistency.
        let me = std::process::id();
        let v = verify_child_host(me);
        // SAFETY: scalar-only getpgid on our own pid.
        let pgid = unsafe { libc::getpgid(me as libc::pid_t) };
        assert_eq!(v.pgroup_separate, pgid == me as libc::pid_t && pgid > 0);
    }
}
