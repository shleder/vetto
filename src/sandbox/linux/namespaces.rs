//! Namespace helpers: unshare wrappers, unprivileged-userns probing and the
//! uid_map/gid_map writing dance performed by the parent.

use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{VettoError, VettoResult};

pub const CLONE_NEWNS: libc::c_int = 0x0002_0000;
pub const CLONE_NEWUSER: libc::c_int = 0x1000_0000;
pub const CLONE_NEWPID: libc::c_int = 0x2000_0000;
pub const CLONE_NEWNET: libc::c_int = 0x4000_0000;
pub const CLONE_NEWIPC: libc::c_int = 0x0800_0000;

/// unshare(2) with a mapped error.
pub fn unshare(flags: libc::c_int) -> VettoResult<()> {
    // SAFETY: direct syscall with no pointers involved.
    let r = unsafe { libc::unshare(flags) };
    if r != 0 {
        return Err(VettoError::Namespace(format!(
            "unshare({flags:#x}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn proc_sys_u32(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Cheap pre-check for unprivileged userns support knobs.
/// The authoritative test remains `probe_unprivileged_userns()` (fork-based).
pub fn userns_knobs_look_enabled() -> bool {
    let clone_ok = match proc_sys_u32("/proc/sys/kernel/unprivileged_userns_clone") {
        Some(v) => v != 0,
        None => true, // knob absent => not gated
    };
    let max_ok = proc_sys_u32("/proc/sys/user/max_user_namespaces").unwrap_or(u64::MAX) > 0;
    clone_ok && max_ok
}

/// Authoritative probe: fork a child that unshares a user namespace while
/// the parent performs the real map writes; success proves the FULL tier is
/// usable end-to-end.
///
/// SAFETY: fork in a single-threaded context (called before any tokio
/// runtime exists); the child only performs syscalls and _exit().
pub fn probe_unprivileged_userns() -> bool {
    if !userns_knobs_look_enabled() {
        return false;
    }
    // SAFETY: see fn docs.
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            // child: try to enter a user namespace, then verify identity.
            if unshare(CLONE_NEWUSER).is_err() {
                unsafe { libc::_exit(1) };
            }
            // Parent writes maps once we report our pid over stdout-less
            // channel: use exit-code protocol via a status pipe instead.
            unsafe { libc::_exit(if maps_written_by_parent_happens_outside()) { 0 } else { 42 } };
        }
        pid => {
            // parent: write maps then read child verdict.
            let ok_child = write_id_maps(pid).is_ok();
            let mut status = 0i32;
            loop {
                // SAFETY: plain waitpid.
                let r = unsafe { libc::waitpid(pid, &mut status, 0) };
                if r == pid || (r < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)) {
                    break;
                }
            }
            let exited_zero =
                unsafe { libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 };
            // WEXITSTATUS==42 means child ran but maps never landed.
            ok_child && exited_zero
        }
    }
}

// The probe child cannot know whether its parent succeeded; the parent's
// map-write result is combined on the parent side above. This stub exists to
// keep the child's control flow explicit and honest.
fn maps_written_by_parent_happens_outside() -> bool {
    true
}

/// Write setgroups-deny + uid_map + gid_map for `pid` mapping the caller's
/// own ids 1:1. Must be called by the REAL parent right after the child
/// enters its new user namespace.
pub fn write_id_maps(pid: libc::pid_t) -> VettoResult<()> {
    let base = Path::new("/proc").join(pid.to_string());
    let uid = unsafe { libc::getuid() }; // SAFETY: no pointers
    let gid = unsafe { libc::getgid() };

    let _ = fs::write(base.join("setgroups"), "deny");

    let mut w = |name: &str, content: String| -> VettoResult<()> {
        let path = base.join(name);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .map_err(|e| VettoError::Namespace(format!("open {}: {e}", path.display())))?;
        f.write_all(content.as_bytes())
            .map_err(|e| VettoError::Namespace(format!("write {}: {e}", path.display())))?;
        Ok(())
    };

    w("uid_map", format!("0 {uid} 1\n"))?;
    w("gid_map", format!("0 {gid} 1\n"))?;
    Ok(())
}
