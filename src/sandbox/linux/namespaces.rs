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
/// the parent performs the real map writes over a pipe handshake; success
/// proves the FULL tier is usable end-to-end (unshare + uid_map + gid_map).
///
/// SAFETY: fork in a single-threaded context (called before any tokio
/// runtime exists); the child only performs syscalls and _exit().
pub fn probe_unprivileged_userns() -> bool {
    if !userns_knobs_look_enabled() {
        return false;
    }
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; scalar flags.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return false;
    }
    // SAFETY: see fn docs.
    eprintln!("[probe-userns] forking");
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            // Child: enter a user ns, tell the parent, wait for its verdict.
            eprintln!("[probe-userns] child: unsharing");
            let entered = unshare(CLONE_NEWUSER).is_ok();
            eprintln!("[probe-userns] child: entered={entered}");
            // SAFETY: raw write of one status byte (1 = unshared).
            let byte: &[u8] = if entered { &[1] } else { &[0] };
            let w = unsafe { libc::write(fds[1], byte.as_ptr().cast(), 1) };
            eprintln!("[probe-userns] child: wrote ready w={w}");
            if !entered {
                unsafe { libc::_exit(1) };
            }
            let mut ack = [0u8; 1];
            // SAFETY: raw blocking read of the parent's verdict.
            eprintln!("[probe-userns] child: waiting ack");
            let n = unsafe { libc::read(fds[0], ack.as_mut_ptr().cast(), 1) };
            eprintln!("[probe-userns] child: ack n={n} b={}", ack[0]);
            // ack 0 => maps written correctly.
            unsafe { libc::_exit(if n == 1 && ack[0] == 0 { 0 } else { 1 }) };
        }
        pid => {
            eprintln!("[probe-userns] parent: pid={pid}");
            let mut status = 0i32;
            parent_probe_side(pid, fds, &mut status)
        }
    }
}

fn parent_probe_side(pid: libc::pid_t, fds: [libc::c_int; 2], status: &mut i32) -> bool {
    let mut ready = [0u8; 1];
    eprintln!("[probe-userns] parent: waiting ready");
    // SAFETY: raw read of the child's status byte.
    let n = unsafe { libc::read(fds[0], ready.as_mut_ptr().cast(), 1) };
    eprintln!("[probe-userns] parent: ready n={n} b={}", ready[0]);
    let entered = n == 1 && ready[0] == 1;
    let mut maps_ok = false;
    if entered {
        maps_ok = write_id_maps(pid).is_ok();
        eprintln!("[probe-userns] parent: maps_ok={maps_ok}");
        // SAFETY: raw write of one verdict byte (0 = maps ok).
        let byte: &[u8] = if maps_ok { &[0] } else { &[1] };
        let w = unsafe { libc::write(fds[1], byte.as_ptr().cast(), 1) };
        eprintln!("[probe-userns] parent: ack written w={w}");
    }
    // SAFETY: close both probe fds.
    unsafe {
        libc::close(fds[0]);
        libc::close(fds[1]);
    }
    eprintln!("[probe-userns] parent: waitpid");
    loop {
        // SAFETY: plain waitpid.
        let r = unsafe { libc::waitpid(pid, status, 0) };
        if r == pid
            || (r < 0
                && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
        {
            break;
        }
    }
    // SAFETY: scalar WIF/WEXIT macros.
    let exited_zero = libc::WIFEXITED(*status) && libc::WEXITSTATUS(*status) == 0;
    entered && maps_ok && exited_zero
}

/// Write setgroups-deny + uid_map + gid_map for `pid` mapping the caller's
/// own ids 1:1. Must be called by the REAL parent right after the child
/// enters its new user namespace.
pub fn write_id_maps(pid: libc::pid_t) -> VettoResult<()> {
    let base = Path::new("/proc").join(pid.to_string());
    let uid = unsafe { libc::getuid() }; // SAFETY: no pointers
    let gid = unsafe { libc::getgid() };

    let _ = fs::write(base.join("setgroups"), "deny");

    let w = |name: &str, content: String| -> VettoResult<()> {
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
