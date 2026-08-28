//! macOS resource limits applied immediately before an agent `execve`.
//!
//! Mirrors the Linux tier (`sandbox::linux::limits`) with one honest platform
//! difference: Darwin refuses several `setrlimit` values that Linux accepts
//! (notably `RLIMIT_AS`, and raising the `RLIMIT_NPROC` hard ceiling without
//! privileges), and it refuses them per host configuration. Failing the whole
//! session for a platform refusal would make the DEFAULT profile (which ships
//! limits) unusable on every macOS machine, so each ceiling is applied
//! best-effort: whatever the kernel accepts is enforced (soft = hard, the
//! agent cannot raise it back), whatever it refuses is reported to the agent's
//! stderr and skipped. Linux stays strict; macOS is the narrower backend.

use crate::policy::ResourceLimits;

fn apply_one(resource: libc::c_int, value: Option<u64>) -> Option<String> {
    let Some(value) = value else {
        return None;
    };
    let requested = value;
    let value = requested as libc::rlim_t;
    if value as u128 != requested as u128 {
        return Some(format!("setrlimit({resource}) value does not fit this ABI"));
    }
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: resource is a fixed libc constant and `limit` is a valid local
    // rlimit structure.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Some(format!(
            "setrlimit({resource}, {value}): {}",
            std::io::Error::last_os_error()
        ));
    }
    None
}

/// Apply all configured ceilings best-effort. Returns one human-readable line
/// per ceiling the platform refused; the caller surfaces them on stderr.
/// Called in the Seatbelt child after stdio setup and before the watchdog /
/// Seatbelt application.
pub fn apply_before_exec(limits: &ResourceLimits) -> Vec<String> {
    let mut refused = Vec::new();
    let entries = [
        (libc::RLIMIT_CPU, "cpu", limits.cpu_seconds),
        (libc::RLIMIT_AS, "address_space", limits.address_space_bytes),
        (libc::RLIMIT_NPROC, "processes", limits.processes),
        (libc::RLIMIT_NOFILE, "open_files", limits.open_files),
        (libc::RLIMIT_FSIZE, "file_size", limits.file_size_bytes),
    ];
    for (resource, name, value) in entries {
        if let Some(error) = apply_one(resource, value) {
            refused.push(format!("resource limit '{name}' not enforced: {error}"));
        }
    }
    refused
}
