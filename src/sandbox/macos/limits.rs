//! macOS resource limits applied immediately before an agent `execve`.
//!
//! Mirrors the Linux tier (`sandbox::linux::limits`) so `--limits` and the
//! policy `limits` block enforce identical ceilings on both Unix backends.
//! The policy layer owns the values; this module owns the macOS `setrlimit(2)`
//! boundary. A missing value never widens the inherited limit, while an
//! explicit value is applied to both the soft and hard ceilings and therefore
//! cannot be raised by the agent after exec.

use crate::error::{VettoError, VettoResult};
use crate::policy::ResourceLimits;

fn apply_one(resource: libc::c_int, value: Option<u64>) -> VettoResult<()> {
    let Some(value) = value else {
        return Ok(());
    };
    let requested = value;
    let value = requested as libc::rlim_t;
    if value as u128 != requested as u128 {
        return Err(VettoError::Sandbox(format!(
            "setrlimit({resource}) value does not fit this ABI"
        )));
    }
    let limit = libc::rlimit {
        rlim_cur: value,
        rlim_max: value,
    };
    // SAFETY: resource is a fixed libc constant and `limit` is a valid local
    // rlimit structure. macOS validates whether the requested hard limit is
    // within the caller's inherited ceiling.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(VettoError::Sandbox(format!(
            "setrlimit({resource}, {value}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Apply all configured ceilings. Called in the Seatbelt child after stdio
/// setup and before the parent-death watchdog / Seatbelt application.
pub fn apply_before_exec(limits: &ResourceLimits) -> VettoResult<()> {
    apply_one(libc::RLIMIT_CPU, limits.cpu_seconds)?;
    apply_one(libc::RLIMIT_AS, limits.address_space_bytes)?;
    apply_one(libc::RLIMIT_NPROC, limits.processes)?;
    apply_one(libc::RLIMIT_NOFILE, limits.open_files)?;
    apply_one(libc::RLIMIT_FSIZE, limits.file_size_bytes)?;
    Ok(())
}
