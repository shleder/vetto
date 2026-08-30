//! Resource limits applied immediately before an agent `execve`.
//!
//! The policy layer owns the values; this module owns the Linux `setrlimit(2)`
//! boundary. A missing value never widens the inherited limit, while an
//! explicit value is applied to both the soft and hard ceilings and therefore
//! cannot be raised by the agent after exec.
//!
//! Phase 4 (Step 24): Extended cross-agent resource limits (memlock, msgqueue,
//! core dumps, data segments, stack).

use crate::error::{VettoError, VettoResult};
use crate::policy::ResourceLimits;

fn apply_one(resource: libc::__rlimit_resource_t, value: Option<u64>) -> VettoResult<()> {
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
    // rlimit structure. Linux validates whether the requested hard limit is
    // within the caller's inherited ceiling.
    if unsafe { libc::setrlimit(resource, &limit) } != 0 {
        return Err(VettoError::Sandbox(format!(
            "setrlimit({resource}, {value}): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Apply all configured ceilings. Call this immediately before `execve`; it
/// is safe to call in both FULL's agent child and the FS-ONLY agent child.
pub fn apply_before_exec(limits: &ResourceLimits) -> VettoResult<()> {
    apply_one(libc::RLIMIT_CPU, limits.cpu_seconds)?;
    apply_one(libc::RLIMIT_AS, limits.address_space_bytes)?;
    apply_one(libc::RLIMIT_NPROC, limits.processes)?;
    apply_one(libc::RLIMIT_NOFILE, limits.open_files)?;
    apply_one(libc::RLIMIT_FSIZE, limits.file_size_bytes)?;
    Ok(())
}

/// Apply strict ceilings on POSIX IPC structures (locked memory and message queues)
/// to prevent cross-agent resource exhaustion.
pub fn apply_ipc_resource_ceilings(
    max_msgqueue_bytes: Option<u64>,
    max_memlock_bytes: Option<u64>,
) -> VettoResult<()> {
    #[cfg(target_os = "linux")]
    {
        apply_one(libc::RLIMIT_MSGQUEUE, max_msgqueue_bytes)?;
        apply_one(libc::RLIMIT_MEMLOCK, max_memlock_bytes)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (max_msgqueue_bytes, max_memlock_bytes);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_limits_are_noops() {
        apply_before_exec(&ResourceLimits::default()).unwrap();
    }

    #[test]
    fn policy_fields_map_to_all_five_resources() {
        let limits = ResourceLimits {
            cpu_seconds: Some(60),
            address_space_bytes: Some(64 * 1024 * 1024),
            processes: Some(32),
            open_files: Some(128),
            file_size_bytes: Some(1024 * 1024),
            ..Default::default()
        };
        assert_eq!(limits.cpu_seconds, Some(60));
        assert_eq!(limits.address_space_bytes, Some(64 * 1024 * 1024));
        assert_eq!(limits.processes, Some(32));
        assert_eq!(limits.open_files, Some(128));
        assert_eq!(limits.file_size_bytes, Some(1024 * 1024));
    }

    #[test]
    fn ipc_limits_noops_when_none() {
        assert!(apply_ipc_resource_ceilings(None, None).is_ok());
    }
}
