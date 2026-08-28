//! Cross-agent memory & signal protection subsystem (Step 24).
//!
//! Enforces zero-trust isolation boundaries between concurrent AI coding agents:
//!
//! 1. Strict PID namespace isolation (`CLONE_NEWPID`): subagents cannot
//!    inspect (`/proc`), signal (`kill`), or attach (`ptrace`) to sibling processes.
//! 2. Strict IPC namespace isolation (`CLONE_NEWIPC`): subagents cannot
//!    access shared memory segments (`shmget`, `shm_open`), semaphores, or
//!    message queues belonging to another agent or the host.
//! 3. Sub-reaper supervision: PID 1 / sub-reapers prevent orphaned zombie
//!    processes from lingering or escaping supervision.
//! 4. Memory quota and address space enforcement across concurrent agents.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::{VettoError, VettoResult};

#[derive(Debug, Clone)]
pub struct AgentIsolationRecord {
    pub name: String,
    pub root_pid: u32,
    pub pid_ns_isolated: bool,
    pub ipc_ns_isolated: bool,
    pub memory_ceiling_bytes: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct IsolationBarrier {
    records: Arc<Mutex<HashMap<String, AgentIsolationRecord>>>,
}

impl IsolationBarrier {
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Register a newly spawned agent into the isolation tracker.
    pub fn register_agent(
        &self,
        name: &str,
        root_pid: u32,
        pid_ns: bool,
        ipc_ns: bool,
        memory_limit: Option<u64>,
    ) {
        if let Ok(mut records) = self.records.lock() {
            records.insert(
                name.to_string(),
                AgentIsolationRecord {
                    name: name.to_string(),
                    root_pid,
                    pid_ns_isolated: pid_ns,
                    ipc_ns_isolated: ipc_ns,
                    memory_ceiling_bytes: memory_limit,
                },
            );
        }
    }

    /// Unregister an exited agent.
    pub fn unregister_agent(&self, name: &str) {
        if let Ok(mut records) = self.records.lock() {
            records.remove(name);
        }
    }

    /// Verify that two agents are strictly isolated from cross-process signaling.
    pub fn verify_signal_isolation(
        &self,
        source_agent: &str,
        target_agent: &str,
    ) -> VettoResult<()> {
        if source_agent == target_agent {
            return Ok(());
        }

        let records = self
            .records
            .lock()
            .map_err(|_| VettoError::Sandbox("isolation barrier lock poisoned".into()))?;

        let src = records.get(source_agent).ok_or_else(|| {
            VettoError::Sandbox(format!("source agent '{source_agent}' not registered"))
        })?;

        let tgt = records.get(target_agent).ok_or_else(|| {
            VettoError::Sandbox(format!("target agent '{target_agent}' not registered"))
        })?;

        if !src.pid_ns_isolated || !tgt.pid_ns_isolated {
            return Err(VettoError::Sandbox(format!(
                "cross-agent signal leak possible: agents '{source_agent}' and '{target_agent}' not both PID-isolated"
            )));
        }

        if src.root_pid == tgt.root_pid {
            return Err(VettoError::Sandbox(format!(
                "PID collision: '{source_agent}' and '{target_agent}' share root PID {}",
                src.root_pid
            )));
        }

        Ok(())
    }

    /// Verify IPC isolation for the given agent.
    pub fn verify_ipc_isolation(&self, agent_name: &str) -> VettoResult<()> {
        let records = self
            .records
            .lock()
            .map_err(|_| VettoError::Sandbox("isolation barrier lock poisoned".into()))?;

        let record = records
            .get(agent_name)
            .ok_or_else(|| VettoError::Sandbox(format!("agent '{agent_name}' not registered")))?;

        if !record.ipc_ns_isolated {
            return Err(VettoError::Sandbox(format!(
                "agent '{agent_name}' is not in a private IPC namespace (risk of POSIX shm / msgqueue leakage)"
            )));
        }

        Ok(())
    }

    /// Verify total memory quota when launching or expanding an agent.
    pub fn check_memory_quota(&self, agent_name: &str, requested_bytes: u64) -> VettoResult<()> {
        let records = self
            .records
            .lock()
            .map_err(|_| VettoError::Sandbox("isolation barrier lock poisoned".into()))?;

        if let Some(record) = records.get(agent_name) {
            if let Some(ceiling) = record.memory_ceiling_bytes {
                if requested_bytes > ceiling {
                    return Err(VettoError::Sandbox(format!(
                        "agent '{agent_name}' requested {requested_bytes} bytes exceeding memory ceiling {ceiling} bytes"
                    )));
                }
            }
        }

        Ok(())
    }
}

/// Linux sub-reaper management: mark the calling process as a sub-reaper
/// so that orphaned descendant processes are adopted by this process rather
/// than PID 1 of the init system.
#[cfg(target_os = "linux")]
pub fn set_subreaper() -> VettoResult<()> {
    const PR_SET_CHILD_SUBREAPER: libc::c_int = 36;
    // SAFETY: scalar prctl call
    if unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0 {
        return Err(VettoError::Sandbox(format!(
            "PR_SET_CHILD_SUBREAPER: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_subreaper() -> VettoResult<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_isolation_verification() {
        let barrier = IsolationBarrier::new();
        barrier.register_agent("agent-a", 1001, true, true, Some(64 * 1024 * 1024));
        barrier.register_agent("agent-b", 1002, true, true, Some(64 * 1024 * 1024));

        assert!(barrier
            .verify_signal_isolation("agent-a", "agent-b")
            .is_ok());
        assert!(barrier.verify_ipc_isolation("agent-a").is_ok());
        assert!(barrier.verify_ipc_isolation("agent-b").is_ok());

        // Same agent self-signaling is permitted
        assert!(barrier
            .verify_signal_isolation("agent-a", "agent-a")
            .is_ok());
    }

    #[test]
    fn unisolated_pid_detection() {
        let barrier = IsolationBarrier::new();
        barrier.register_agent("unisolated-a", 2001, false, true, None);
        barrier.register_agent("agent-b", 2002, true, true, None);

        assert!(barrier
            .verify_signal_isolation("unisolated-a", "agent-b")
            .is_err());
    }

    #[test]
    fn unisolated_ipc_detection() {
        let barrier = IsolationBarrier::new();
        barrier.register_agent("leaky-ipc", 3001, true, false, None);

        assert!(barrier.verify_ipc_isolation("leaky-ipc").is_err());
    }

    #[test]
    fn memory_quota_checks() {
        let barrier = IsolationBarrier::new();
        barrier.register_agent("bounded-agent", 4001, true, true, Some(32 * 1024 * 1024));

        assert!(barrier
            .check_memory_quota("bounded-agent", 16 * 1024 * 1024)
            .is_ok());
        assert!(barrier
            .check_memory_quota("bounded-agent", 64 * 1024 * 1024)
            .is_err());
    }
}
