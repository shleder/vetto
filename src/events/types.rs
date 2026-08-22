use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A security-relevant event observed by the leash shield.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ShieldEvent {
    SyscallAllowed(SyscallEvent),
    SyscallBlocked(SyscallEvent),
    SyscallSuspicious(SyscallEvent),
    AgentStarted { pid: u32, profile: String },
    AgentStopped { pid: u32, code: i32 },
}

/// Low-level syscall observation attached to syscall events.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyscallEvent {
    pub timestamp: DateTime<Utc>,
    pub pid: u32,
    pub syscall_name: String,
    pub args: Vec<String>,
    pub result: i64,
}
