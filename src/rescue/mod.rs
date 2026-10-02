//! Workspace snapshot, atomic rollback, lock management and ephemeral execution cleanup.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

pub mod ephemeral;
pub mod lock;
pub mod rollback;
pub mod snapshot;

pub use ephemeral::handle_ephemeral_completion;

/// Security telemetry collected from session logs and reports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityTelemetry {
    pub blocked_file_count: u64,
    pub blocked_file_paths: Vec<String>,
    pub blocked_network_count: u64,
    pub blocked_network_destinations: Vec<String>,
    pub allowed_egress: Vec<String>,
}

/// Kind of file modification observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

/// Cryptographically verifiable receipt produced upon successful state repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepairReceipt {
    pub adapter: String,
    pub session_key: String,
    pub original_sha256: String,
    pub repaired_sha256: String,
    pub backup_archive_path: PathBuf,
    pub actions_applied: Vec<String>,
    pub timestamp_unix_secs: u64,
}

/// Receipt generated upon successful atomic rollback of a previous state repair.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RollbackReceipt {
    pub adapter: String,
    pub session_key: String,
    pub target_path: String,
    pub restored_sha256: String,
    pub timestamp_unix_secs: u64,
}

/// Backwards compatibility alias for modules importing `crate::rescue::types::*`.
pub mod types {
    pub use super::{ChangeType, RepairReceipt, RollbackReceipt, SecurityTelemetry};
}
