use std::path::PathBuf;

use serde::Serialize;

pub const DEFAULT_MAX_FILES: usize = 10_000;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_MAX_SESSION_BYTES: u64 = 64 * 1024 * 1024;
pub const DEFAULT_MAX_RECORD_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct RescueContext {
    pub root: PathBuf,
    pub max_files: usize,
    pub max_total_bytes: u64,
    pub max_session_bytes: u64,
    pub max_record_bytes: usize,
}

impl RescueContext {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            max_files: DEFAULT_MAX_FILES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
            max_record_bytes: DEFAULT_MAX_RECORD_BYTES,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Availability {
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdapterStatus {
    pub adapter: String,
    pub availability: Availability,
    pub support_level: String,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionRef {
    pub adapter: String,
    pub key: String,
    pub relative_path: String,
    pub bytes: u64,
    pub modified_unix_secs: Option<u64>,
    #[serde(skip)]
    pub(crate) source_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SessionHealth {
    Healthy,
    Warning,
    Corrupt,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub adapter: String,
    pub key: String,
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
    pub health: SessionHealth,
    pub records: usize,
    pub malformed_records: usize,
    pub oversized_records: usize,
    pub terminated_with_newline: bool,
    /// Stable, machine-readable semantic findings discovered without replaying
    /// the provider state.  Adapters must keep these bounded and must never
    /// include raw prompts, tool arguments, or credentials.
    pub findings: Vec<String>,
    pub notices: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotReceipt {
    pub adapter: String,
    pub source_key: String,
    pub destination: String,
    pub bytes: u64,
    pub sha256: String,
    pub source_preserved: bool,
}
