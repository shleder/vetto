//! Typed errors and exit code mapping for production execution.

use std::path::PathBuf;
use crate::policy_ir::ExecutionState;

#[derive(thiserror::Error, Debug)]
pub enum ProductionError {
    #[error("Execution timed out after {0:?} (Process tree extinction verified)")]
    TimedOut(std::time::Duration),

    #[error("invalid production contract digest: Contract BLAKE3/SHA256 digest verification failed")]
    ContractDigestMismatch,

    #[error("Lifecycle state mismatch: expected {expected:?}, got {actual:?}")]
    InvalidState {
        expected: ExecutionState,
        actual: ExecutionState,
    },

    #[error("Input drift detected between frozen contract and runtime inputs: {0}")]
    ContractDrift(String),

    #[error("Platform capability preparation failed: {0}")]
    PreparationFailed(String),

    #[error("Process spawning failed: {0}")]
    SpawnFailed(String),

    #[error("Process tree extinction breach (INV-20): {reason} (elapsed: {elapsed_ms}ms)")]
    ExtinctionBreach { reason: String, elapsed_ms: u64 },

    #[error("Evidence capture channel compromised (INV-37): {0}")]
    EvidenceDisrupted(String),

    #[error("Audit ledger hash chain verification failed: {path}")]
    AuditLedgerTampered { path: PathBuf },

    #[error("Stdio drain failure: {0}")]
    DrainFailure(String),

    #[error("Signal management error: {0}")]
    SignalError(String),
}

impl ProductionError {
    #[inline]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::TimedOut(_) => 124, // Clean timeout with verified tree extinction
            _ => 125,                 // Security invariant, contract breach or process leak
        }
    }
}
