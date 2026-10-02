//! Typed error taxonomy for the supervision subsystem.
//!
//! Enforces deterministic exit codes matching Section 5.2.1 and INV-01:
//! - 127 (`EXIT_COMMAND_NOT_FOUND`): Agent executable resolution failure
//! - 125 (`EXIT_FAIL_CLOSED`): Security invariant failure, preflight leak, relay mismatch, spawn error
//! - 2 (`EXIT_INVALID_USAGE`): Empty agent command or invalid usage
//! - 1 (`EXIT_AGENT_ERROR`): Generic operational or agent error

use thiserror::Error;
use crate::exit_codes;

#[derive(Error, Debug)]
pub enum SuperviseError {
    #[error("Agent command is empty")]
    EmptyAgentCommand,

    #[error("Agent executable '{cmd}' not found in PATH: {source}")]
    ExecutableNotFound {
        cmd: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Network relay requires Tier FULL: tier '{tier}' does not support unprivileged userns")]
    NetworkRelayTierMismatch { tier: String },

    #[error("Security policy load failure: {0}")]
    PolicyLoadFailed(#[source] anyhow::Error),

    #[error("Preflight boundary check detected leaks ({leaks} found); fail-closed rejection")]
    PreflightVerificationFailed { leaks: usize },

    #[error("PTY/pipe allocation failure: {0}")]
    StdioAllocationFailed(#[source] std::io::Error),

    #[error("Sandbox process spawn failure: {0}")]
    ProcessSpawnFailed(#[source] std::io::Error),

    #[error("Signal controller failure: {0}")]
    SignalInstallationFailed(String),

    #[error("I/O pump failure: {0}")]
    IoPumpFailed(#[source] std::io::Error),

    #[error("Report generation failure: {0}")]
    ReportGenerationFailed(#[source] anyhow::Error),

    #[error(transparent)]
    Fatal(#[from] anyhow::Error),
}

impl SuperviseError {
    /// Deterministic process exit code mapping.
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::ExecutableNotFound { .. } => exit_codes::EXIT_COMMAND_NOT_FOUND, // 127
            Self::PreflightVerificationFailed { .. }
            | Self::NetworkRelayTierMismatch { .. }
            | Self::PolicyLoadFailed(_)
            | Self::StdioAllocationFailed(_)
            | Self::ProcessSpawnFailed(_) => exit_codes::EXIT_FAIL_CLOSED, // 125 (INV-01)
            Self::EmptyAgentCommand => exit_codes::EXIT_INVALID_USAGE,      // 2
            _ => exit_codes::EXIT_AGENT_ERROR,                             // 1
        }
    }
}

impl From<crate::sandbox::production::ProductionError> for SuperviseError {
    fn from(err: crate::sandbox::production::ProductionError) -> Self {
        Self::ProcessSpawnFailed(std::io::Error::new(
            std::io::ErrorKind::Other,
            err.to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_mappings() {
        assert_eq!(
            SuperviseError::ExecutableNotFound {
                cmd: "missing".into(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found")
            }
            .exit_code(),
            127
        );

        assert_eq!(
            SuperviseError::PreflightVerificationFailed { leaks: 3 }.exit_code(),
            125
        );

        assert_eq!(
            SuperviseError::NetworkRelayTierMismatch {
                tier: "fs-only".into()
            }
            .exit_code(),
            125
        );

        assert_eq!(
            SuperviseError::StdioAllocationFailed(std::io::Error::new(
                std::io::ErrorKind::Other,
                "pty failure"
            ))
            .exit_code(),
            125
        );

        assert_eq!(
            SuperviseError::ProcessSpawnFailed(std::io::Error::new(
                std::io::ErrorKind::Other,
                "spawn failed"
            ))
            .exit_code(),
            125
        );

        assert_eq!(SuperviseError::EmptyAgentCommand.exit_code(), 2);

        assert_eq!(
            SuperviseError::PolicyLoadFailed(anyhow::anyhow!("syntax error")).exit_code(),
            125
        );

        assert_eq!(
            SuperviseError::SignalInstallationFailed("sigaction failed".into()).exit_code(),
            1
        );

        assert_eq!(
            SuperviseError::IoPumpFailed(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "pipe closed"
            ))
            .exit_code(),
            1
        );

        assert_eq!(
            SuperviseError::ReportGenerationFailed(anyhow::anyhow!("disk full")).exit_code(),
            1
        );

        assert_eq!(
            SuperviseError::Fatal(anyhow::anyhow!("unexpected")).exit_code(),
            1
        );
    }

    #[test]
    fn test_production_error_conversion() {
        let prod_err = crate::sandbox::production::ProductionError::ContractDigestMismatch;
        let sup_err: SuperviseError = prod_err.into();
        assert_eq!(sup_err.exit_code(), 125);
        assert!(matches!(sup_err, SuperviseError::ProcessSpawnFailed(_)));
    }
}
