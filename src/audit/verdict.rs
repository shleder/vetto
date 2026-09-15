//! Authoritative Verdict Engine and Non-Negotiable Decision Truth Table.
//!
//! Fulfills Section 18 of the Next-Generation Architectural Specification:
//! Implements the 2D Verdict Matrix (VerdictStatus × EvidenceStrength),
//! fail-closed exit code assignment (Exit 125 on contract breaches), and
//! CoW layer commit/wipe decisions.

use serde::{Deserialize, Serialize};

use crate::policy_ir::SecurityContract;

/// Verdict dimension of the 2D matrix (§18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictStatus {
    Pass,
    Fail,
    Inconclusive,
    NotApplicable,
}

impl VerdictStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Inconclusive => "INCONCLUSIVE",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Evidence strength dimension of the 2D matrix (§18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceStrength {
    Strong,
    Partial,
    Unsupported,
}

impl EvidenceStrength {
    pub fn label(self) -> &'static str {
        match self {
            Self::Strong => "STRONG",
            Self::Partial => "PARTIAL",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

/// Final authoritative execution verdict (§18.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalVerdict {
    pub status: VerdictStatus,
    pub strength: EvidenceStrength,
    pub exit_code: i32,
    pub reason: String,
}

impl FinalVerdict {
    /// Formatted two-dimensional verdict badge (e.g. `PASS [STRONG]`, `FAIL [STRONG]`).
    pub fn display_badge(&self) -> String {
        format!("{} [{}]", self.status.label(), self.strength.label())
    }

    /// Action mandated by the Decision Truth Table (§18.2).
    pub fn recommended_action(&self) -> &'static str {
        match (self.status, self.strength) {
            (VerdictStatus::Pass, EvidenceStrength::Strong) => "Commit CoW changes to host workspace.",
            (VerdictStatus::Pass, EvidenceStrength::Partial) => "Commit CoW changes to host workspace with partial warning.",
            (VerdictStatus::Pass, EvidenceStrength::Unsupported) => "Invalid verdict: unsupported platform cannot pass.",
            (VerdictStatus::Fail, _) => "Wipe CoW layer; abort session immediately.",
            (VerdictStatus::Inconclusive, _) => "Wipe CoW layer; audit ledger inconclusive.",
            (VerdictStatus::NotApplicable, _) => "Execution aborted pre-launch.",
        }
    }

    /// Whether the execution cleanly succeeded and is safe to commit.
    pub fn is_success(&self) -> bool {
        self.status == VerdictStatus::Pass && self.strength != EvidenceStrength::Unsupported
    }
}

/// Authoritative Verdict Engine (§18.3).
pub struct VerdictEngine;

impl VerdictEngine {
    /// Evaluates execution parameters against the Canonical Security Contract.
    ///
    /// Non-negotiable decisions:
    /// - Kernel capability denials > 0 -> FAIL [STRONG] (Exit 125)
    /// - Unauthorized writes > 0 -> FAIL [STRONG] (Exit 125)
    /// - Zombie processes survived > 0 -> FAIL [STRONG] (Exit 125)
    /// - Interrupted evidence channel -> INCONCLUSIVE [STRONG] (Exit 125)
    /// - Clean execution -> PASS [STRONG] (Agent exit code)
    pub fn evaluate(
        _contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        evidence_channel_intact: bool,
        agent_exit_code: i32,
    ) -> FinalVerdict {
        Self::evaluate_with_strength(
            _contract,
            kernel_denials,
            unauthorized_writes,
            zombies_survived,
            evidence_channel_intact,
            agent_exit_code,
            EvidenceStrength::Strong,
        )
    }

    /// Evaluates execution with custom evidence strength (e.g. for unsupported or partial platforms).
    pub fn evaluate_with_strength(
        _contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        evidence_channel_intact: bool,
        agent_exit_code: i32,
        strength: EvidenceStrength,
    ) -> FinalVerdict {
        if strength == EvidenceStrength::Unsupported {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength: EvidenceStrength::Unsupported,
                exit_code: 125,
                reason: "Platform lacks necessary kernel enforcement primitives: fail-closed".to_string(),
            };
        }

        // Invariant 1: Any unauthorized access or surviving zombie process is immediate FAIL
        if kernel_denials > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!("Contract violation: {} kernel capability denials recorded", kernel_denials),
            };
        }

        if unauthorized_writes > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!("VFS violation: {} writes outside authorized workspace", unauthorized_writes),
            };
        }

        if zombies_survived > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!("Lifecycle breach: {} descendant processes escaped extinction", zombies_survived),
            };
        }

        // Invariant 2: Interrupted evidence channel yields INCONCLUSIVE
        if !evidence_channel_intact {
            return FinalVerdict {
                status: VerdictStatus::Inconclusive,
                strength,
                exit_code: 125,
                reason: "Evidence capture channel dropped events: audit ledger inconclusive".to_string(),
            };
        }

        // Invariant 3: Clean execution yields PASS
        FinalVerdict {
            status: VerdictStatus::Pass,
            strength,
            exit_code: agent_exit_code,
            reason: "All security contract invariants satisfied with authoritative host facts".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_ir::{
        AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract, NetworkContract,
        NetworkMode, ResourceContract, UnsealedSecurityContract,
    };
    use std::path::PathBuf;

    fn mock_contract() -> SecurityContract {
        let unsealed = UnsealedSecurityContract {
            contract_version: 1,
            contract_id: "test-contract-001".to_string(),
            session_nonce: "nonce-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: "test-agent".to_string(),
                agent_preset: "test".to_string(),
                agent_version: "0.2.24".to_string(),
                invoked_binary: PathBuf::from("/usr/bin/test"),
                invoked_args: vec!["run".to_string()],
            },
            filesystem: FilesystemContract {
                workspace_root: PathBuf::from("/workspace"),
                allow_read: vec![PathBuf::from("/workspace")],
                allow_write: vec![PathBuf::from("/workspace")],
                allow_execute: vec![PathBuf::from("/bin")],
                mask_paths: vec![PathBuf::from("/home/user/.ssh")],
                cow_overlay: true,
                execution_root_ro: true,
            },
            network: NetworkContract {
                mode: NetworkMode::Strict,
                allowed_domains: vec![],
                allowed_ports: vec![],
                block_cloud_metadata: true,
                block_loopback_daemons: true,
            },
            resources: ResourceContract {
                max_pids: 128,
                max_memory_bytes: 2 * 1024 * 1024 * 1024,
                max_cpu_percent: 100,
                max_wall_time_ms: 120_000,
                max_stdout_bytes: 10 * 1024 * 1024,
                max_file_size_bytes: 100 * 1024 * 1024,
            },
            environment: EnvironmentContract {
                pass_through_vars: vec!["PATH".to_string()],
                explicit_vars: std::collections::BTreeMap::new(),
                redacted_patterns: vec!["*_KEY".to_string()],
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: true,
                sign_cosign_slsa: true,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        };
        unsealed.seal().expect("seal mock contract")
    }

    #[test]
    fn test_clean_pass_strong() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 0);
        assert_eq!(verdict.display_badge(), "PASS [STRONG]");
        assert!(verdict.is_success());
        assert_eq!(verdict.recommended_action(), "Commit CoW changes to host workspace.");
    }

    #[test]
    fn test_kernel_denials_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 3, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "FAIL [STRONG]");
        assert!(!verdict.is_success());
        assert_eq!(verdict.recommended_action(), "Wipe CoW layer; abort session immediately.");
    }

    #[test]
    fn test_unauthorized_writes_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 1, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.exit_code, 125);
    }

    #[test]
    fn test_zombies_survived_fail_closed() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 2, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.exit_code, 125);
    }

    #[test]
    fn test_inconclusive_evidence_channel() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, false, 0);
        assert_eq!(verdict.status, VerdictStatus::Inconclusive);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "INCONCLUSIVE [STRONG]");
    }

    #[test]
    fn test_unsupported_platform() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate_with_strength(
            &contract, 0, 0, 0, true, 0, EvidenceStrength::Unsupported,
        );
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Unsupported);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "FAIL [UNSUPPORTED]");
    }
}
