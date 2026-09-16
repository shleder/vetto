//! Authoritative Verdict Engine and Non-Negotiable Decision Truth Table.
//!
//! Fulfills Section 18 of the Next-Generation Architectural Specification:
//! Implements the 2D Verdict Matrix (VerdictStatus × EvidenceStrength),
//! fail-closed exit code assignment (Exit 125 on contract breaches), and
//! CoW layer commit/wipe decisions.

use serde::{Deserialize, Serialize};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

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
            (VerdictStatus::Pass, EvidenceStrength::Strong) => {
                "Commit CoW changes to host workspace."
            }
            (VerdictStatus::Pass, EvidenceStrength::Partial) => {
                "Commit CoW changes to host workspace with partial warning."
            }
            (VerdictStatus::Pass, EvidenceStrength::Unsupported) => {
                "Invalid verdict: unsupported platform cannot pass."
            }
            (VerdictStatus::Fail, _) => "Wipe CoW layer; abort session immediately.",
            (VerdictStatus::Inconclusive, _) => "Wipe CoW layer; audit ledger inconclusive.",
            (VerdictStatus::NotApplicable, _) => "Execution aborted pre-launch.",
        }
    }

    /// Whether the execution cleanly succeeded (contract satisfied and workload exit code == 0).
    pub fn is_success(&self) -> bool {
        self.status == VerdictStatus::Pass
            && self.strength != EvidenceStrength::Unsupported
            && self.exit_code == 0
    }

    /// Whether the security contract invariants were satisfied (regardless of workload exit code).
    pub fn is_contract_satisfied(&self) -> bool {
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
        contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        evidence_channel_intact: bool,
        agent_exit_code: i32,
    ) -> FinalVerdict {
        Self::evaluate_with_strength(
            contract,
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
        contract: &SecurityContract,
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
                reason: "Platform lacks necessary kernel enforcement primitives: fail-closed"
                    .to_string(),
            };
        }

        // Invariant 1: Any unauthorized access or surviving zombie process is immediate FAIL
        if kernel_denials > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!(
                    "Contract violation: {} kernel capability denials recorded",
                    kernel_denials
                ),
            };
        }

        if unauthorized_writes > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!(
                    "VFS violation: {} writes outside authorized workspace",
                    unauthorized_writes
                ),
            };
        }

        if zombies_survived > 0 {
            return FinalVerdict {
                status: VerdictStatus::Fail,
                strength,
                exit_code: 125,
                reason: format!(
                    "Lifecycle breach: {} descendant processes escaped extinction",
                    zombies_survived
                ),
            };
        }

        // Invariant 2: Interrupted evidence channel yields INCONCLUSIVE
        if !evidence_channel_intact {
            return FinalVerdict {
                status: VerdictStatus::Inconclusive,
                strength,
                exit_code: 125,
                reason: "Evidence capture channel dropped events: audit ledger inconclusive"
                    .to_string(),
            };
        }

        // Invariant 3: Mandatory cryptographic signing (INV-36)
        if contract.crypto.minisign_enabled {
            if let Err(err) = verify_contract_signature(contract) {
                return FinalVerdict {
                    status: VerdictStatus::Fail,
                    strength: EvidenceStrength::Strong,
                    exit_code: 125,
                    reason: format!(
                        "Cryptographic signing verification failed (INV-36): {}",
                        err
                    ),
                };
            }
        }

        // Invariant 4: Clean execution yields PASS
        FinalVerdict {
            status: VerdictStatus::Pass,
            strength,
            exit_code: agent_exit_code,
            reason: "All security contract invariants satisfied with authoritative host facts"
                .to_string(),
        }
    }
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err("hex string must have even length".to_string());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex byte at index {i}: {e}"))
        })
        .collect()
}

fn verify_contract_signature(contract: &SecurityContract) -> Result<(), String> {
    let sig_hex = contract
        .crypto
        .signature
        .as_deref()
        .ok_or_else(|| "cryptographic signature is missing from contract".to_string())?;

    if sig_hex.trim().is_empty() {
        return Err("cryptographic signature is empty".to_string());
    }

    let pubkey_hex = contract
        .crypto
        .public_key
        .as_deref()
        .ok_or_else(|| "cryptographic public key is missing from contract".to_string())?;

    if pubkey_hex.trim().is_empty() {
        return Err("cryptographic public key is empty".to_string());
    }

    let pubkey_bytes = decode_hex(pubkey_hex)?;
    if pubkey_bytes.len() != 32 {
        return Err(format!(
            "invalid public key length: expected 32 bytes, got {}",
            pubkey_bytes.len()
        ));
    }
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pubkey_bytes);

    let verifying_key = VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| format!("invalid ed25519 public key: {e}"))?;

    let sig_bytes = decode_hex(sig_hex)?;
    if sig_bytes.len() != 64 {
        return Err(format!(
            "invalid signature length: expected 64 bytes, got {}",
            sig_bytes.len()
        ));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);

    let signature = Signature::from_bytes(&sig_arr);

    // Verify signature against contract BLAKE3 digest or session nonce
    let digest_bytes = contract.contract_digest_blake3.as_bytes();
    if verifying_key.verify(digest_bytes, &signature).is_ok() {
        return Ok(());
    }

    if let Ok(raw_digest) = decode_hex(&contract.contract_digest_blake3) {
        if verifying_key.verify(&raw_digest, &signature).is_ok() {
            return Ok(());
        }
    }

    let nonce_bytes = contract.session_nonce.as_bytes();
    if verifying_key.verify(nonce_bytes, &signature).is_ok() {
        return Ok(());
    }

    Err("ed25519 signature verification failed against contract digest and nonce".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_ir::{
        AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract,
        NetworkContract, NetworkMode, ResourceContract, UnsealedSecurityContract,
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
                mode: NetworkMode::Off,
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
        assert!(verdict.is_contract_satisfied());
        assert_eq!(
            verdict.recommended_action(),
            "Commit CoW changes to host workspace."
        );
    }

    #[test]
    fn test_workload_nonzero_exit_code() {
        let contract = mock_contract();
        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 1);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 1);
        assert!(verdict.is_contract_satisfied());
        assert!(!verdict.is_success()); // Failed workload exit code is not a success
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
        assert_eq!(
            verdict.recommended_action(),
            "Wipe CoW layer; abort session immediately."
        );
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
            &contract,
            0,
            0,
            0,
            true,
            0,
            EvidenceStrength::Unsupported,
        );
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Unsupported);
        assert_eq!(verdict.exit_code, 125);
        assert_eq!(verdict.display_badge(), "FAIL [UNSUPPORTED]");
    }

    #[test]
    fn test_inv36_missing_signature_downgrades_to_fail_125() {
        let mut contract = mock_contract();
        contract.crypto.minisign_enabled = true;
        contract.crypto.signature = None;
        contract.crypto.public_key = None;

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 125);
        assert!(verdict.reason.contains("INV-36"));
        assert!(verdict.reason.contains("missing"));
    }

    #[test]
    fn test_inv36_invalid_signature_downgrades_to_fail_125() {
        let mut contract = mock_contract();
        contract.crypto.minisign_enabled = true;
        contract.crypto.public_key = Some("00".repeat(32));
        contract.crypto.signature = Some("ff".repeat(64));

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Fail);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 125);
        assert!(verdict.reason.contains("INV-36"));
    }

    #[test]
    fn test_inv36_valid_signature_awards_pass_strong() {
        use ed25519_dalek::{Signer, SigningKey};
        use rand_core::OsRng;

        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        let mut contract = mock_contract();
        let digest_bytes = contract.contract_digest_blake3.as_bytes();
        let signature = signing_key.sign(digest_bytes);

        let sig_hex: String = signature
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let pk_hex: String = verifying_key
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();

        contract = contract.with_minisign(true, Some(sig_hex), Some(pk_hex));

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 0);
        assert!(verdict.is_success());
        assert!(verdict.is_contract_satisfied());
    }

    #[test]
    fn test_inv36_disabled_awards_pass_without_signature() {
        let contract = mock_contract();
        assert!(!contract.crypto.minisign_enabled);

        let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
        assert_eq!(verdict.status, VerdictStatus::Pass);
        assert_eq!(verdict.strength, EvidenceStrength::Strong);
        assert_eq!(verdict.exit_code, 0);
        assert!(verdict.is_success());
    }
}
