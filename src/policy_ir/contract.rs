//! Authoritative Specification: Canonical Security Contract (Phase 2 / NEXT_GEN §7).
//!
//! Formalizes the immutable capability boundary between supervisor and agent
//! workload. Sealed via cryptographic digest over canonical serialization to
//! prevent tampering.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Unsealed contract payload used for deterministic canonical hashing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnsealedSecurityContract {
    pub contract_version: u32,
    pub contract_id: String,
    pub session_nonce: String,
    pub agent_identity: AgentIdentity,
    pub filesystem: FilesystemContract,
    pub network: NetworkContract,
    pub resources: ResourceContract,
    pub environment: EnvironmentContract,
    pub attestation: AttestationContract,
}

impl UnsealedSecurityContract {
    /// Compute deterministic cryptographic digest (SHA-256) of canonical serialization.
    pub fn compute_digest(&self) -> Result<String, serde_json::Error> {
        let value = serde_json::to_value(self)?;
        let json_bytes = serde_json::to_vec(&value)?;
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&json_bytes);
        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Seal the contract, binding the cryptographic digest.
    pub fn seal(self) -> Result<SecurityContract, serde_json::Error> {
        let digest = self.compute_digest()?;
        Ok(SecurityContract {
            contract_version: self.contract_version,
            contract_id: self.contract_id,
            session_nonce: self.session_nonce,
            agent_identity: self.agent_identity,
            filesystem: self.filesystem,
            network: self.network,
            resources: self.resources,
            environment: self.environment,
            attestation: self.attestation,
            contract_digest_blake3: digest,
        })
    }
}

/// Authoritative Sealed Security Contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecurityContract {
    pub contract_version: u32,
    pub contract_id: String,
    pub session_nonce: String,
    pub agent_identity: AgentIdentity,
    pub filesystem: FilesystemContract,
    pub network: NetworkContract,
    pub resources: ResourceContract,
    pub environment: EnvironmentContract,
    pub attestation: AttestationContract,
    /// Cryptographic digest of CanonicalJSON(UnsealedSecurityContract).
    /// Skipped during canonical serialization to avoid circular dependencies.
    #[serde(default, skip_serializing)]
    pub contract_digest_blake3: String,
}

impl SecurityContract {
    /// Extract unsealed payload.
    pub fn unsealed(&self) -> UnsealedSecurityContract {
        UnsealedSecurityContract {
            contract_version: self.contract_version,
            contract_id: self.contract_id.clone(),
            session_nonce: self.session_nonce.clone(),
            agent_identity: self.agent_identity.clone(),
            filesystem: self.filesystem.clone(),
            network: self.network.clone(),
            resources: self.resources.clone(),
            environment: self.environment.clone(),
            attestation: self.attestation.clone(),
        }
    }

    /// Verify that the contract digest matches the unsealed payload.
    pub fn verify_digest(&self) -> bool {
        match self.unsealed().compute_digest() {
            Ok(expected) => expected == self.contract_digest_blake3,
            Err(_) => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentIdentity {
    pub agent_name: String,
    pub agent_preset: String,
    pub agent_version: String,
    pub invoked_binary: PathBuf,
    pub invoked_args: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesystemContract {
    pub workspace_root: PathBuf,
    pub allow_read: Vec<PathBuf>,
    pub allow_write: Vec<PathBuf>,
    pub allow_execute: Vec<PathBuf>,
    pub mask_paths: Vec<PathBuf>,
    pub cow_overlay: bool,
    pub execution_root_ro: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkMode {
    Off,
    Allowlist,
    Direct,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkContract {
    pub mode: NetworkMode,
    pub allowed_domains: Vec<String>,
    pub allowed_ports: Vec<u16>,
    pub block_cloud_metadata: bool,
    pub block_loopback_daemons: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResourceContract {
    pub max_pids: u32,
    pub max_memory_bytes: u64,
    pub max_cpu_percent: u32,
    pub max_wall_time_ms: u64,
    pub max_stdout_bytes: u64,
    pub max_file_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnvironmentContract {
    pub pass_through_vars: Vec<String>,
    pub explicit_vars: BTreeMap<String, String>,
    pub redacted_patterns: Vec<String>,
    pub inject_session_nonce: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestationContract {
    pub generate_audit_jsonl: bool,
    pub sign_minisign: bool,
    pub sign_cosign_slsa: bool,
    pub evidence_level_minimum: String,
}

#[cfg(test)]
mod contract_tests {
    use super::*;

    fn sample_unsealed() -> UnsealedSecurityContract {
        UnsealedSecurityContract {
            contract_version: 1,
            contract_id: "test-contract-001".to_string(),
            session_nonce: "nonce-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: "claude".to_string(),
                agent_preset: "claude".to_string(),
                agent_version: env!("CARGO_PKG_VERSION").to_string(),
                invoked_binary: PathBuf::from("/usr/bin/claude"),
                invoked_args: vec!["run".to_string()],
            },
            filesystem: FilesystemContract {
                workspace_root: PathBuf::from("/workspace"),
                allow_read: vec![PathBuf::from("/workspace"), PathBuf::from("/usr")],
                allow_write: vec![PathBuf::from("/workspace/target")],
                allow_execute: vec![PathBuf::from("/bin"), PathBuf::from("/usr/bin")],
                mask_paths: vec![PathBuf::from("/home/user/.ssh")],
                cow_overlay: true,
                execution_root_ro: true,
            },
            network: NetworkContract {
                mode: NetworkMode::Allowlist,
                allowed_domains: vec!["api.anthropic.com".to_string()],
                allowed_ports: vec![443],
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
                explicit_vars: BTreeMap::new(),
                redacted_patterns: vec!["*_KEY".to_string()],
                inject_session_nonce: true,
            },
            attestation: AttestationContract {
                generate_audit_jsonl: true,
                sign_minisign: true,
                sign_cosign_slsa: false,
                evidence_level_minimum: "HOST_FACT".to_string(),
            },
        }
    }

    #[test]
    fn seal_and_verify_digest() {
        let unsealed = sample_unsealed();
        let sealed = unsealed.clone().seal().expect("seal contract");
        assert!(!sealed.contract_digest_blake3.is_empty());
        assert!(sealed.verify_digest());

        // Tampering with contract should invalidate digest
        let mut tampered = sealed.clone();
        tampered.filesystem.cow_overlay = false;
        assert!(!tampered.verify_digest());

        let mut tampered_net = sealed.clone();
        tampered_net.network.mode = NetworkMode::Direct;
        assert!(!tampered_net.verify_digest());
    }

    #[test]
    fn deterministic_digest() {
        let u1 = sample_unsealed();
        let u2 = sample_unsealed();
        assert_eq!(u1.compute_digest().unwrap(), u2.compute_digest().unwrap());
    }
}
