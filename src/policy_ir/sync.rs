//! Enterprise Policy Synchronization and Certification Engine.
//!
//! Fulfills Phase 4 of the Next-Generation Architectural Specification:
//! Synchronizes canonical security contracts across multi-agent swarm fleets,
//! verifying contract immutability and preventing policy drift with fail-closed
//! rejection (Exit 125).

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::policy_ir::SecurityContract;

/// Synchronization and policy drift errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PolicySyncError {
    #[error("Contract digest verification failed: tamper detected (exit 125)")]
    DigestVerificationFailed,

    #[error("Policy drift detected: agent '{agent_name}' contract digest mismatch (expected {expected}, got {actual}) (exit 125)")]
    PolicyDrift {
        agent_name: String,
        expected: String,
        actual: String,
    },

    #[error("No canonical policy registered for agent '{0}' (exit 125)")]
    UnregisteredPolicy(String),

    #[error("Invalid policy manifest: {0}")]
    InvalidManifest(String),
}

impl PolicySyncError {
    /// Exit code mandated by Next-Gen fail-closed architecture (§18 / INV-01).
    pub fn exit_code(&self) -> i32 {
        125
    }
}

/// A serialized entry in an enterprise policy sync manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyManifestEntry {
    pub agent_name: String,
    pub contract_digest_blake3: String,
    pub supervisor_version: String,
    pub network_mode: String,
    pub cow_overlay_enabled: bool,
}

/// An enterprise policy sync manifest for fleet distribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnterpriseSyncManifest {
    pub schema_version: u32,
    pub timestamp_utc: String,
    pub policies: BTreeMap<String, PolicyManifestEntry>,
}

impl EnterpriseSyncManifest {
    /// Validates the manifest schema version and structure.
    pub fn validate(&self) -> Result<(), PolicySyncError> {
        if self.schema_version != 1 {
            return Err(PolicySyncError::InvalidManifest(format!(
                "unsupported schema version {}; expected 1",
                self.schema_version
            )));
        }
        Ok(())
    }

    /// Verifies a worker's SecurityContract against this distributed policy manifest.
    pub fn verify_contract(&self, contract: &SecurityContract) -> Result<(), PolicySyncError> {
        self.validate()?;

        if !contract.verify_digest() {
            return Err(PolicySyncError::DigestVerificationFailed);
        }

        let agent_name = &contract.agent_identity.agent_name;
        let entry = self
            .policies
            .get(agent_name)
            .ok_or_else(|| PolicySyncError::UnregisteredPolicy(agent_name.clone()))?;

        if entry.contract_digest_blake3 != contract.contract_digest_blake3 {
            return Err(PolicySyncError::PolicyDrift {
                agent_name: agent_name.clone(),
                expected: entry.contract_digest_blake3.clone(),
                actual: contract.contract_digest_blake3.clone(),
            });
        }

        Ok(())
    }
}

/// Enterprise Policy Synchronizer managing canonical contracts for agent fleets.
#[derive(Debug, Clone, Default)]
pub struct EnterprisePolicySync {
    canonical_contracts: BTreeMap<String, SecurityContract>,
}

impl EnterprisePolicySync {
    pub fn new() -> Self {
        Self {
            canonical_contracts: BTreeMap::new(),
        }
    }

    /// Registers a canonical, sealed SecurityContract for an agent.
    /// Fails closed with PolicyDrift if an attempt is made to register a conflicting policy.
    pub fn register_contract(&mut self, contract: SecurityContract) -> Result<(), PolicySyncError> {
        if !contract.verify_digest() {
            return Err(PolicySyncError::DigestVerificationFailed);
        }
        let agent_name = &contract.agent_identity.agent_name;
        if let Some(existing) = self.canonical_contracts.get(agent_name) {
            if existing.contract_digest_blake3 != contract.contract_digest_blake3 {
                return Err(PolicySyncError::PolicyDrift {
                    agent_name: agent_name.clone(),
                    expected: existing.contract_digest_blake3.clone(),
                    actual: contract.contract_digest_blake3.clone(),
                });
            }
        }
        self.canonical_contracts
            .insert(agent_name.clone(), contract);
        Ok(())
    }

    /// Retrieves a canonical contract for a given agent name.
    pub fn get_contract(&self, agent_name: &str) -> Option<&SecurityContract> {
        self.canonical_contracts.get(agent_name)
    }

    /// Number of registered canonical policies.
    pub fn count(&self) -> usize {
        self.canonical_contracts.len()
    }

    /// Verifies that a worker's supplied contract conforms to the enterprise canonical contract.
    ///
    /// Fails closed (Exit 125) on:
    /// - Corrupted or tampered contract digest
    /// - Mismatch against the enterprise canonical digest
    /// - Unregistered agent policy
    pub fn verify_worker_contract(
        &self,
        worker_contract: &SecurityContract,
    ) -> Result<(), PolicySyncError> {
        if !worker_contract.verify_digest() {
            return Err(PolicySyncError::DigestVerificationFailed);
        }

        let agent_name = &worker_contract.agent_identity.agent_name;
        let canonical = self
            .canonical_contracts
            .get(agent_name)
            .ok_or_else(|| PolicySyncError::UnregisteredPolicy(agent_name.clone()))?;

        if canonical.contract_digest_blake3 != worker_contract.contract_digest_blake3 {
            return Err(PolicySyncError::PolicyDrift {
                agent_name: agent_name.clone(),
                expected: canonical.contract_digest_blake3.clone(),
                actual: worker_contract.contract_digest_blake3.clone(),
            });
        }

        Ok(())
    }

    /// Generates a machine-readable sync manifest for distribution to remote fleet nodes.
    pub fn export_manifest(&self) -> Result<EnterpriseSyncManifest> {
        let mut policies = BTreeMap::new();
        for (name, contract) in &self.canonical_contracts {
            policies.insert(
                name.clone(),
                PolicyManifestEntry {
                    agent_name: name.clone(),
                    contract_digest_blake3: contract.contract_digest_blake3.clone(),
                    supervisor_version: contract.agent_identity.agent_version.clone(),
                    network_mode: format!("{:?}", contract.network.mode),
                    cow_overlay_enabled: contract.filesystem.cow_overlay,
                },
            );
        }

        Ok(EnterpriseSyncManifest {
            schema_version: 1,
            timestamp_utc: chrono::Utc::now().to_rfc3339(),
            policies,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_ir::contract::{
        AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract,
        NetworkContract, NetworkMode, ResourceContract, UnsealedSecurityContract,
    };
    use std::path::PathBuf;

    fn sample_contract(name: &str) -> SecurityContract {
        let unsealed = UnsealedSecurityContract {
            contract_version: 1,
            contract_id: format!("contract-{}", name),
            session_nonce: "nonce-12345".to_string(),
            agent_identity: AgentIdentity {
                agent_name: name.to_string(),
                agent_preset: name.to_string(),
                agent_version: "0.2.24".to_string(),
                invoked_binary: PathBuf::from("/usr/bin").join(name),
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
                explicit_vars: BTreeMap::new(),
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
        unsealed.seal().expect("seal contract")
    }

    #[test]
    fn test_sync_register_and_verify_pass() {
        let mut sync = EnterprisePolicySync::new();
        let canonical = sample_contract("claude");
        sync.register_contract(canonical.clone()).expect("register");

        assert_eq!(sync.count(), 1);
        assert!(sync.verify_worker_contract(&canonical).is_ok());
    }

    #[test]
    fn test_sync_drift_rejection() {
        let mut sync = EnterprisePolicySync::new();
        let canonical = sample_contract("claude");
        sync.register_contract(canonical.clone()).expect("register");

        // Create altered contract for same agent
        let mut unsealed = canonical.unsealed();
        unsealed.resources.max_pids = 512;
        let drifted = unsealed.seal().unwrap();

        let err = sync.verify_worker_contract(&drifted).unwrap_err();
        assert_eq!(err.exit_code(), 125);
        assert!(matches!(err, PolicySyncError::PolicyDrift { .. }));
    }

    #[test]
    fn test_sync_unregistered_agent() {
        let sync = EnterprisePolicySync::new();
        let unregistered = sample_contract("unknown-agent");
        let err = sync.verify_worker_contract(&unregistered).unwrap_err();
        assert_eq!(err.exit_code(), 125);
        assert!(matches!(err, PolicySyncError::UnregisteredPolicy(_)));
    }

    #[test]
    fn test_register_conflicting_contract_fails_closed() {
        let mut sync = EnterprisePolicySync::new();
        let canonical = sample_contract("claude");
        sync.register_contract(canonical.clone()).unwrap();

        // Registering identical contract is idempotent
        assert!(sync.register_contract(canonical.clone()).is_ok());

        // Registering conflicting contract for same agent fails with PolicyDrift
        let mut unsealed = canonical.unsealed();
        unsealed.resources.max_pids = 999;
        let altered = unsealed.seal().unwrap();

        let err = sync.register_contract(altered).unwrap_err();
        assert_eq!(err.exit_code(), 125);
        assert!(matches!(err, PolicySyncError::PolicyDrift { .. }));
    }

    #[test]
    fn test_export_and_verify_manifest() {
        let mut sync = EnterprisePolicySync::new();
        let ca = sample_contract("agent-a");
        let cb = sample_contract("agent-b");
        sync.register_contract(ca.clone()).unwrap();
        sync.register_contract(cb.clone()).unwrap();

        let manifest = sync.export_manifest().expect("export manifest");
        assert_eq!(manifest.policies.len(), 2);
        assert!(manifest.policies.contains_key("agent-a"));
        assert!(manifest.policies.contains_key("agent-b"));

        // Manifest verifies registered contracts
        assert!(manifest.verify_contract(&ca).is_ok());
        assert!(manifest.verify_contract(&cb).is_ok());

        // Manifest rejects unregistered agent
        let unregistered = sample_contract("agent-c");
        let unreg_err = manifest.verify_contract(&unregistered).unwrap_err();
        assert!(matches!(unreg_err, PolicySyncError::UnregisteredPolicy(_)));

        // Manifest rejects drifted contract
        let mut unsealed = ca.unsealed();
        unsealed.resources.max_memory_bytes = 4 * 1024 * 1024 * 1024;
        let drifted = unsealed.seal().unwrap();
        let drift_err = manifest.verify_contract(&drifted).unwrap_err();
        assert!(matches!(drift_err, PolicySyncError::PolicyDrift { .. }));

        // Invalid manifest schema version fails closed
        let mut invalid_manifest = manifest.clone();
        invalid_manifest.schema_version = 2;
        let inv_err = invalid_manifest.verify_contract(&ca).unwrap_err();
        assert!(matches!(inv_err, PolicySyncError::InvalidManifest(_)));
    }
}
