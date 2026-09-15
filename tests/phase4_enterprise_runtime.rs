//! Integration tests for Phase 4: Production Enterprise & Multi-Agent Fleet GA.
//!
//! Covers:
//! - §17.2.2 Cosign / Sigstore SLSA Level 3 In-Toto attestation envelopes
//! - §18 Authoritative Verdict Engine & Non-Negotiable Decision Truth Table
//! - §19 Multi-Agent Fleet Concurrency & Fair-Share Cgroups (20-100 agents)
//! - §12.1 Mathematical Process Tree Extinction Theorem verification
//! - Enterprise Policy Synchronization and anti-drift certification

use std::collections::BTreeMap;
use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use vetto::audit::verdict::{EvidenceStrength, VerdictEngine, VerdictStatus};
use vetto::crypto::slsa::{
    CosignSlsaBuilder, IN_TOTO_PAYLOAD_TYPE, IN_TOTO_STATEMENT_V1, SLSA_PROVENANCE_V1,
};
use vetto::multi::fleet::{
    FleetConfig, FleetManager, DEFAULT_BASE_PORT, DEFAULT_CPU_WEIGHT, DEFAULT_MEMORY_LIMIT_BYTES,
    DEFAULT_PIDS_MAX,
};
use vetto::policy_ir::contract::{
    AgentIdentity, AttestationContract, EnvironmentContract, FilesystemContract, NetworkContract,
    NetworkMode, ResourceContract, SecurityContract, UnsealedSecurityContract,
};
use vetto::policy_ir::sync::{EnterprisePolicySync, PolicySyncError};
use vetto::proctree::{
    ExtinctionVerifier, PlatformExtinctionTier, FAIL_CLOSED_EXTINCTION_EXIT_CODE,
    MAX_EXTINCTION_DEADLINE_MS,
};

fn create_sealed_contract(name: &str) -> SecurityContract {
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
    unsealed.seal().expect("contract must seal successfully")
}

#[test]
fn test_slsa_l3_attestation_envelope_and_signature() {
    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);

    let contract_id = "7b0a8806-3bc5-4c07-9fa4-89c02d59cf0a";
    let agent_name = "claude-code";

    let builder = CosignSlsaBuilder::new(contract_id, agent_name)
        .subject(
            "git-commit:b3ea2af",
            "8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a",
        )
        .builder_id("vetto-runtime:v0.40.0")
        .invocation_id("session-550e8400-e29b-41d4-a716-446655440000")
        .timestamps("2026-09-14T15:30:00Z", "2026-09-14T15:30:12Z");

    let signed_envelope = builder.sign(&signing_key).expect("signing must succeed");

    assert_eq!(signed_envelope.payload_type, IN_TOTO_PAYLOAD_TYPE);
    assert_eq!(
        signed_envelope.statement.statement_type,
        IN_TOTO_STATEMENT_V1
    );
    assert_eq!(signed_envelope.statement.predicate_type, SLSA_PROVENANCE_V1);
    assert_eq!(signed_envelope.signature.len(), 128); // 64-byte Ed25519 in hex

    let statement_json = signed_envelope.statement.to_json().unwrap();
    assert!(statement_json.contains(contract_id));
    assert!(statement_json.contains(agent_name));
    assert!(statement_json.contains("git-commit:b3ea2af"));

    // Cryptographically verify with public key
    let verifying_key = signing_key.verifying_key();
    assert!(signed_envelope.verify(&verifying_key).is_ok());

    // Wrong public key rejects
    let wrong_key = SigningKey::generate(&mut csprng).verifying_key();
    assert!(signed_envelope.verify(&wrong_key).is_err());

    // Tampered payload rejects
    let mut tampered_envelope = signed_envelope.clone();
    tampered_envelope.payload.push_str(" ");
    assert!(tampered_envelope.verify(&verifying_key).is_err());
}

#[test]
fn test_verdict_engine_all_matrix_states() {
    let contract = create_sealed_contract("claude");

    // 1. Pass [Strong]
    let v_pass = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
    assert_eq!(v_pass.status, VerdictStatus::Pass);
    assert_eq!(v_pass.strength, EvidenceStrength::Strong);
    assert_eq!(v_pass.exit_code, 0);
    assert!(v_pass.is_success());
    assert_eq!(v_pass.display_badge(), "PASS [STRONG]");
    assert_eq!(
        v_pass.recommended_action(),
        "Commit CoW changes to host workspace."
    );

    // 2. Fail [Strong] - kernel denials
    let v_denial = VerdictEngine::evaluate(&contract, 5, 0, 0, true, 0);
    assert_eq!(v_denial.status, VerdictStatus::Fail);
    assert_eq!(v_denial.strength, EvidenceStrength::Strong);
    assert_eq!(v_denial.exit_code, 125);
    assert!(!v_denial.is_success());
    assert_eq!(v_denial.display_badge(), "FAIL [STRONG]");
    assert_eq!(
        v_denial.recommended_action(),
        "Wipe CoW layer; abort session immediately."
    );

    // 3. Fail [Strong] - unauthorized writes
    let v_write = VerdictEngine::evaluate(&contract, 0, 2, 0, true, 0);
    assert_eq!(v_write.status, VerdictStatus::Fail);
    assert_eq!(v_write.exit_code, 125);

    // 4. Fail [Strong] - zombie processes survived
    let v_zombie = VerdictEngine::evaluate(&contract, 0, 0, 1, true, 0);
    assert_eq!(v_zombie.status, VerdictStatus::Fail);
    assert_eq!(v_zombie.exit_code, 125);

    // 5. Inconclusive [Strong] - dropped audit channel
    let v_inconcl = VerdictEngine::evaluate(&contract, 0, 0, 0, false, 0);
    assert_eq!(v_inconcl.status, VerdictStatus::Inconclusive);
    assert_eq!(v_inconcl.exit_code, 125);
    assert_eq!(v_inconcl.display_badge(), "INCONCLUSIVE [STRONG]");

    // 6. Fail [Unsupported] - platform capability deficit
    let v_unsupp = VerdictEngine::evaluate_with_strength(
        &contract,
        0,
        0,
        0,
        true,
        0,
        EvidenceStrength::Unsupported,
    );
    assert_eq!(v_unsupp.status, VerdictStatus::Fail);
    assert_eq!(v_unsupp.strength, EvidenceStrength::Unsupported);
    assert_eq!(v_unsupp.exit_code, 125);
    assert_eq!(v_unsupp.display_badge(), "FAIL [UNSUPPORTED]");

    // 7. Non-zero agent exit code: security invariants satisfied, but workload failed
    let v_err_exit = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 1);
    assert_eq!(v_err_exit.status, VerdictStatus::Pass);
    assert_eq!(v_err_exit.exit_code, 1);
    assert!(v_err_exit.is_contract_satisfied());
    assert!(!v_err_exit.is_success());
}

#[test]
fn test_multi_agent_fleet_concurrency_and_cgroups_fair_share() {
    let config = FleetConfig {
        max_agents: 30, // 20-100 agents supported
        ..Default::default()
    };
    let fleet = FleetManager::new(config);

    // Allocate 25 concurrent worker scopes
    let mut workers = Vec::new();
    for i in 1..=25 {
        let name = format!("swarm-worker-{}", i);
        let scope = fleet.allocate_worker(&name).expect("must allocate worker");
        assert_eq!(scope.worker_id, format!("agent-{:02}", i));
        assert_eq!(scope.cpu_weight, DEFAULT_CPU_WEIGHT);
        assert_eq!(scope.memory_limit_bytes, DEFAULT_MEMORY_LIMIT_BYTES);
        assert_eq!(scope.pids_max, DEFAULT_PIDS_MAX);
        assert_eq!(scope.ephemeral_port, DEFAULT_BASE_PORT + (i - 1) as u16);
        assert!(scope.ipc_isolated);
        workers.push(scope);
    }

    assert_eq!(fleet.active_count(), 25);

    // Verify cross-agent isolation invariants for pairs
    for i in 0..workers.len() - 1 {
        let a = &workers[i];
        let b = &workers[i + 1];
        fleet
            .verify_isolation(&a.worker_id, &b.worker_id)
            .expect("isolation invariants must hold between all worker pairs");
    }

    // Release workers 5 through 10
    for i in 5..=10 {
        let wid = format!("agent-{:02}", i);
        fleet.release_worker(&wid).expect("must release worker");
    }
    assert_eq!(fleet.active_count(), 19);

    // Newly allocated worker takes the lowest recycled slot (agent-05)
    let reallocated = fleet.allocate_worker("recycled-agent").expect("reallocate");
    assert_eq!(reallocated.worker_id, "agent-05");
    assert_eq!(reallocated.ephemeral_port, DEFAULT_BASE_PORT + 4);
}

#[test]
fn test_process_tree_extinction_theorem_cases() {
    // 1. Linux Tier 1: Proven extinction (survivors = 0, elapsed <= 500ms)
    let linux_proof =
        ExtinctionVerifier::verify(PlatformExtinctionTier::LinuxTier1Proven, 0, 0, 250)
            .expect("Linux extinction must succeed");
    assert_eq!(linux_proof.surviving_processes, 0);
    assert_eq!(linux_proof.surviving_resources, 0);
    assert!(linux_proof.mathematically_proven);

    // 2. Windows Tier 3: Proven extinction via Job Object
    let win_proof =
        ExtinctionVerifier::verify(PlatformExtinctionTier::WindowsTier3Proven, 0, 0, 300)
            .expect("Windows extinction must succeed");
    assert!(win_proof.mathematically_proven);

    // 3. macOS Tier 2: Best-effort (unverified against double-fork)
    let mac_proof =
        ExtinctionVerifier::verify(PlatformExtinctionTier::MacOsTier2BestEffort, 0, 0, 150)
            .expect("macOS best effort succeeds");
    assert!(
        !mac_proof.mathematically_proven,
        "macOS is non-authoritative"
    );

    // 4. Survivor breach triggers Exit 125 fail-closed
    let survivor_breach =
        ExtinctionVerifier::verify(PlatformExtinctionTier::LinuxTier1Proven, 1, 0, 100)
            .unwrap_err();
    assert_eq!(survivor_breach.exit_code, FAIL_CLOSED_EXTINCTION_EXIT_CODE);
    assert_eq!(survivor_breach.exit_code, 125);
    assert!(survivor_breach.reason.contains("Lifecycle breach"));

    // 5. Leaked resources trigger Exit 125
    let resource_breach =
        ExtinctionVerifier::verify(PlatformExtinctionTier::LinuxTier1Proven, 0, 2, 100)
            .unwrap_err();
    assert_eq!(resource_breach.exit_code, 125);
    assert!(resource_breach.reason.contains("Resource breach"));

    // 6. Deadline exceeded (> 500ms) triggers Exit 125
    let timeout_breach = ExtinctionVerifier::verify(
        PlatformExtinctionTier::LinuxTier1Proven,
        0,
        0,
        MAX_EXTINCTION_DEADLINE_MS + 1,
    )
    .unwrap_err();
    assert_eq!(timeout_breach.exit_code, 125);
    assert!(timeout_breach
        .reason
        .contains("Extinction deadline exceeded"));
}

#[test]
fn test_enterprise_policy_synchronization_and_drift_detection() {
    let mut sync = EnterprisePolicySync::new();

    let contract_claude = create_sealed_contract("claude");
    let contract_codex = create_sealed_contract("codex");

    sync.register_contract(contract_claude.clone())
        .expect("register claude");
    sync.register_contract(contract_codex.clone())
        .expect("register codex");

    assert_eq!(sync.count(), 2);

    // Verification of valid worker contracts
    assert!(sync.verify_worker_contract(&contract_claude).is_ok());
    assert!(sync.verify_worker_contract(&contract_codex).is_ok());

    // Policy drift rejection: modified contract with identical name
    let mut unsealed = contract_claude.unsealed();
    unsealed.network.mode = NetworkMode::Direct;
    let tampered = unsealed.seal().unwrap();

    let drift_err = sync.verify_worker_contract(&tampered).unwrap_err();
    assert_eq!(drift_err.exit_code(), 125);
    assert!(matches!(drift_err, PolicySyncError::PolicyDrift { .. }));

    // Unregistered agent rejection
    let unregistered = create_sealed_contract("unregistered-rogue-agent");
    let unreg_err = sync.verify_worker_contract(&unregistered).unwrap_err();
    assert_eq!(unreg_err.exit_code(), 125);
    assert!(matches!(unreg_err, PolicySyncError::UnregisteredPolicy(_)));

    // Export sync manifest
    let manifest = sync.export_manifest().expect("manifest export");
    assert_eq!(manifest.policies.len(), 2);
    assert!(manifest.policies.contains_key("claude"));
    assert!(manifest.policies.contains_key("codex"));

    // Manifest verification succeeds for registered contracts
    assert!(manifest.verify_contract(&contract_claude).is_ok());
    assert!(manifest.verify_contract(&contract_codex).is_ok());

    // Manifest rejects unregistered agent
    assert!(matches!(
        manifest.verify_contract(&unregistered).unwrap_err(),
        PolicySyncError::UnregisteredPolicy(_)
    ));

    // Manifest rejects drifted contract
    assert!(matches!(
        manifest.verify_contract(&tampered).unwrap_err(),
        PolicySyncError::PolicyDrift { .. }
    ));

    // Manifest with invalid schema version rejects with InvalidManifest
    let mut invalid_manifest = manifest.clone();
    invalid_manifest.schema_version = 99;
    assert!(matches!(
        invalid_manifest
            .verify_contract(&contract_claude)
            .unwrap_err(),
        PolicySyncError::InvalidManifest(_)
    ));

    // Registering conflicting contract for same agent name fails (immutability guarantee)
    let re_reg_err = sync.register_contract(tampered).unwrap_err();
    assert_eq!(re_reg_err.exit_code(), 125);
    assert!(matches!(re_reg_err, PolicySyncError::PolicyDrift { .. }));
}
