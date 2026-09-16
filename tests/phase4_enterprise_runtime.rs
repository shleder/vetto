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

use vetto::audit::record::{
    FsMutationType, SyscallActionTaken, TierClassification, VettoAuditRecord,
};
use vetto::audit::verdict::{EvidenceStrength, VerdictEngine, VerdictStatus};
use vetto::crypto::attest::AuditLedger;
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
use vetto::policy_ir::fsm::ExecutionState;
use vetto::policy_ir::sync::{EnterprisePolicySync, PolicySyncError};
use vetto::proctree::{
    ExtinctionVerifier, PlatformExtinctionTier, FAIL_CLOSED_EXTINCTION_EXIT_CODE,
    MAX_EXTINCTION_DEADLINE_MS,
};
use vetto::sandbox::{
    is_evidence_channel_intact, mark_evidence_channel_disrupted, reset_evidence_channel,
    SupervisorEngine,
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
    tampered_envelope.payload.push(' ');
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

#[test]
fn test_section17_1_audit_records_json_schema() {
    let session_id = "550e8400-e29b-41d4-a716-446655440000";
    let contract_digest = "8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a";

    // 1. SESSION_INIT
    let init_rec = VettoAuditRecord::session_init(
        session_id,
        contract_digest,
        "linux",
        "6.8.0",
        "claude-code",
        TierClassification::Tier1Linux,
    );
    let init_json = init_rec.to_json_line().unwrap();
    assert!(init_json.contains("\"record_type\":\"SESSION_INIT\""));
    assert!(init_json.contains("\"tier\":\"TIER_1_LINUX\""));
    assert!(init_json.contains("\"platform\":\"linux\""));

    // 2. SYSCALL_DENIAL
    let denial_rec = VettoAuditRecord::syscall_denial(
        session_id,
        contract_digest,
        "openat",
        "/etc/shadow",
        "landlock",
        SyscallActionTaken::Blocked,
    );
    let denial_json = denial_rec.to_json_line().unwrap();
    assert!(denial_json.contains("\"record_type\":\"SYSCALL_DENIAL\""));
    assert!(denial_json.contains("\"action_taken\":\"BLOCKED\""));
    assert!(denial_json.contains("\"syscall_name\":\"openat\""));

    // 3. FS_MUTATION
    let fs_rec = VettoAuditRecord::fs_mutation(
        session_id,
        contract_digest,
        "src/main.rs",
        FsMutationType::Modified,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    let fs_json = fs_rec.to_json_line().unwrap();
    assert!(fs_json.contains("\"record_type\":\"FS_MUTATION\""));
    assert!(fs_json.contains("\"mutation_type\":\"MODIFIED\""));

    // 4. RESOURCE_SAMPLE
    let res_rec =
        VettoAuditRecord::resource_sample(session_id, contract_digest, 42.5, 1024 * 1024 * 64, 8);
    let res_json = res_rec.to_json_line().unwrap();
    assert!(res_json.contains("\"record_type\":\"RESOURCE_SAMPLE\""));
    assert!(res_json.contains("\"cpu_percent\":42.5"));

    // 5. TREE_EXTINCTION
    let ext_rec = VettoAuditRecord::tree_extinction(
        session_id,
        contract_digest,
        "LinuxTier1Proven",
        0,
        9,
        120,
        true,
    );
    let ext_json = ext_rec.to_json_line().unwrap();
    assert!(ext_json.contains("\"record_type\":\"TREE_EXTINCTION\""));
    assert!(ext_json.contains("\"clean\":true"));

    // 6. SESSION_VERDICT
    let contract = create_sealed_contract("claude");
    let verdict = VerdictEngine::evaluate(&contract, 0, 0, 0, true, 0);
    let verdict_rec = VettoAuditRecord::session_verdict(
        session_id,
        contract_digest,
        &verdict,
        "8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a",
    );
    let verdict_json = verdict_rec.to_json_line().unwrap();
    assert!(verdict_json.contains("\"record_type\":\"SESSION_VERDICT\""));
    assert!(verdict_json.contains("\"verdict\":\"PASS\""));
    assert!(verdict_json.contains("\"evidence_strength\":\"STRONG\""));
    assert!(verdict_json.contains("\"exit_code\":0"));
}

#[test]
fn test_contract_blake3_sealing_and_digest_verification() {
    let contract = create_sealed_contract("claude");
    assert!(!contract.contract_digest_blake3.is_empty());
    assert_eq!(contract.contract_digest_blake3.len(), 64);
    assert!(contract.verify_digest());

    // Tampering unsealed content breaks verification
    let mut tampered = contract.clone();
    tampered.network.mode = NetworkMode::Direct;
    assert!(!tampered.verify_digest());
}

#[test]
fn test_audit_ledger_record_and_sign() {
    use std::fs;
    let dir = std::env::temp_dir().join(format!("vetto-test-audit-{}", std::process::id()));
    let _ = fs::create_dir_all(&dir);
    let ledger_path = dir.join("vetto-audit.jsonl");

    let mut ledger = AuditLedger::new(&ledger_path).expect("open ledger");

    let rec1 = VettoAuditRecord::session_init(
        "session-1",
        "digest-1",
        "linux",
        "6.8.0",
        "claude",
        TierClassification::Tier1Linux,
    );
    let hash1 = ledger.record_audit_record(&rec1).expect("record rec1");
    assert!(!hash1.is_empty());

    let rec2 = VettoAuditRecord::fs_mutation(
        "session-1",
        "digest-1",
        "Cargo.toml",
        FsMutationType::Modified,
        "sha-cargo-toml",
    );
    let hash2 = ledger.record_audit_record(&rec2).expect("record rec2");
    assert!(!hash2.is_empty());
    assert_ne!(hash1, hash2);

    let mut csprng = OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let sig = ledger.sign_and_close(&signing_key).expect("sign ledger");
    assert_eq!(sig.len(), 128); // 64 bytes in hex

    let contents = fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(contents.contains("SESSION_INIT"));
    assert!(contents.contains("FS_MUTATION"));
    assert!(contents.contains(&sig));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn test_inv37_netlink_disruption_forces_inconclusive_verdict() {
    let contract = create_sealed_contract("claude-worker");

    reset_evidence_channel();
    assert!(is_evidence_channel_intact());

    // Clean execution with intact evidence channel yields PASS [STRONG]
    let clean_verdict =
        VerdictEngine::evaluate(&contract, 0, 0, 0, is_evidence_channel_intact(), 0);
    assert_eq!(clean_verdict.status, VerdictStatus::Pass);
    assert_eq!(clean_verdict.strength, EvidenceStrength::Strong);
    assert_eq!(clean_verdict.exit_code, 0);
    assert!(clean_verdict.is_success());
    assert_eq!(
        clean_verdict.recommended_action(),
        "Commit CoW changes to host workspace."
    );

    // Disruption trigger (INV-37: Netlink buffer overflow / packet drop)
    mark_evidence_channel_disrupted();
    assert!(!is_evidence_channel_intact());

    let disrupted_verdict =
        VerdictEngine::evaluate(&contract, 0, 0, 0, is_evidence_channel_intact(), 0);
    assert_eq!(disrupted_verdict.status, VerdictStatus::Inconclusive);
    assert_eq!(disrupted_verdict.strength, EvidenceStrength::Strong);
    assert_eq!(disrupted_verdict.exit_code, 125);
    assert_eq!(disrupted_verdict.display_badge(), "INCONCLUSIVE [STRONG]");
    assert_eq!(
        disrupted_verdict.recommended_action(),
        "Wipe CoW layer; audit ledger inconclusive."
    );
    assert!(!disrupted_verdict.is_success());
    assert!(!disrupted_verdict.is_contract_satisfied());
    assert!(disrupted_verdict
        .reason
        .contains("Evidence capture channel dropped events"));

    // CoW policy decisions
    assert!(!SupervisorEngine::should_commit_cow(&disrupted_verdict));
    assert!(SupervisorEngine::should_wipe_cow(&disrupted_verdict));

    // Reset channel state after test
    reset_evidence_channel();
    assert!(is_evidence_channel_intact());
}

#[test]
fn test_triplane_supervisor_engine_full_lifecycle_and_invariants() {
    let contract = create_sealed_contract("claude-supervisor");

    // 1. Initial state validation
    let mut supervisor = SupervisorEngine::new(contract.clone()).expect("supervisor init succeeds");
    assert_eq!(supervisor.current_state(), ExecutionState::ContractSealed);
    assert_eq!(supervisor.contract().contract_id, contract.contract_id);

    // 2. Tampered contract rejection
    let mut tampered = contract.clone();
    tampered.resources.max_pids = 99999;
    assert!(SupervisorEngine::new(tampered).is_err());

    // 3. Happy-path lifecycle
    supervisor.prepare().expect("prepare succeeds");
    assert_eq!(supervisor.current_state(), ExecutionState::Prepare);

    supervisor.spawn_guard().expect("spawn guard succeeds");
    assert_eq!(supervisor.current_state(), ExecutionState::Observe);

    supervisor.terminate().expect("terminate succeeds");
    assert_eq!(supervisor.current_state(), ExecutionState::Terminate);

    let proof = supervisor
        .cleanup_and_verify(PlatformExtinctionTier::LinuxTier1Proven, 0, 0, 120)
        .expect("cleanup and extinction verification succeeds");
    assert_eq!(proof.surviving_processes, 0);
    assert_eq!(proof.surviving_resources, 0);
    assert!(proof.mathematically_proven);
    assert_eq!(supervisor.current_state(), ExecutionState::Verify);

    reset_evidence_channel();
    let verdict = supervisor
        .evaluate_verdict(0, 0, 0, 0)
        .expect("evaluate verdict succeeds");
    assert_eq!(verdict.status, VerdictStatus::Pass);
    assert_eq!(verdict.strength, EvidenceStrength::Strong);
    assert_eq!(verdict.exit_code, 0);
    assert!(verdict.is_success());
    assert_eq!(supervisor.current_state(), ExecutionState::Terminal);
    assert!(SupervisorEngine::should_commit_cow(&verdict));
    assert!(!SupervisorEngine::should_wipe_cow(&verdict));

    // 4. Audit ledger recording of the verdict
    let dir = std::env::temp_dir().join(format!("vetto-test-sup-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let ledger_path = dir.join("vetto-audit.jsonl");
    let mut ledger = AuditLedger::new(&ledger_path).expect("open audit ledger");
    let root_digest = "8f434346648f6b96df89dda901c5176b10f60047a0641b98b95886ac8f6eec6a";
    let rec_hash = supervisor
        .record_verdict_to_ledger(&mut ledger, &verdict, root_digest)
        .expect("record verdict to ledger");
    assert!(!rec_hash.is_empty());
    let ledger_content = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(ledger_content.contains("SESSION_VERDICT"));
    assert!(ledger_content.contains("\"verdict\":\"PASS\""));
    assert!(ledger_content.contains("\"exit_code\":0"));
    let _ = std::fs::remove_dir_all(&dir);

    // 5. Fail-closed path: zombie processes trigger Exit 125
    let mut sup2 = SupervisorEngine::new(contract.clone()).expect("sup2 init");
    sup2.prepare().unwrap();
    sup2.spawn_guard().unwrap();
    sup2.terminate().unwrap();
    let breach = sup2
        .cleanup_and_verify(PlatformExtinctionTier::LinuxTier1Proven, 2, 0, 100)
        .unwrap_err();
    assert_eq!(breach.exit_code, 125);
    assert_eq!(sup2.current_state(), ExecutionState::FailClosed);

    // 6. Fail-closed path: INV-37 evidence channel disruption triggers INCONCLUSIVE
    let mut sup3 = SupervisorEngine::new(contract).expect("sup3 init");
    sup3.prepare().unwrap();
    sup3.spawn_guard().unwrap();
    sup3.terminate().unwrap();
    sup3.cleanup_and_verify(PlatformExtinctionTier::LinuxTier1Proven, 0, 0, 100)
        .unwrap();
    mark_evidence_channel_disrupted();
    let inconcl_verdict = sup3
        .evaluate_verdict(0, 0, 0, 0)
        .expect("verdict evaluated");
    assert_eq!(inconcl_verdict.status, VerdictStatus::Inconclusive);
    assert_eq!(inconcl_verdict.exit_code, 125);
    assert_eq!(sup3.current_state(), ExecutionState::Terminal);
    assert!(!SupervisorEngine::should_commit_cow(&inconcl_verdict));
    assert!(SupervisorEngine::should_wipe_cow(&inconcl_verdict));

    reset_evidence_channel();
}
