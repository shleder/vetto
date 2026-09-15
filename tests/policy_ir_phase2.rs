//! Integration tests for Phase 2: Tri-Plane Policy IR & Canonical Security Contract.

use vetto::policy_ir::{
    compile as legacy_compile, validate as legacy_validate, CompilerError, ExecutionState,
    ExecutionStateMachine, NetworkMode, PolicyCompiler, RequestedPolicy, SecurityContract,
    SecurityLevel, StateTransitionError,
};

#[test]
fn test_legacy_policy_ir_compatibility() {
    let req = RequestedPolicy {
        level: SecurityLevel::Standard,
        allow_read: vec!["/workspace".to_string(), "/tmp".to_string()],
        allow_write: vec!["/workspace/target".to_string()],
    };
    let compiled = legacy_compile(&req).expect("legacy compile should succeed");
    assert_eq!(compiled.level, SecurityLevel::Standard);
    assert!(legacy_validate(&compiled).is_ok());
}

#[test]
fn test_policy_compiler_contract_sealing() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_test_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let sub_write = ws.join("src/output.rs");
    let contract = PolicyCompiler::compile(
        "claude",
        &ws,
        Some(NetworkMode::Allowlist),
        std::slice::from_ref(&ws),
        &[sub_write],
    )
    .expect("compile contract");

    assert_eq!(contract.contract_version, 1);
    assert_eq!(contract.agent_identity.agent_name, "claude");
    assert_eq!(contract.network.mode, NetworkMode::Allowlist);
    assert!(!contract.contract_digest_blake3.is_empty());
    assert!(contract.verify_digest(), "digest verification must succeed");

    // Anti-tamper verification
    let mut tampered = contract.clone();
    tampered.resources.max_pids = 99999;
    assert!(
        !tampered.verify_digest(),
        "tampered contract must fail digest verification"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_ancestor_containment_and_escape() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_escape_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // Write path that escapes the workspace
    let escape_target = temp_dir.join("escaped_file.txt");
    let res = PolicyCompiler::compile(
        "codex",
        &ws,
        None,
        std::slice::from_ref(&ws),
        &[escape_target],
    );

    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "escaping write target must fail with ConflictingPermissions"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_mask_path_collision() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_mask_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    // Attempting to target .env inside workspace
    let env_target = ws.join(".env");
    let res = PolicyCompiler::compile("aider", &ws, None, std::slice::from_ref(&ws), &[env_target]);

    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "write target colliding with .env mask must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_execution_state_machine_transitions() {
    let mut fsm = ExecutionStateMachine::new();
    assert_eq!(fsm.current_state(), ExecutionState::Intent);

    let expected_steps = [
        ExecutionState::PolicyCompiled,
        ExecutionState::ContractSealed,
        ExecutionState::Prepare,
        ExecutionState::Spawn,
        ExecutionState::Enforce,
        ExecutionState::Observe,
        ExecutionState::Terminate,
        ExecutionState::Cleanup,
        ExecutionState::Verify,
        ExecutionState::Attest,
        ExecutionState::Verdict,
        ExecutionState::Terminal,
    ];

    for step in expected_steps {
        fsm.transition(step).expect("valid transition");
        assert_eq!(fsm.current_state(), step);
    }
    assert!(fsm.is_terminal());

    // Transitioning from Terminal should fail
    let err = fsm.transition(ExecutionState::Intent).unwrap_err();
    assert!(matches!(
        err,
        StateTransitionError::InvalidTransition { .. }
    ));
}

#[test]
fn test_execution_state_machine_fail_closed() {
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();

    let err = fsm.fail_closed("Simulated kernel LSM failure");
    assert!(matches!(err, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);
    assert!(fsm.is_fail_closed());

    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    fsm.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm.is_terminal());
}

#[test]
fn test_contract_serde_roundtrip() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_serde_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let contract = PolicyCompiler::compile("claude", &ws, Some(NetworkMode::Allowlist), &[], &[])
        .expect("compile contract");

    // Serialization skips contract_digest_blake3 to prevent circularity
    let json = serde_json::to_string(&contract).expect("serialize contract");
    assert!(!json.contains("contract_digest_blake3"));

    // Deserialization must succeed with #[serde(default)]
    let deserialized: SecurityContract = serde_json::from_str(&json).expect("deserialize contract");
    assert_eq!(deserialized.agent_identity.agent_name, "claude");
    assert_eq!(deserialized.contract_digest_blake3, "");

    // When resealed, digest is valid
    let resealed = deserialized.unsealed().seal().expect("reseal");
    assert!(resealed.verify_digest());

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_relative_read_paths() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_relread_{}", std::process::id()));
    std::fs::create_dir_all(ws.join("src")).expect("create test workspace src");

    // Pass relative path "src" in raw_reads
    let contract =
        PolicyCompiler::compile("claude", &ws, None, &[std::path::PathBuf::from("src")], &[])
            .expect("compile contract with relative read path");

    let canon_src = ws.join("src").canonicalize().unwrap();
    assert!(contract.filesystem.allow_read.contains(&canon_src));
    assert!(contract.filesystem.allow_read.contains(&ws));

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_git_dir_collision() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_git_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let git_dir = ws.join(".git");
    let res = PolicyCompiler::compile("claude", &ws, None, &[], &[git_dir]);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "targeting .git directory must collide with .git/config secret mask"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_policy_compiler_directory_traversal_rejection() {
    let temp_dir = std::env::temp_dir()
        .canonicalize()
        .expect("canonicalize temp dir");
    let ws = temp_dir.join(format!("vetto_p2_trav_{}", std::process::id()));
    std::fs::create_dir_all(&ws).expect("create test workspace");

    let traversal_write = ws.join("nonexistent/sub/../leak");
    let res = PolicyCompiler::compile("claude", &ws, None, &[], &[traversal_write]);
    assert!(
        matches!(res, Err(CompilerError::ConflictingPermissions(_))),
        "directory traversal in non-existent write target must be rejected"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_execution_state_machine_fail_closed_idempotent() {
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();

    let err1 = fsm.fail_closed("first error");
    assert!(matches!(err1, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    // Re-entrant fail_closed must succeed idempotently
    let err2 = fsm.fail_closed("second error");
    assert!(matches!(err2, StateTransitionError::FailClosed { .. }));
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    // EmergencyCleanup error can re-enter FailClosed or stay
    fsm.transition(ExecutionState::FailClosed).unwrap();
    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    fsm.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm.is_terminal());
}
