//! Integration tests for Phase 2: Tri-Plane Policy IR & Canonical Security Contract.

use vetto::policy_ir::{
    compile as legacy_compile, validate as legacy_validate, CompilerError, ExecutionState,
    ExecutionStateMachine, NetworkMode, PolicyCompiler, RequestedPolicy, SecurityLevel,
    StateTransitionError,
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
    let res = PolicyCompiler::compile(
        "aider",
        &ws,
        None,
        std::slice::from_ref(&ws),
        &[env_target],
    );

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
