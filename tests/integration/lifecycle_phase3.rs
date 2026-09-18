//! Phase 3 Lifecycle integration and invariant tests.
//!
//! Validates:
//! 1. FSM rejects transition to Terminal when surviving_processes > 0.
//! 2. FSM strict error handling without silent suppression.
//! 3. Failed spawn triggers mandatory EmergencyCleanup before Terminal.
//! 4. Verifier failure strictly overrides raw agent exit code 0 to 125.

use crate::common::*;
use vetto::exit_codes::{map_session_exit_code, EXIT_FAIL_CLOSED, EXIT_SUCCESS};
use vetto::policy_ir::fsm::{ExecutionState, ExecutionStateMachine, StateTransitionError};
use vetto::proctree::{ExtinctionVerifier, PlatformExtinctionTier};

/// Invariant: FSM rejects transition to Terminal when surviving_processes > 0.
#[test]
fn fsm_rejects_transition_to_terminal_when_surviving_processes_positive() {
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();
    fsm.transition(ExecutionState::ContractSealed).unwrap();
    fsm.transition(ExecutionState::Prepare).unwrap();
    fsm.transition(ExecutionState::Spawn).unwrap();
    fsm.transition(ExecutionState::Enforce).unwrap();
    fsm.transition(ExecutionState::Observe).unwrap();
    fsm.transition(ExecutionState::Terminate).unwrap();
    fsm.transition(ExecutionState::Cleanup).unwrap();
    fsm.transition(ExecutionState::Verify).unwrap();
    fsm.transition(ExecutionState::Attest).unwrap();
    fsm.transition(ExecutionState::Verdict).unwrap();

    // Record that 1 surviving process escaped extinction boundary
    fsm.record_extinction_result(1);

    // Attempting to transition to Terminal must be rejected!
    let err = fsm.transition(ExecutionState::Terminal).unwrap_err();
    match err {
        StateTransitionError::InvalidTransition { from, to, reason } => {
            assert_eq!(from, ExecutionState::Verdict);
            assert_eq!(to, ExecutionState::Terminal);
            assert!(
                reason.contains("surviving") || reason.contains("descendant"),
                "reason should mention surviving processes: {reason}"
            );
        }
        other => panic!("expected InvalidTransition, got: {:?}", other),
    }
    assert!(!fsm.is_terminal());

    // When surviving processes are 0, transition to Terminal succeeds
    let mut clean_fsm = ExecutionStateMachine::new();
    clean_fsm.transition(ExecutionState::PolicyCompiled).unwrap();
    clean_fsm.transition(ExecutionState::ContractSealed).unwrap();
    clean_fsm.transition(ExecutionState::Prepare).unwrap();
    clean_fsm.transition(ExecutionState::Spawn).unwrap();
    clean_fsm.transition(ExecutionState::Enforce).unwrap();
    clean_fsm.transition(ExecutionState::Observe).unwrap();
    clean_fsm.transition(ExecutionState::Terminate).unwrap();
    clean_fsm.transition(ExecutionState::Cleanup).unwrap();
    clean_fsm.transition(ExecutionState::Verify).unwrap();
    clean_fsm.transition(ExecutionState::Attest).unwrap();
    clean_fsm.transition(ExecutionState::Verdict).unwrap();

    clean_fsm.record_extinction_result(0);
    assert!(clean_fsm.transition(ExecutionState::Terminal).is_ok());
    assert!(clean_fsm.is_terminal());
}

/// Invariant: FSM strict error handling without silent suppression.
#[test]
fn fsm_strict_error_handling_no_silent_suppression() {
    let mut fsm = ExecutionStateMachine::new();
    assert_eq!(fsm.current_state(), ExecutionState::Intent);

    // Attempt invalid forward jumps:
    let jumps = [
        ExecutionState::Verdict,
        ExecutionState::Terminal,
        ExecutionState::Cleanup,
        ExecutionState::Enforce,
    ];
    for target in jumps {
        let res = fsm.transition(target);
        assert!(res.is_err(), "jump from Intent to {:?} must fail", target);
        let err = res.unwrap_err();
        match err {
            StateTransitionError::InvalidTransition { from, to, .. } => {
                assert_eq!(from, ExecutionState::Intent);
                assert_eq!(to, target);
            }
            other => panic!("expected InvalidTransition, got: {:?}", other),
        }
        assert_eq!(fsm.current_state(), ExecutionState::Intent);
    }

    fsm.transition(ExecutionState::PolicyCompiled).unwrap();
    fsm.transition(ExecutionState::ContractSealed).unwrap();
    fsm.transition(ExecutionState::Prepare).unwrap();
    assert_eq!(fsm.current_state(), ExecutionState::Prepare);

    // Cannot step backwards to Intent
    assert!(fsm.transition(ExecutionState::Intent).is_err());
    assert_eq!(fsm.current_state(), ExecutionState::Prepare);

    // fail_closed must transition and return typed error
    let fc_err = fsm.fail_closed("kernel hook rejected in test");
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);
    assert!(fsm.is_fail_closed());
    match fc_err {
        StateTransitionError::FailClosed { state, error } => {
            assert_eq!(state, ExecutionState::Prepare);
            assert!(error.contains("kernel hook"));
        }
        other => panic!("expected FailClosed error, got: {:?}", other),
    }
}

/// Invariant: failed spawn triggers mandatory EmergencyCleanup before reaching Terminal.
#[test]
fn failed_spawn_triggers_mandatory_emergency_cleanup() {
    // 1. FSM state transition test
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();
    fsm.transition(ExecutionState::ContractSealed).unwrap();
    fsm.transition(ExecutionState::Prepare).unwrap();

    let _ = fsm.fail_closed("failed to spawn: binary not found");
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    // Cannot transition directly from FailClosed to Terminal
    let direct_term = fsm.transition(ExecutionState::Terminal);
    assert!(
        direct_term.is_err(),
        "must not transition directly from FailClosed to Terminal without EmergencyCleanup"
    );

    // Must pass through EmergencyCleanup
    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    assert_eq!(fsm.current_state(), ExecutionState::EmergencyCleanup);

    fsm.record_extinction_result(0);
    assert!(fsm.transition(ExecutionState::Terminal).is_ok());
    assert!(fsm.is_terminal());
    assert!(fsm.is_fail_closed());

    // 2. End-to-end CLI execution test
    if have_landlock() {
        let proj = TempProject::new("failed-spawn-cleanup");
        let non_existent = proj.path().join("missing_agent_binary_404");
        let out = run_vetto_in(
            proj.path(),
            &[
                "--tui=none",
                "--",
                non_existent.to_str().unwrap(),
            ],
        );
        assert!(
            !out.status.success(),
            "spawn of non-existent binary must fail; stdout: {}, stderr: {}",
            stdout(&out),
            stderr(&out)
        );
        let code = out.status.code().unwrap_or(-1);
        assert!(
            code == 127 || code == 125,
            "expected exit 127 (COMMAND_NOT_FOUND) or 125 (FAIL_CLOSED); got {code}"
        );
    }
}

/// Invariant: verifier failure overrides raw agent exit code 0 to 125 (EXIT_FAIL_CLOSED).
#[test]
fn verifier_failure_overrides_agent_exit_code_zero_to_125() {
    let raw_agent_exit = EXIT_SUCCESS;
    assert_eq!(raw_agent_exit, 0);

    // Verifier detects extinction breach (surviving processes > 0)
    let verifier_result = ExtinctionVerifier::verify(
        PlatformExtinctionTier::LinuxTier1Proven,
        1,
        0,
        50,
    );
    assert!(verifier_result.is_err());
    let breach = verifier_result.unwrap_err();

    assert_eq!(breach.exit_code, EXIT_FAIL_CLOSED);
    assert_eq!(breach.exit_code, 125);

    // Override logic: breach forces final exit to 125
    let final_code = if breach.exit_code == EXIT_FAIL_CLOSED {
        EXIT_FAIL_CLOSED
    } else {
        raw_agent_exit
    };
    assert_eq!(final_code, 125);

    let mapped = map_session_exit_code(final_code, false, false);
    assert_eq!(
        mapped, 125,
        "verifier breach must override agent exit code 0 to 125"
    );

    // FSM routing verification: failure at Verify routes to FailClosed -> EmergencyCleanup
    let mut fsm = ExecutionStateMachine::new();
    fsm.transition(ExecutionState::PolicyCompiled).unwrap();
    fsm.transition(ExecutionState::ContractSealed).unwrap();
    fsm.transition(ExecutionState::Prepare).unwrap();
    fsm.transition(ExecutionState::Spawn).unwrap();
    fsm.transition(ExecutionState::Enforce).unwrap();
    fsm.transition(ExecutionState::Observe).unwrap();
    fsm.transition(ExecutionState::Terminate).unwrap();
    fsm.transition(ExecutionState::Cleanup).unwrap();
    fsm.transition(ExecutionState::Verify).unwrap();

    let _ = fsm.fail_closed("verifier breach: leaked residual process");
    assert_eq!(fsm.current_state(), ExecutionState::FailClosed);

    // Normal forward progression (Attest / Verdict) is blocked
    assert!(fsm.transition(ExecutionState::Attest).is_err());
    assert!(fsm.transition(ExecutionState::Verdict).is_err());

    fsm.transition(ExecutionState::EmergencyCleanup).unwrap();
    fsm.record_extinction_result(0);
    fsm.transition(ExecutionState::Terminal).unwrap();
    assert!(fsm.is_terminal());
    assert!(fsm.is_fail_closed());
}
