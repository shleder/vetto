//! Authoritative Implementation: Execution State Machine Formalization (Phase 2 / NEXT_GEN §10).
//!
//! Enforces deterministic, 12-state execution lifecycle with strict transition guards
//! and fail-closed error transitions per Transition Truth Table 10.2.

use serde::{Deserialize, Serialize};

/// 12 Formal Execution States plus FailClosed, EmergencyCleanup, and Terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionState {
    /// Initial intent collection from agent profile / CLI
    Intent,
    /// Policy parsed, normalized, and validated
    PolicyCompiled,
    /// Canonical contract sealed with BLAKE3/SHA-256 digest
    ContractSealed,
    /// Host resources (cgroups, pipes, namespaces) allocated
    Prepare,
    /// Process created in suspended/pre-exec state
    Spawn,
    /// Self-restriction (Landlock) and synchronization handshake completed
    Enforce,
    /// Process running; supervisor active with non-blocking async drain
    Observe,
    /// Normal exit, timeout reached, or tripwire triggered
    Terminate,
    /// Process tree extinction and cgroup/JobObject cleanup
    Cleanup,
    /// Independent verification of 0 surviving descendants & audit traces
    Verify,
    /// Merkle DAG generated and audit ledger cryptographically signed
    Attest,
    /// Two-dimensional verdict matrix evaluated
    Verdict,
    /// Fail-closed containment state upon any policy/kernel failure (Exit 125)
    FailClosed,
    /// Emergency cleanup of leaked host artifacts and scopes
    EmergencyCleanup,
    /// Execution complete; final exit code yielded
    Terminal,
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum StateTransitionError {
    #[error("Invalid state transition from {from:?} to {to:?}: {reason}")]
    InvalidTransition {
        from: ExecutionState,
        to: ExecutionState,
        reason: &'static str,
    },
    #[error("Execution failed closed in state {state:?}: {error} (Exit 125)")]
    FailClosed {
        state: ExecutionState,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct ExecutionStateMachine {
    current_state: ExecutionState,
    history: Vec<(ExecutionState, std::time::Instant)>,
}

impl Default for ExecutionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionStateMachine {
    pub fn new() -> Self {
        Self {
            current_state: ExecutionState::Intent,
            history: vec![(ExecutionState::Intent, std::time::Instant::now())],
        }
    }

    pub fn current_state(&self) -> ExecutionState {
        self.current_state
    }

    pub fn history(&self) -> &[(ExecutionState, std::time::Instant)] {
        &self.history
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.current_state, ExecutionState::Terminal)
    }

    pub fn is_fail_closed(&self) -> bool {
        matches!(
            self.current_state,
            ExecutionState::FailClosed | ExecutionState::EmergencyCleanup
        )
    }

    pub fn transition(&mut self, next: ExecutionState) -> Result<(), StateTransitionError> {
        let valid = match (self.current_state, next) {
            // Forward happy-path pipeline (Table 10.2)
            (ExecutionState::Intent, ExecutionState::PolicyCompiled) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::ContractSealed) => true,
            (ExecutionState::ContractSealed, ExecutionState::Prepare) => true,
            (ExecutionState::Prepare, ExecutionState::Spawn) => true,
            (ExecutionState::Spawn, ExecutionState::Enforce) => true,
            (ExecutionState::Enforce, ExecutionState::Observe) => true,
            (ExecutionState::Observe, ExecutionState::Terminate) => true,
            (ExecutionState::Terminate, ExecutionState::Cleanup) => true,
            (ExecutionState::Cleanup, ExecutionState::Verify) => true,
            (ExecutionState::Verify, ExecutionState::Attest) => true,
            (ExecutionState::Attest, ExecutionState::Verdict) => true,
            (ExecutionState::Verdict, ExecutionState::Terminal) => true,

            // Fail-closed transitions from any active state upon anomaly / violation
            (ExecutionState::Intent, ExecutionState::FailClosed) => true,
            (ExecutionState::PolicyCompiled, ExecutionState::FailClosed) => true,
            (ExecutionState::ContractSealed, ExecutionState::FailClosed) => true,
            (ExecutionState::Prepare, ExecutionState::FailClosed) => true,
            (ExecutionState::Spawn, ExecutionState::FailClosed) => true,
            (ExecutionState::Enforce, ExecutionState::FailClosed) => true,
            (ExecutionState::Observe, ExecutionState::FailClosed) => true,
            (ExecutionState::Terminate, ExecutionState::FailClosed) => true,
            (ExecutionState::Cleanup, ExecutionState::FailClosed) => true,
            (ExecutionState::Verify, ExecutionState::FailClosed) => true,
            (ExecutionState::Attest, ExecutionState::FailClosed) => true,
            (ExecutionState::Verdict, ExecutionState::FailClosed) => true,

            // Fail-closed recovery & terminal paths
            (ExecutionState::FailClosed, ExecutionState::FailClosed) => true,
            (ExecutionState::FailClosed, ExecutionState::EmergencyCleanup) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::EmergencyCleanup) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::FailClosed) => true,
            (ExecutionState::EmergencyCleanup, ExecutionState::Terminal) => true,

            _ => false,
        };

        if !valid {
            return Err(StateTransitionError::InvalidTransition {
                from: self.current_state,
                to: next,
                reason: "transition disallowed by execution state machine transition table",
            });
        }

        self.current_state = next;
        self.history.push((next, std::time::Instant::now()));
        Ok(())
    }

    /// Abort execution fail-closed, moving to FailClosed state.
    pub fn fail_closed(&mut self, error: impl Into<String>) -> StateTransitionError {
        let err_str = error.into();
        let prev_state = self.current_state;
        let _ = self.transition(ExecutionState::FailClosed);
        StateTransitionError::FailClosed {
            state: prev_state,
            error: err_str,
        }
    }
}

#[cfg(test)]
mod fsm_tests {
    use super::*;

    #[test]
    fn complete_happy_path_lifecycle() {
        let mut fsm = ExecutionStateMachine::new();
        assert_eq!(fsm.current_state(), ExecutionState::Intent);

        let sequence = [
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

        for next in sequence {
            assert!(fsm.transition(next).is_ok());
            assert_eq!(fsm.current_state(), next);
        }

        assert!(fsm.is_terminal());
        assert_eq!(fsm.history().len(), 13);
    }

    #[test]
    fn reject_skipping_lifecycle_states() {
        let mut fsm = ExecutionStateMachine::new();
        // Cannot jump directly from Intent to Spawn
        let err = fsm.transition(ExecutionState::Spawn).unwrap_err();
        assert!(matches!(
            err,
            StateTransitionError::InvalidTransition { .. }
        ));
        assert_eq!(fsm.current_state(), ExecutionState::Intent);
    }

    #[test]
    fn fail_closed_and_emergency_cleanup() {
        let mut fsm = ExecutionStateMachine::new();
        fsm.transition(ExecutionState::PolicyCompiled).unwrap();
        fsm.transition(ExecutionState::ContractSealed).unwrap();
        fsm.transition(ExecutionState::Prepare).unwrap();

        // Anomaly encountered during spawn
        let err = fsm.fail_closed("LSM hook rejected in kernel");
        assert!(matches!(err, StateTransitionError::FailClosed { .. }));
        assert_eq!(fsm.current_state(), ExecutionState::FailClosed);
        assert!(fsm.is_fail_closed());

        // Emergency cleanup transition
        assert!(fsm.transition(ExecutionState::EmergencyCleanup).is_ok());
        assert!(fsm.transition(ExecutionState::Terminal).is_ok());
        assert!(fsm.is_terminal());
    }
}
