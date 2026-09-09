//! Process-tree cleanup state machine (P3 slice): GRACEFUL → ESCALATE → VERIFY.
//!
//! This module only *plans* the kill sequence and models phase transitions.
//! Actually signalling processes stays in the sandbox backends (destructive
//! behavior is exercised in disposable VMs, never in unit tests).

/// Cleanup phase for one process tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillPhase {
    /// Ask nicely: SIGTERM / polite shutdown, bounded by a deadline.
    Graceful,
    /// Deadline expired with survivors: SIGKILL the remainder.
    Escalate,
    /// Confirm no survivors; anything still alive is a cleanup failure.
    Verify,
}

impl KillPhase {
    pub fn label(self) -> &'static str {
        match self {
            KillPhase::Graceful => "GRACEFUL",
            KillPhase::Escalate => "ESCALATE",
            KillPhase::Verify => "VERIFY",
        }
    }
}

/// One planned step of the cleanup sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KillStep {
    pub phase: KillPhase,
    pub pid: u32,
    /// Grace period in milliseconds before the next step (0 = act now).
    pub grace_ms: u64,
}

/// Default polite window before escalation.
pub const DEFAULT_GRACE_MS: u64 = 2_000;

/// Plan the full sequence for a rooted process tree: terminate, then kill,
/// then verify. Always all three steps — skipping VERIFY hides survivors.
pub fn plan_kill(root_pid: u32, grace_ms: u64) -> Vec<KillStep> {
    vec![
        KillStep {
            phase: KillPhase::Graceful,
            pid: root_pid,
            grace_ms,
        },
        KillStep {
            phase: KillPhase::Escalate,
            pid: root_pid,
            grace_ms: 0,
        },
        KillStep {
            phase: KillPhase::Verify,
            pid: root_pid,
            grace_ms: 0,
        },
    ]
}

/// Advance the machine after a step: with survivors after GRACEFUL the only
/// legal move is ESCALATE; after ESCALATE always VERIFY; VERIFY with
/// survivors is a terminal cleanup failure (`None` = no further step helps).
pub fn advance(phase: KillPhase, survivors: bool) -> Option<KillPhase> {
    match (phase, survivors) {
        (KillPhase::Graceful, true) => Some(KillPhase::Escalate),
        (KillPhase::Graceful, false) => Some(KillPhase::Verify),
        (KillPhase::Escalate, _) => Some(KillPhase::Verify),
        (KillPhase::Verify, false) => None,
        (KillPhase::Verify, true) => None,
    }
}

/// True only when VERIFY observed zero survivors — the single success state.
pub fn cleanup_ok(phase: KillPhase, survivors: bool) -> bool {
    phase == KillPhase::Verify && !survivors
}

#[cfg(test)]
mod proctree_tests {
    use super::*;

    #[test]
    fn plan_always_has_all_three_steps_in_order() {
        let plan = plan_kill(4242, DEFAULT_GRACE_MS);
        let phases: Vec<KillPhase> = plan.iter().map(|s| s.phase).collect();
        assert_eq!(
            phases,
            vec![KillPhase::Graceful, KillPhase::Escalate, KillPhase::Verify]
        );
        assert!(plan.iter().all(|s| s.pid == 4242));
        assert_eq!(plan[0].grace_ms, DEFAULT_GRACE_MS);
    }

    #[test]
    fn graceful_with_survivors_must_escalate() {
        assert_eq!(
            advance(KillPhase::Graceful, true),
            Some(KillPhase::Escalate)
        );
        assert_eq!(advance(KillPhase::Graceful, false), Some(KillPhase::Verify));
    }

    #[test]
    fn verify_is_terminal_and_honest() {
        assert_eq!(advance(KillPhase::Escalate, true), Some(KillPhase::Verify));
        assert_eq!(advance(KillPhase::Verify, true), None);
        assert_eq!(advance(KillPhase::Verify, false), None);
        assert!(cleanup_ok(KillPhase::Verify, false));
        assert!(!cleanup_ok(KillPhase::Verify, true));
        assert!(!cleanup_ok(KillPhase::Escalate, false));
    }
}
