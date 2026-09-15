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


/// Hard upper bound for total process tree and resource extinction (§12.1).
pub const MAX_EXTINCTION_DEADLINE_MS: u64 = 500;

/// Exit code emitted upon any process tree extinction or cleanup breach (INV-27).
pub const FAIL_CLOSED_EXTINCTION_EXIT_CODE: i32 = 125;

/// Platform tier classification for the Process Tree Extinction Theorem (§12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformExtinctionTier {
    /// Linux cgroups v2 (`cgroup.kill` + freeze): mathematically proven extinction.
    LinuxTier1Proven,
    /// Windows Win32 Job Objects (`TerminateJobObject` without breakaway): NT kernel enforced.
    WindowsTier3Proven,
    /// macOS Multi-Phase Sweep (SIGTERM -> SIGKILL -> session nonce): best-effort, unverified.
    MacOsTier2BestEffort,
}

impl PlatformExtinctionTier {
    pub fn is_authoritative(self) -> bool {
        matches!(self, Self::LinuxTier1Proven | Self::WindowsTier3Proven)
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::LinuxTier1Proven => "Linux (cgroups v2 — Proven)",
            Self::WindowsTier3Proven => "Windows (Job Object — Proven)",
            Self::MacOsTier2BestEffort => "macOS (Multi-Phase Sweep — Best-Effort)",
        }
    }
}

/// Verification result certifying total extinction of the process set P(t) and resource space E(t).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtinctionProof {
    pub platform: PlatformExtinctionTier,
    pub surviving_processes: usize,
    pub surviving_resources: usize,
    pub elapsed_ms: u64,
    pub mathematically_proven: bool,
}

/// Failure breach emitted when extinction fails or exceeds deadline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtinctionBreach {
    pub platform: PlatformExtinctionTier,
    pub exit_code: i32,
    pub reason: String,
    pub surviving_processes: usize,
    pub surviving_resources: usize,
    pub elapsed_ms: u64,
}

/// Verifier enforcing the Mathematical Process Tree Extinction Theorem (§12.1).
pub struct ExtinctionVerifier;

impl ExtinctionVerifier {
    /// Verifies that process set P(t) and resource set E(t) have converged to empty
    /// within Delta t_max <= 500ms.
    pub fn verify(
        platform: PlatformExtinctionTier,
        surviving_processes: usize,
        surviving_resources: usize,
        elapsed_ms: u64,
    ) -> Result<ExtinctionProof, ExtinctionBreach> {
        if surviving_processes > 0 {
            return Err(ExtinctionBreach {
                platform,
                exit_code: FAIL_CLOSED_EXTINCTION_EXIT_CODE,
                reason: format!(
                    "Lifecycle breach: {} descendant processes escaped extinction boundary",
                    surviving_processes
                ),
                surviving_processes,
                surviving_resources,
                elapsed_ms,
            });
        }

        if surviving_resources > 0 {
            return Err(ExtinctionBreach {
                platform,
                exit_code: FAIL_CLOSED_EXTINCTION_EXIT_CODE,
                reason: format!(
                    "Resource breach: {} execution resources (pipes/mounts/IPC) leaked",
                    surviving_resources
                ),
                surviving_processes,
                surviving_resources,
                elapsed_ms,
            });
        }

        if elapsed_ms > MAX_EXTINCTION_DEADLINE_MS {
            return Err(ExtinctionBreach {
                platform,
                exit_code: FAIL_CLOSED_EXTINCTION_EXIT_CODE,
                reason: format!(
                    "Extinction deadline exceeded: elapsed {}ms > {}ms max limit",
                    elapsed_ms, MAX_EXTINCTION_DEADLINE_MS
                ),
                surviving_processes,
                surviving_resources,
                elapsed_ms,
            });
        }

        Ok(ExtinctionProof {
            platform,
            surviving_processes: 0,
            surviving_resources: 0,
            elapsed_ms,
            mathematically_proven: platform.is_authoritative(),
        })
    }
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

    #[test]
    fn test_extinction_theorem_verification_pass() {
        let proof = ExtinctionVerifier::verify(
            PlatformExtinctionTier::LinuxTier1Proven,
            0,
            0,
            120,
        )
        .expect("linux extinction must verify");

        assert_eq!(proof.surviving_processes, 0);
        assert_eq!(proof.surviving_resources, 0);
        assert!(proof.mathematically_proven);
    }

    #[test]
    fn test_extinction_theorem_macos_best_effort() {
        let proof = ExtinctionVerifier::verify(
            PlatformExtinctionTier::MacOsTier2BestEffort,
            0,
            0,
            80,
        )
        .expect("macos extinction best effort");

        assert_eq!(proof.surviving_processes, 0);
        assert!(!proof.mathematically_proven, "macOS is non-authoritative");
    }

    #[test]
    fn test_extinction_theorem_surviving_pid_fails_closed() {
        let breach = ExtinctionVerifier::verify(
            PlatformExtinctionTier::LinuxTier1Proven,
            1,
            0,
            50,
        )
        .unwrap_err();

        assert_eq!(breach.exit_code, 125);
        assert!(breach.reason.contains("Lifecycle breach"));
    }

    #[test]
    fn test_extinction_theorem_deadline_exceeded_fails_closed() {
        let breach = ExtinctionVerifier::verify(
            PlatformExtinctionTier::LinuxTier1Proven,
            0,
            0,
            501,
        )
        .unwrap_err();

        assert_eq!(breach.exit_code, 125);
        assert!(breach.reason.contains("Extinction deadline exceeded"));
    }
}
