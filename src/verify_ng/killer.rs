//! Killer stage: deadline -> terminate -> re-wait (FM-04/FM-05).
//!
//! The engine owns the `SandboxHandle`; the killer borrows it mutably for
//! exactly one stage and hands it back. No other module may terminate or
//! drop the handle mid-run: cleanup responsibility is single-owner (FM-14).
//!
//! Cleanup strength by tier (FM-05), enforced by the caller selecting the
//! matching [`CleanupExpectation`]:
//! - FULL / Windows-Job: kernel/Job teardown, residue is a FAIL.
//! - FS-ONLY / macOS: group-kill + bounded sweep, residue is FAIL with a
//!   documented residual; destructive suites stay on Strong tiers or in a VM.

use std::time::{Duration, Instant};

/// What cleanup strength the caller may assume for this run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupExpectation {
    /// Kernel/Job teardown: any residue is a containment FAIL.
    Strong,
    /// Group-kill + bounded sweep: residue is FAIL with known residual text.
    BestEffort { sweep_budget_ms: u64 },
}

impl CleanupExpectation {
    /// Select from the current backend/tier. Windows Job and Linux FULL are
    /// Strong; everything else is best-effort with the reparent-sweep budget.
    pub fn for_current_tier(tier_label: Option<&str>) -> Self {
        #[cfg(target_os = "windows")]
        {
            let _ = tier_label;
            CleanupExpectation::Strong
        }
        #[cfg(target_os = "linux")]
        {
            match tier_label {
                Some("full") => CleanupExpectation::Strong,
                _ => CleanupExpectation::BestEffort {
                    sweep_budget_ms: 2000,
                },
            }
        }
        #[cfg(target_os = "macos")]
        {
            let _ = tier_label;
            CleanupExpectation::BestEffort {
                sweep_budget_ms: 2000,
            }
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = tier_label;
            CleanupExpectation::BestEffort {
                sweep_budget_ms: 2000,
            }
        }
    }
}

/// Outcome of the kill stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    /// Child exited on its own before the deadline.
    Exited,
    /// Deadline hit; terminate was issued.
    KilledOnDeadline,
}

/// Minimal wait/kill surface the deadline loop needs. Implemented by
/// [`crate::sandbox::SandboxHandle`] (sandboxed runs) and by the
/// direct-exec child handle in [`super::runner`] (plumbing runs): both go
/// through the same [`kill_on_deadline_with`] code path, never blocking
/// `wait()`.
pub trait WaitKill {
    /// Non-blocking poll: `Some(code)` once the child is reaped.
    fn try_wait(&mut self) -> Option<i32>;
    /// Issue termination (SIGKILL / `Child::kill`). Idempotent.
    fn terminate(&mut self);
}

impl WaitKill for crate::sandbox::SandboxHandle {
    fn try_wait(&mut self) -> Option<i32> {
        crate::sandbox::SandboxHandle::try_wait(self)
    }

    fn terminate(&mut self) {
        crate::sandbox::SandboxHandle::terminate(self);
    }
}

/// Poll `try_wait` until `deadline`; on expiry call `terminate` once and do
/// a final bounded re-wait so the caller always gets an exit value.
/// Blocking `wait()` is never used here (FM-04).
pub fn kill_on_deadline(
    handle: &mut crate::sandbox::SandboxHandle,
    deadline: Instant,
    poll: Duration,
) -> (KillOutcome, i32) {
    kill_on_deadline_with(handle, deadline, poll)
}

/// Generic deadline loop over any [`WaitKill`] handle. Same contract as
/// [`kill_on_deadline`]: poll, terminate once on expiry, bounded re-wait.
pub fn kill_on_deadline_with<H: WaitKill>(
    handle: &mut H,
    deadline: Instant,
    poll: Duration,
) -> (KillOutcome, i32) {
    loop {
        if let Some(code) = handle.try_wait() {
            return (KillOutcome::Exited, code);
        }
        if Instant::now() >= deadline {
            handle.terminate();
            let end = Instant::now() + Duration::from_secs(10);
            loop {
                if let Some(code) = handle.try_wait() {
                    return (KillOutcome::KilledOnDeadline, code);
                }
                if Instant::now() >= end {
                    handle.terminate();
                    return (KillOutcome::KilledOnDeadline, -1);
                }
                std::thread::sleep(poll);
            }
        }
        std::thread::sleep(poll);
    }
}

#[cfg(test)]
mod killer_tests {
    use super::*;
    use std::collections::VecDeque;

    /// In-memory [`WaitKill`] double with a scripted exit schedule.
    struct FakeHandle {
        polls: VecDeque<Option<i32>>,
        terminates: usize,
    }

    impl WaitKill for FakeHandle {
        fn try_wait(&mut self) -> Option<i32> {
            self.polls.pop_front().flatten()
        }

        fn terminate(&mut self) {
            self.terminates += 1;
            // A SIGKILLed child becomes reaped on the next poll.
            self.polls.push_front(Some(-9));
        }
    }

    #[test]
    fn exits_before_deadline_without_terminate() {
        let mut h = FakeHandle {
            polls: vec![None, None, Some(0)].into(),
            terminates: 0,
        };
        let (outcome, code) = kill_on_deadline_with(
            &mut h,
            Instant::now() + Duration::from_secs(30),
            Duration::from_millis(1),
        );
        assert_eq!((outcome, code), (KillOutcome::Exited, 0));
        assert_eq!(h.terminates, 0);
    }

    #[test]
    fn deadline_kills_exactly_once_and_reaps() {
        let mut h = FakeHandle {
            polls: vec![None].into(),
            terminates: 0,
        };
        let (outcome, code) =
            kill_on_deadline_with(&mut h, Instant::now(), Duration::from_millis(1));
        assert_eq!((outcome, code), (KillOutcome::KilledOnDeadline, -9));
        assert_eq!(h.terminates, 1);
    }

    #[test]
    fn expectation_matrix() {
        #[cfg(target_os = "linux")]
        {
            assert_eq!(
                CleanupExpectation::for_current_tier(Some("full")),
                CleanupExpectation::Strong
            );
            assert!(matches!(
                CleanupExpectation::for_current_tier(Some("fs-only")),
                CleanupExpectation::BestEffort { .. }
            ));
        }
        #[cfg(target_os = "windows")]
        {
            assert_eq!(
                CleanupExpectation::for_current_tier(None),
                CleanupExpectation::Strong
            );
        }
        #[cfg(target_os = "macos")]
        {
            assert!(matches!(
                CleanupExpectation::for_current_tier(None),
                CleanupExpectation::BestEffort { .. }
            ));
        }
    }
}
