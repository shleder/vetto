//! Stable exit codes and mapping functions for vetto.
//!
//! All session termination paths and error exits map through this module to
//! guarantee consistent, deterministic exit codes across all platforms and TUI modes.
//! See `docs/exit-codes.md` for full specification.

/// Successful execution of the sandboxed agent.
pub const EXIT_SUCCESS: i32 = 0;

/// Generic agent error or general operational error.
pub const EXIT_AGENT_ERROR: i32 = 1;

/// Session timeout: the supervisor killed the child process after the deadline (mirrors GNU timeout).
pub const EXIT_TIMEOUT: i32 = 124;

/// Fail-closed sandbox error: sandbox initialization failure, preflight leak, or unsupported platform.
pub const EXIT_FAIL_CLOSED: i32 = 125;

/// Policy violation: fail-on-block threshold reached or enterprise policy lockdown violation.
pub const EXIT_POLICY_BLOCKED: i32 = 126;

/// Agent executable not found in PATH or failed to resolve.
pub const EXIT_COMMAND_NOT_FOUND: i32 = 127;

/// Base offset for processes terminated by signals (128 + signal_number).
pub const EXIT_SIGNAL_BASE: i32 = 128;

/// Map raw process exit status, timeout flag, and blocked attempt thresholds to a final stable exit code.
pub fn map_session_exit_code(
    raw_exit_code: i32,
    timed_out: bool,
    fail_on_block_triggered: bool,
) -> i32 {
    if timed_out {
        return EXIT_TIMEOUT;
    }
    if fail_on_block_triggered {
        return EXIT_POLICY_BLOCKED;
    }
    if raw_exit_code < 0 {
        // Negative return indicates signal termination (e.g. -9 -> 128 + 9 = 137).
        let sig = -raw_exit_code;
        return EXIT_SIGNAL_BASE.saturating_add(sig);
    }
    raw_exit_code
}

/// One-line actionable recap for the end of a supervised session.
///
/// Returns `None` when the session was fully clean (exit 0, no denials,
/// no timeout) so the exit path stays quiet. Every other outcome maps to
/// exactly one next action — this is the in-product half of the activation
/// funnel (issue #27): a first-run failure must point at one command.
pub fn recap_hint(final_code: i32, blocked_total: u64, timed_out: bool) -> Option<String> {
    if timed_out || final_code == EXIT_TIMEOUT {
        return Some(
            "session hit the deadline — re-run with a larger --session-timeout or split the task"
                .to_string(),
        );
    }
    if final_code == EXIT_POLICY_BLOCKED {
        return Some(format!(
            "{blocked_total} boundary denials tripped fail-on-block — 'vetto audit --latest' shows what the kernel denied; adjust grants with 'vetto allow'/'vetto deny'"
        ));
    }
    if final_code == EXIT_FAIL_CLOSED {
        return Some(
            "sandbox refused fail-closed — run 'vetto doctor' for the capability picture, then 'vetto pack --bug -o bug.vetto-pack' to bundle a report"
                .to_string(),
        );
    }
    if final_code == EXIT_COMMAND_NOT_FOUND {
        return Some(
            "agent binary not found in PATH — 'vetto enable <agent>' wires the shim, or check PATH"
                .to_string(),
        );
    }
    if final_code != EXIT_SUCCESS {
        return Some(format!(
            "agent exited {final_code} — 'vetto pack --bug -o bug.vetto-pack' bundles a redacted report for your issue"
        ));
    }
    if blocked_total > 0 {
        return Some(format!(
            "{blocked_total} denials contained, exit 0 — 'vetto audit --latest' shows what was denied"
        ));
    }
    None
}

/// Map an anyhow error from session setup or command execution to an exit code.
///
/// Deterministic path first: if the error chain carries a typed [`crate::error::VettoError`],
/// its [`crate::error::VettoError::exit_code`] wins. The substring fallback below is legacy
/// (kept for untyped `anyhow!` call sites) — do not extend it; construct a typed error instead.
pub fn map_error_to_exit_code(err: &anyhow::Error) -> i32 {
    if let Some(typed) = err.downcast_ref::<crate::error::VettoError>() {
        return typed.exit_code();
    }
    let msg = err.to_string().to_lowercase();
    if msg.contains("not found in path") || msg.contains("no such file or directory") {
        EXIT_COMMAND_NOT_FOUND
    } else if msg.contains("lockdown violation") || msg.contains("fail-on-block") {
        EXIT_POLICY_BLOCKED
    } else if msg.contains("fail-closed")
        || msg.contains("boundary verification failed")
        || msg.contains("refusing to run")
        || msg.contains("not supported")
        || msg.contains("sandbox setup failed")
        || msg.contains("landlock")
        || msg.contains("namespace")
        || msg.contains("mount")
    {
        EXIT_FAIL_CLOSED
    } else {
        EXIT_AGENT_ERROR
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;

    #[test]
    fn maps_successful_exit() {
        assert_eq!(map_session_exit_code(0, false, false), EXIT_SUCCESS);
    }

    #[test]
    fn maps_agent_error_code() {
        assert_eq!(map_session_exit_code(1, false, false), 1);
        assert_eq!(map_session_exit_code(42, false, false), 42);
    }

    #[test]
    fn maps_timeout_exit() {
        assert_eq!(map_session_exit_code(0, true, false), EXIT_TIMEOUT);
        assert_eq!(map_session_exit_code(1, true, false), EXIT_TIMEOUT);
        assert_eq!(map_session_exit_code(-9, true, false), EXIT_TIMEOUT);
    }

    #[test]
    fn maps_fail_on_block_exit() {
        assert_eq!(map_session_exit_code(0, false, true), EXIT_POLICY_BLOCKED);
        assert_eq!(map_session_exit_code(1, false, true), EXIT_POLICY_BLOCKED);
    }

    #[test]
    fn maps_signal_terminations() {
        assert_eq!(map_session_exit_code(-9, false, false), 137); // SIGKILL
        assert_eq!(map_session_exit_code(-15, false, false), 143); // SIGTERM
        assert_eq!(map_session_exit_code(-2, false, false), 130); // SIGINT
    }

    #[test]
    fn maps_errors_to_appropriate_codes() {
        assert_eq!(
            map_error_to_exit_code(&anyhow!("agent command 'missing' not found in PATH")),
            EXIT_COMMAND_NOT_FOUND
        );
        assert_eq!(
            map_error_to_exit_code(&anyhow!(
                "--verify: boundary verification failed; refusing to start the agent (fail-closed)"
            )),
            EXIT_FAIL_CLOSED
        );
        assert_eq!(
            map_error_to_exit_code(&anyhow!(
                "policy lockdown violation: cannot override immutable root"
            )),
            EXIT_POLICY_BLOCKED
        );
        assert_eq!(
            map_error_to_exit_code(&anyhow!("invalid CLI argument provided")),
            EXIT_AGENT_ERROR
        );
    }

    #[test]
    fn recap_stays_quiet_on_clean_exit() {
        assert_eq!(recap_hint(EXIT_SUCCESS, 0, false), None);
    }

    #[test]
    fn recap_points_at_one_action_per_outcome() {
        let timeout = recap_hint(EXIT_TIMEOUT, 0, true).expect("timeout recap");
        assert!(timeout.contains("--session-timeout"));

        let blocked = recap_hint(EXIT_POLICY_BLOCKED, 7, false).expect("blocked recap");
        assert!(blocked.contains('7'));
        assert!(blocked.contains("vetto audit --latest"));

        let fail_closed = recap_hint(EXIT_FAIL_CLOSED, 0, false).expect("fail-closed recap");
        assert!(fail_closed.contains("vetto doctor"));
        assert!(fail_closed.contains("vetto pack --bug"));

        let missing = recap_hint(EXIT_COMMAND_NOT_FOUND, 0, false).expect("missing recap");
        assert!(missing.contains("vetto enable"));

        let agent_err = recap_hint(3, 0, false).expect("agent error recap");
        assert!(agent_err.contains('3'));
        assert!(agent_err.contains("vetto pack --bug"));

        let signal = recap_hint(137, 0, false).expect("signal recap");
        assert!(signal.contains("137"));

        let contained = recap_hint(EXIT_SUCCESS, 4, false).expect("contained recap");
        assert!(contained.contains('4'));
        assert!(contained.contains("vetto audit --latest"));
    }
