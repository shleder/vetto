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

/// Map an anyhow error from session setup or command execution to an exit code.
pub fn map_error_to_exit_code(err: &anyhow::Error) -> i32 {
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
}
