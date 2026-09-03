//! Process execution with timeout and process group cleanup.
//!
//! Enforces execution deadlines on subprocesses and ensures that any runaway
//! child processes or deep process trees spawned by autonomous AI agents are
//! cleanly terminated using process groups and progressive SIGTERM -> SIGKILL escalation.

use std::time::Duration;

use anyhow::Result;

/// Runs a command with a strict deadline, terminating the entire process group if the timeout
/// is exceeded.
///
/// On Unix:
/// - Configures `process_group(0)` on `cmd` so the child starts a new process group.
/// - Polls `try_wait()` with a 50ms sleep interval.
/// - If `timeout` expires:
///   - Sends `SIGTERM` to `-pgid`.
///   - Polls for up to 2 seconds grace period.
///   - Sends `SIGKILL` to `-pgid` if still running.
///   - Prints warning message to stderr.
///   - Returns an `ExitStatus` representing code `124`.
///
/// On Windows / non-Unix:
/// - Spawns child and polls `try_wait()` with a 50ms interval.
/// - Calls `child.kill()` if `timeout` expires.
/// - Returns an `ExitStatus` representing code `124`.
#[cfg(unix)]
pub fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    use std::os::unix::process::CommandExt;
    use std::os::unix::process::ExitStatusExt;

    cmd.process_group(0);
    let mut child = cmd.spawn()?;
    let pid = child.id() as libc::pid_t;

    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            break;
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        std::thread::sleep(poll_interval.min(remaining));
    }

    // SAFETY: Negating the PID targets the process group created by `process_group(0)`.
    unsafe {
        libc::kill(-pid, libc::SIGTERM);
    }

    // Wait up to 2 seconds grace period
    let grace_period = Duration::from_secs(2);
    let grace_start = std::time::Instant::now();
    let mut reaped = false;

    while grace_start.elapsed() < grace_period {
        if child.try_wait()?.is_some() {
            reaped = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    if !reaped {
        // SAFETY: Negating the PID targets the process group for unconditional SIGKILL.
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
        let kill_start = std::time::Instant::now();
        while kill_start.elapsed() < Duration::from_secs(1) {
            if child.try_wait()?.is_some() {
                reaped = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        if !reaped {
            let _ = child.wait();
        }
    }

    eprintln!("[VETTO WATCHDOG] Process exceeded timeout of {timeout:?} and was killed.");

    Ok(ExitStatusExt::from_raw(124 << 8))
}

#[cfg(not(unix))]
pub fn run_with_timeout(
    cmd: &mut std::process::Command,
    timeout: Duration,
) -> Result<std::process::ExitStatus> {
    #[cfg(windows)]
    use std::os::windows::process::ExitStatusExt;

    let mut child = cmd.spawn()?;
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_millis(50);

    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if start.elapsed() >= timeout {
            break;
        }
        let remaining = timeout.saturating_sub(start.elapsed());
        std::thread::sleep(poll_interval.min(remaining));
    }

    let _ = child.kill();
    let _ = child.wait();

    eprintln!("[VETTO WATCHDOG] Process exceeded timeout of {timeout:?} and was killed.");

    #[cfg(windows)]
    {
        Ok(ExitStatusExt::from_raw(124))
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!(
            "[VETTO WATCHDOG] Process exceeded timeout of {:?} and was killed.",
            timeout
        )
    }
}

/// Parses human-readable duration strings (e.g. `90s`, `30m`, `2h`, or bare seconds).
pub fn parse_timeout(s: &str) -> Result<Duration> {
    crate::config::parse_session_timeout(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn test_timeout_completes_fast_command() {
        #[cfg(unix)]
        let mut cmd = Command::new("echo");
        #[cfg(unix)]
        cmd.arg("test");

        #[cfg(windows)]
        let mut cmd = Command::new("cmd");
        #[cfg(windows)]
        cmd.args(["/c", "echo", "test"]);

        let status = run_with_timeout(&mut cmd, Duration::from_secs(5))
            .expect("fast command should complete successfully");
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn test_timeout_terminates_hanging_command() {
        #[cfg(unix)]
        let mut cmd = Command::new("sleep");
        #[cfg(unix)]
        cmd.arg("5");

        #[cfg(windows)]
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        cmd.args(["-Command", "Start-Sleep -Seconds 5"]);

        let res = run_with_timeout(&mut cmd, Duration::from_millis(150));
        if let Ok(status) = res {
            assert_eq!(status.code(), Some(124));
        }
    }

    #[test]
    fn test_parse_timeout_duration() {
        assert_eq!(parse_timeout("10s").unwrap(), Duration::from_secs(10));
        assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
        assert_eq!(parse_timeout("1h").unwrap(), Duration::from_secs(3600));
        assert_eq!(parse_timeout("60").unwrap(), Duration::from_secs(60));
        assert!(parse_timeout("0s").is_err());
        assert!(parse_timeout("abc").is_err());
    }
}
