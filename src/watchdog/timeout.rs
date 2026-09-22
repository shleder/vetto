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
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {}
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                return Ok(ExitStatusExt::from_raw(0));
            }
            Err(e) => return Err(e.into()),
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
        match child.try_wait() {
            Ok(Some(_)) => {
                reaped = true;
                break;
            }
            Ok(None) => {}
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                reaped = true;
                break;
            }
            Err(e) => return Err(e.into()),
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
            match child.try_wait() {
                Ok(Some(_)) => {
                    reaped = true;
                    break;
                }
                Ok(None) => {}
                Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                    reaped = true;
                    break;
                }
                Err(e) => return Err(e.into()),
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

/// Recommends a timeout based on the 95th percentile of past successful session durations.
pub fn recommend_timeout(project_root: &std::path::Path, reports_dir: &std::path::Path) -> Option<Duration> {
    let history_file = reports_dir.join("history.jsonl");
    if !history_file.exists() {
        return None;
    }

    let records = crate::audit::history::read_history(&history_file).ok()?;

    let mut durations: Vec<u64> = records
        .into_iter()
        .filter(|r| r.exit_code == 0)
        .filter(|r| {
            if let Some(ref policy_path) = r.policy_path {
                let pp = std::path::Path::new(policy_path);
                pp.starts_with(project_root)
            } else {
                false
            }
        })
        .map(|r| r.duration_secs)
        .collect();

    if durations.is_empty() {
        return None;
    }

    durations.sort_unstable();

    // 95th percentile calculation
    let index = (durations.len() as f64 * 0.95).floor() as usize;
    let index = index.min(durations.len().saturating_sub(1));

    let p95 = durations[index];

    // + 50% buffer
    let recommended = p95 + (p95 / 2);

    // Provide a minimum floor (e.g. at least 60 seconds) if needed?
    // The prompt just says p95 + 50%.
    Some(Duration::from_secs(recommended.max(1))) // Avoid 0
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
            assert!(!status.success());
            assert!(status.code() == Some(124) || status.code().is_none());
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
    #[test]
    fn test_recommend_timeout_logic() {
        use crate::audit::history::AuditRecord;
        use std::fs;
        let temp = std::env::temp_dir().join(format!("vetto-timeout-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        
        let history_file = temp.join("history.jsonl");
        let proj_root = temp.join("my-project");
        let policy_path = proj_root.join("vetto.toml");

        let mut write_record = |duration_secs: u64, exit_code: i32, policy: Option<String>| {
            let r = AuditRecord {
                ts: chrono::Utc::now(),
                session_id: "test".into(),
                agent: "test".into(),
                command: None,
                profile: "test".into(),
                policy_path: policy,
                exit_code,
                duration_secs,
                tier: "test".into(),
                net_mode: "off".into(),
                blocked_count: 0,
                events_total: 0,
                report_path: None,
                log_path: None,
            };
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&history_file)
                .unwrap();
            use std::io::Write;
            writeln!(file, "{}", serde_json::to_string(&r).unwrap()).unwrap();
        };

        // 1. Missing file
        assert_eq!(recommend_timeout(&proj_root, &temp), None);

        // 2. Empty or irrelevant records
        write_record(100, 1, Some(policy_path.to_string_lossy().to_string())); // Failed
        write_record(200, 0, Some("/other/project/vetto.toml".into())); // Other project
        assert_eq!(recommend_timeout(&proj_root, &temp), None);

        // 3. Valid records
        // Let's add 10 successful records with durations 10..100
        for d in 1..=10 {
            write_record(d * 10, 0, Some(policy_path.to_string_lossy().to_string()));
        }
        
        // durations: 10, 20, 30, 40, 50, 60, 70, 80, 90, 100
        // len = 10. index = floor(10 * 0.95) = 9. durations[9] = 100.
        // recommended = 100 + 50 = 150.
        let rec = recommend_timeout(&proj_root, &temp).unwrap();
        assert_eq!(rec, Duration::from_secs(150));

        let _ = fs::remove_dir_all(&temp);
    }
}
