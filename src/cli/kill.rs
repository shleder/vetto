//! Process safety & runaway process killer (`vetto kill`).
//!
//! Terminates runaway or hanging AI agent processes and active Vetto sessions
//! by PID or Session ID, and provides a `--hung` scanner to kill sessions exceeding
//! a runtime threshold (default: 30 minutes).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Result};
use clap::Args;

/// Command-line arguments for `vetto kill`.
#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct KillArgs {
    /// Target session ID or process ID (PID) to terminate.
    #[arg(value_name = "TARGET")]
    pub target: Option<String>,

    /// Kill any active Vetto session/process running longer than 30 minutes (or --older-than).
    #[arg(long)]
    pub hung: bool,

    /// Duration threshold for hung sessions (e.g. 10m, 1h). Implies --hung.
    #[arg(long, value_name = "DURATION")]
    pub older_than: Option<String>,

    /// Send SIGKILL immediately without graceful SIGTERM.
    #[arg(short = '9', long = "force")]
    pub force: bool,
}

/// Kills a process by PID, optionally sending SIGKILL immediately or with a grace period.
pub fn kill_pid(pid: u32, force: bool) -> Result<()> {
    if pid <= 1 {
        bail!("Refusing to kill reserved PID {pid}");
    }

    #[cfg(unix)]
    {
        let pid_i = pid as libc::pid_t;
        if force {
            // SAFETY: Negating the PID targets the process group. If that fails,
            // we fall back to signaling the individual PID directly.
            unsafe {
                if libc::kill(-pid_i, libc::SIGKILL) != 0 {
                    libc::kill(pid_i, libc::SIGKILL);
                }
            }
        } else {
            // SAFETY: Negating the PID sends SIGTERM to the process group.
            unsafe {
                if libc::kill(-pid_i, libc::SIGTERM) != 0 {
                    libc::kill(pid_i, libc::SIGTERM);
                }
            }
            let deadline = std::time::Instant::now() + Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if !crate::cli::status::is_pid_alive(pid) {
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            if crate::cli::status::is_pid_alive(pid) {
                // SAFETY: Escalating to SIGKILL for unresponsive process/group.
                unsafe {
                    if libc::kill(-pid_i, libc::SIGKILL) != 0 {
                        libc::kill(pid_i, libc::SIGKILL);
                    }
                }
            }
        }
        Ok(())
    }

    #[cfg(windows)]
    {
        let flag = if force { "/F" } else { "/T" };
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), flag])
            .output();
        Ok(())
    }

    #[cfg(not(any(unix, windows)))]
    {
        let _ = (pid, force);
        Ok(())
    }
}

/// Main entrypoint for `vetto kill`.
pub fn run_cli(args: &KillArgs) -> Result<()> {
    if let Some(target) = &args.target {
        if let Ok(pid) = target.parse::<u32>() {
            kill_by_pid(pid, args.force)
        } else {
            kill_by_session_id(target, args.force)
        }
    } else if args.hung || args.older_than.is_some() {
        let threshold = match &args.older_than {
            Some(raw) => crate::watchdog::timeout::parse_timeout(raw)?,
            None => Duration::from_secs(30 * 60),
        };
        kill_hung_sessions(threshold, args.force)
    } else {
        bail!("Specify a target PID or Session ID, or use --hung to terminate hung sessions.");
    }
}

fn kill_by_pid(pid: u32, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let session = active.iter().find(|s| s.pid == pid);

    if let Some(s) = session {
        kill_pid(pid, force)?;
        registry.unregister(&s.session_id);
        println!("Terminated session {} (PID {})", s.session_id, pid);
        return Ok(());
    }

    // Also check daemon registry
    if let Ok(daemon_dir) = crate::daemon::auth::default_daemon_dir() {
        let daemon_reg = crate::daemon::registry::SessionRegistry::new(daemon_dir);
        for s in daemon_reg.list_sessions() {
            if s.pid == pid && s.status == crate::daemon::registry::SessionStatus::Running {
                let _ = daemon_reg.stop_session(&s.id);
                println!("Terminated daemon session {} (PID {})", s.id, pid);
                return Ok(());
            }
        }
    }

    if crate::cli::status::is_pid_alive(pid) {
        kill_pid(pid, force)?;
        println!("Terminated process PID {}", pid);
        Ok(())
    } else {
        bail!("Process PID {} is not running", pid);
    }
}

fn kill_by_session_id(target: &str, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let matched: Vec<_> = active
        .into_iter()
        .filter(|s| s.session_id == target || s.session_id.starts_with(target))
        .collect();

    if !matched.is_empty() {
        for s in matched {
            kill_pid(s.pid, force)?;
            registry.unregister(&s.session_id);
            println!("Terminated session {} (PID {})", s.session_id, s.pid);
        }
        return Ok(());
    }

    // Check daemon registry
    if let Ok(daemon_dir) = crate::daemon::auth::default_daemon_dir() {
        let daemon_reg = crate::daemon::registry::SessionRegistry::new(daemon_dir);
        if let Some(s) = daemon_reg.get_session(target) {
            let _ = daemon_reg.stop_session(&s.id);
            println!("Terminated daemon session {} (PID {})", s.id, s.pid);
            return Ok(());
        }
        for s in daemon_reg.list_sessions() {
            if s.id.starts_with(target)
                && s.status == crate::daemon::registry::SessionStatus::Running
            {
                let _ = daemon_reg.stop_session(&s.id);
                println!("Terminated daemon session {} (PID {})", s.id, s.pid);
                return Ok(());
            }
        }
    }

    bail!("No active session found matching '{target}'");
}

fn kill_hung_sessions(threshold: Duration, force: bool) -> Result<()> {
    let registry = crate::cli::status::SessionRegistry::new()?;
    let active = registry.list_active()?;
    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut killed = 0;
    for s in &active {
        let elapsed = now_secs.saturating_sub(s.started_at_secs);
        if elapsed >= threshold.as_secs() {
            kill_pid(s.pid, force)?;
            registry.unregister(&s.session_id);
            println!(
                "Terminated hung session {} (PID {}, running for {}s)",
                s.session_id, s.pid, elapsed
            );
            killed += 1;
        }
    }

    // Also scan daemon sessions
    if let Ok(daemon_dir) = crate::daemon::auth::default_daemon_dir() {
        let daemon_reg = crate::daemon::registry::SessionRegistry::new(daemon_dir);
        for s in daemon_reg.list_sessions() {
            if s.status == crate::daemon::registry::SessionStatus::Running {
                let elapsed = now_secs.saturating_sub(s.started_at);
                if elapsed >= threshold.as_secs() {
                    let _ = daemon_reg.stop_session(&s.id);
                    println!(
                        "Terminated hung daemon session {} (PID {}, running for {}s)",
                        s.id, s.pid, elapsed
                    );
                    killed += 1;
                }
            }
        }
    }

    if killed == 0 {
        println!("No hung sessions found running longer than {:?}", threshold);
    } else {
        println!("Successfully terminated {} hung session(s)", killed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_refuse_reserved_pids() {
        assert!(kill_pid(0, false).is_err());
        assert!(kill_pid(1, false).is_err());
        assert!(kill_pid(0, true).is_err());
        assert!(kill_pid(1, true).is_err());
    }

    #[test]
    fn test_kill_args_validation() {
        let args = KillArgs {
            target: None,
            hung: false,
            older_than: None,
            force: false,
        };
        assert!(run_cli(&args).is_err());
    }
}
