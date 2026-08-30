//! Session status registry and management (`vetto status`).
//!
//! Tracks active supervisor sessions under `~/.vetto/run/<session_id>/`.
//! Automatically cleans up stale/dead session files when inspected.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionEntry {
    pub session_id: String,
    pub pid: u32,
    pub agent: String,
    pub started_at_secs: u64,
    pub policy: String,
    pub tier: String,
    pub cwd: String,
}

pub struct SessionRegistry {
    run_dir: PathBuf,
}

impl SessionRegistry {
    pub fn default_run_dir() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("failed to resolve HOME directory for session registry")?;
        Ok(home.join(".vetto").join("run"))
    }

    pub fn new() -> Result<Self> {
        let run_dir = Self::default_run_dir()?;
        fs::create_dir_all(&run_dir)?;
        Ok(Self { run_dir })
    }

    pub fn with_dir(run_dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&run_dir);
        Self { run_dir }
    }

    /// Register a newly started session.
    pub fn register(
        &self,
        session_id: &str,
        pid: u32,
        agent: &str,
        policy: &str,
        tier: &str,
        cwd: &Path,
    ) -> Result<()> {
        let entry_dir = self.run_dir.join(session_id);
        fs::create_dir_all(&entry_dir)?;

        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entry = SessionEntry {
            session_id: session_id.to_string(),
            pid,
            agent: agent.to_string(),
            started_at_secs: now_secs,
            policy: policy.to_string(),
            tier: tier.to_string(),
            cwd: cwd.display().to_string(),
        };

        let json = serde_json::to_string_pretty(&entry)?;
        fs::write(entry_dir.join("info.json"), json)?;
        fs::write(entry_dir.join("pid"), pid.to_string())?;
        fs::write(entry_dir.join("policy"), policy)?;
        fs::write(entry_dir.join("started"), now_secs.to_string())?;
        Ok(())
    }

    /// Unregister a completed session.
    pub fn unregister(&self, session_id: &str) {
        let entry_dir = self.run_dir.join(session_id);
        let _ = fs::remove_dir_all(&entry_dir);
    }

    /// List all live sessions, pruning dead PIDs.
    pub fn list_active(&self) -> Result<Vec<SessionEntry>> {
        let mut active = Vec::new();
        if !self.run_dir.exists() {
            return Ok(active);
        }

        let entries = match fs::read_dir(&self.run_dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(active),
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let info_file = path.join("info.json");
            if let Ok(content) = fs::read_to_string(&info_file) {
                if let Ok(session) = serde_json::from_str::<SessionEntry>(&content) {
                    if is_pid_alive(session.pid) {
                        active.push(session);
                    } else {
                        // Prune dead session directory
                        let _ = fs::remove_dir_all(&path);
                    }
                } else {
                    let _ = fs::remove_dir_all(&path);
                }
            } else {
                let _ = fs::remove_dir_all(&path);
            }
        }

        active.sort_by_key(|s| s.started_at_secs);
        Ok(active)
    }
}

/// Check if a PID is currently alive on the host.
pub fn is_pid_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // SAFETY: kill(pid, 0) performs error checking without sending a signal.
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if ret == 0 {
            true
        } else {
            let err = std::io::Error::last_os_error();
            // EPERM means the process exists but belongs to another user
            err.raw_os_error() == Some(libc::EPERM)
        }
    }
    #[cfg(windows)]
    {
        let _ = pid;
        true
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = pid;
        true
    }
}

/// CLI handler for `vetto status`.
pub fn run_cli(json: bool) -> Result<()> {
    let registry = SessionRegistry::new()?;
    let sessions = registry.list_active()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }

    if sessions.is_empty() {
        println!("No active vetto sessions.");
        return Ok(());
    }

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    println!(
        "{:<10} {:<15} {:<12} {:<15} {:<10} {:<8}",
        "PID", "AGENT", "POLICY", "TIER", "UPTIME", "SESSION"
    );
    println!("{}", "-".repeat(75));

    for s in &sessions {
        let uptime_secs = now_secs.saturating_sub(s.started_at_secs);
        let uptime_str = format_uptime(uptime_secs);
        let short_sid = if s.session_id.len() > 8 {
            &s.session_id[..8]
        } else {
            &s.session_id
        };
        println!(
            "{:<10} {:<15} {:<12} {:<15} {:<10} {:<8}",
            s.pid, s.agent, s.policy, s.tier, uptime_str, short_sid
        );
    }

    Ok(())
}

fn format_uptime(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m {}s", secs / 60, secs % 60)
    } else {
        format!("{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_lifecycle_and_pruning() {
        let temp = std::env::temp_dir().join(format!("vetto-test-reg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        let registry = SessionRegistry::with_dir(temp.clone());

        let my_pid = std::process::id();
        registry
            .register(
                "test-sess-1",
                my_pid,
                "codex",
                "default",
                "full",
                Path::new("/tmp"),
            )
            .unwrap();

        // Dead pid
        registry
            .register(
                "test-sess-dead",
                999_999_999,
                "claude",
                "strict",
                "fs-only",
                Path::new("/tmp"),
            )
            .unwrap();

        let active = registry.list_active().unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].session_id, "test-sess-1");

        registry.unregister("test-sess-1");
        let active = registry.list_active().unwrap();
        assert_eq!(active.len(), 0);

        let _ = fs::remove_dir_all(&temp);
    }
}
