//! `vetto events <session>` subcommand (Feature 38).
//!
//! Tail and filter JSONL session event logs:
//! - `--filter deny` (blocked attempts, network denies)
//! - `--filter net` (network requests)
//! - `--filter files` (file observations)
//! - `--filter exec` (process executions)
//! - `--follow` / `-f` (streaming tail)
//! - `--json` or formatted table output

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};

use super::types::{Event, FileAccess};

/// Filter predicate for events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventTailFilter {
    All,
    Deny,
    Network,
    Files,
    Exec,
    Notice,
    Custom(String),
}

impl EventTailFilter {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" | "" => Self::All,
            "deny" | "blocked" => Self::Deny,
            "net" | "network" => Self::Network,
            "file" | "files" => Self::Files,
            "exec" | "process" | "procs" => Self::Exec,
            "notice" | "notices" => Self::Notice,
            other => Self::Custom(other.to_string()),
        }
    }

    pub fn matches(&self, event: &Event) -> bool {
        match self {
            Self::All => true,
            Self::Deny => {
                matches!(event, Event::BlockedAttempt { .. })
                    || matches!(event, Event::NetRequest { allowed: false, .. })
                    || crate::classifier::classify_event(event).is_some()
            }
            Self::Network => matches!(event, Event::NetRequest { .. }),
            Self::Files => {
                matches!(
                    event,
                    Event::FileObserved { .. } | Event::SecretMasked { .. }
                )
            }
            Self::Exec => matches!(event, Event::ExecObserved { .. }),
            Self::Notice => matches!(event, Event::Notice { .. }),
            Self::Custom(query) => {
                let q = query.to_ascii_lowercase();
                let kind_match = event.kind().to_ascii_lowercase().contains(&q);
                let path_match = event
                    .path()
                    .is_some_and(|p| p.to_ascii_lowercase().contains(&q));
                let net_match = event
                    .network_target()
                    .is_some_and(|(h, _, _)| h.to_ascii_lowercase().contains(&q));
                kind_match || path_match || net_match
            }
        }
    }
}

/// Format an event as a clean table row.
pub fn format_event_row(event: &Event) -> String {
    let t = event.ts().format("%H:%M:%S").to_string();
    let kind = event.kind();
    match event {
        Event::SessionStarted {
            pid, tier, profile, ..
        } => {
            format!(
                "{:<10}  {:<16}  pid={:<6}  profile={} tier={}",
                t, kind, pid, profile, tier
            )
        }
        Event::SessionEnded {
            exit_code,
            duration_secs,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  exit={:<5}  duration={}s",
                t, kind, exit_code, duration_secs
            )
        }
        Event::FileObserved {
            comm,
            pid,
            path,
            access,
            ..
        } => {
            let a = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!(
                "{:<10}  {:<16}  {}[{}]  {} ({})",
                t, kind, comm, pid, path, a
            )
        }
        Event::ExecObserved { pid, argv, .. } => {
            let cmd = argv.join(" ");
            format!("{:<10}  {:<16}  pid={:<6}  exec: {}", t, kind, pid, cmd)
        }
        Event::BlockedAttempt {
            comm,
            pid,
            path,
            source,
            ..
        } => {
            format!(
                "{:<10}  {:<16}  {}[{}]  BLOCKED {} [{}]",
                t, "BLOCKED", comm, pid, path, source
            )
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            let status = if *allowed { "ALLOW" } else { "DENIED" };
            format!(
                "{:<10}  {:<16}  {:<10}  {}:{}",
                t, "net_request", status, host, port
            )
        }
        Event::SecretMasked { path, .. } => {
            format!(
                "{:<10}  {:<16}  {:<10}  masked: {}",
                t, kind, "MASKED", path
            )
        }
        Event::Notice { message, .. } => {
            format!("{:<10}  {:<16}  {:<10}  {}", t, kind, "NOTICE", message)
        }
        Event::SessionTimeout { .. } => {
            format!(
                "{:<10}  {:<16}  {:<10}  sandbox killed (timeout)",
                t, kind, "TIMEOUT"
            )
        }
    }
}

/// Resolves session JSONL path from file path or session ID.
pub fn resolve_session_path(session_arg: &Path) -> Result<PathBuf> {
    if session_arg.is_file() {
        return Ok(session_arg.to_path_buf());
    }
    // Check if appending .jsonl finds it
    let with_ext = session_arg.with_extension("jsonl");
    if with_ext.is_file() {
        return Ok(with_ext);
    }
    // Check in .vetto/reports/ or ~/.vetto/
    if let Some(home) = std::env::var_os("HOME").map(PathBuf::from) {
        let in_home = home.join(".vetto").join(session_arg);
        if in_home.is_file() {
            return Ok(in_home);
        }
        let in_home_ext = home.join(".vetto").join(&with_ext);
        if in_home_ext.is_file() {
            return Ok(in_home_ext);
        }
    }
    let in_dot_vetto = Path::new(".vetto").join("reports").join(session_arg);
    if in_dot_vetto.is_file() {
        return Ok(in_dot_vetto);
    }
    let in_dot_vetto_ext = Path::new(".vetto").join("reports").join(&with_ext);
    if in_dot_vetto_ext.is_file() {
        return Ok(in_dot_vetto_ext);
    }

    Ok(session_arg.to_path_buf())
}

/// Execute the `vetto events` command.
pub fn run_events(
    session_arg: &Path,
    filter_str: Option<&str>,
    follow: bool,
    json_output: bool,
) -> Result<()> {
    let path = resolve_session_path(session_arg)?;
    if !path.exists() {
        anyhow::bail!("session log file '{}' does not exist", path.display());
    }

    let filter = filter_str
        .map(EventTailFilter::parse)
        .unwrap_or(EventTailFilter::All);
    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    let mut printed_header = false;

    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => {
                if !follow {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Ok(_) => {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                // Skip sink metadata line
                if trimmed.contains("\"_vetto\":") {
                    continue;
                }
                if let Ok(event) = serde_json::from_str::<Event>(trimmed) {
                    if filter.matches(&event) {
                        if json_output {
                            println!("{}", serde_json::to_string(&event)?);
                        } else {
                            if !printed_header {
                                println!(
                                    "{:<10}  {:<16}  {:<10}  DETAILS",
                                    "TIME", "EVENT", "TARGET/PID"
                                );
                                println!("{:-<10}  {:-<16}  {:-<10}  {:-<30}", "", "", "", "");
                                printed_header = true;
                            }
                            println!("{}", format_event_row(&event));
                        }
                    }
                }
            }
            Err(e) => {
                if !follow {
                    return Err(e).context("read error");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn filter_matches_correct_events() {
        let blocked = Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1,
            comm: "cat".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        };
        let file_obs = Event::FileObserved {
            ts: Utc::now(),
            pid: 1,
            comm: "python".into(),
            path: "/tmp/foo.py".into(),
            access: FileAccess::Read,
        };
        let net_obs = Event::NetRequest {
            ts: Utc::now(),
            host: "example.com".into(),
            port: 443,
            allowed: true,
        };

        assert!(EventTailFilter::Deny.matches(&blocked));
        assert!(!EventTailFilter::Deny.matches(&file_obs));
        assert!(!EventTailFilter::Deny.matches(&net_obs));

        assert!(EventTailFilter::Files.matches(&file_obs));
        assert!(!EventTailFilter::Files.matches(&net_obs));

        assert!(EventTailFilter::Network.matches(&net_obs));
        assert!(!EventTailFilter::Network.matches(&file_obs));

        let custom = EventTailFilter::Custom("shadow".into());
        assert!(custom.matches(&blocked));
        assert!(!custom.matches(&file_obs));
    }
}
