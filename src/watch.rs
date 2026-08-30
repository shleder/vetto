//! Watch Mode (Feature 35).
//!
//! Live tailing of session events from JSONL log files with optional path filtering.

use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use crate::events::Event;

/// Resolves the JSONL file path from a session PID or a direct file path.
pub fn resolve_log_path(target: &str) -> Result<PathBuf> {
    let direct_path = Path::new(target);
    if direct_path.is_file() {
        return Ok(direct_path.to_path_buf());
    }

    // Try finding by PID in common report directories
    if let Ok(pid) = target.parse::<u32>() {
        let candidates = [
            PathBuf::from(".vetto/reports"),
            PathBuf::from(".vetto"),
            std::env::temp_dir(),
        ];

        for base in candidates {
            if let Ok(entries) = std::fs::read_dir(base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".jsonl")
                        && (name.contains(&format!("-{pid}-"))
                            || name.contains(&format!("_{pid}_"))
                            || name.contains(&pid.to_string()))
                    {
                        return Ok(path);
                    }
                }
            }
        }
    }

    bail!("could not locate JSONL log file for target '{target}'")
}

/// Formats an event for console presentation in watch mode.
pub fn format_event(event: &Event) -> String {
    let ts = event.ts().format("%H:%M:%S%.3f");
    let _kind = event.kind();

    match event {
        Event::SessionStarted {
            pid,
            tier,
            net_mode,
            profile,
            ..
        } => {
            format!("[{ts}] SESSION_STARTED pid={pid} tier={tier} net={net_mode} profile={profile}")
        }
        Event::FileObserved {
            pid,
            comm,
            path,
            access,
            ..
        } => {
            format!("[{ts}] FILE_OBSERVED   pid={pid} comm={comm} access={access:?} path={path}")
        }
        Event::ExecObserved { pid, argv, .. } => {
            format!("[{ts}] EXEC_OBSERVED   pid={pid} argv={:?}", argv)
        }
        Event::BlockedAttempt {
            pid,
            comm,
            path,
            source,
            ..
        } => {
            format!("[{ts}] BLOCKED_ATTEMPT pid={pid} comm={comm} src={source} path={path}")
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            let status = if *allowed { "ALLOWED" } else { "DENIED" };
            format!("[{ts}] NET_REQUEST     host={host}:{port} status={status}")
        }
        Event::DnsResolved { host, ips, .. } => {
            format!("[{ts}] DNS_RESOLVED   host={host} ips={:?}", ips)
        }
        Event::NetEgress {
            host,
            ip,
            port,
            bytes_tx,
            bytes_rx,
            ..
        } => {
            format!("[{ts}] NET_EGRESS     host={host} ip={ip}:{port} tx={bytes_tx} rx={bytes_rx}")
        }
        Event::NetQuotaExceeded {
            host,
            limit_bytes,
            used_bytes,
            ..
        } => {
            format!(
                "[{ts}] NET_QUOTA      host={host} exceeded limit={limit_bytes} used={used_bytes}"
            )
        }
        Event::SecretMasked { path, .. } => {
            format!("[{ts}] SECRET_MASKED   path={path}")
        }
        Event::Notice { message, .. } => {
            format!("[{ts}] NOTICE          message={message}")
        }
        Event::SessionTimeout { .. } => {
            format!("[{ts}] SESSION_TIMEOUT session terminated due to deadline")
        }
        Event::SessionEnded {
            exit_code,
            duration_secs,
            ..
        } => {
            format!("[{ts}] SESSION_ENDED   exit_code={exit_code} duration={duration_secs}s")
        }
    }
}

/// Runs the watch mode live tail.
pub fn run_watch(target: &str, filter_path: Option<&str>, json_mode: bool) -> Result<()> {
    let log_path = resolve_log_path(target)?;
    println!("vetto watch: following log {}", log_path.display());

    let mut file = File::open(&log_path)
        .with_context(|| format!("failed to open log file {}", log_path.display()))?;

    // Start from beginning
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BufReader::new(file);

    let mut line = String::new();
    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            // EOF reached: wait for new data
            sleep(Duration::from_millis(100));
            continue;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: Result<Event, _> = serde_json::from_str(trimmed);
        match event {
            Ok(ev) => {
                if let Some(pattern) = filter_path {
                    if let Some(ev_path) = ev.path() {
                        if !ev_path.contains(pattern) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }

                if json_mode {
                    println!("{trimmed}");
                } else {
                    println!("{}", format_event(&ev));
                }
            }
            Err(_) => {
                if !json_mode {
                    println!("[raw] {trimmed}");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::{now, FileAccess};

    #[test]
    fn formats_events_cleanly() {
        let ev = Event::FileObserved {
            ts: now(),
            pid: 1234,
            comm: "node".into(),
            path: "/tmp/app.js".into(),
            access: FileAccess::Read,
        };

        let formatted = format_event(&ev);
        assert!(formatted.contains("FILE_OBSERVED"));
        assert!(formatted.contains("pid=1234"));
        assert!(formatted.contains("comm=node"));
        assert!(formatted.contains("/tmp/app.js"));
    }
}
