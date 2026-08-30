//! Sandbox session event replay (`vetto replay <session>`) (Feature 45).
//!
//! Replays the chronological sequence of sandbox observation and security enforcement
//! events from a session JSONL log with optional speed-scaling (`--speed 1.0` for real-time).
//!
//! NOTE: This replays sandbox events (file opens, network connections, blocked attempts,
//! process spawns), NOT interactive user terminal keystrokes.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

use super::tail::resolve_session_path;
use super::types::{Event, FileAccess};

pub fn run_replay(session_arg: &Path, speed: Option<f64>, json_output: bool) -> Result<()> {
    let path = resolve_session_path(session_arg)?;
    if !path.exists() {
        anyhow::bail!("session log file '{}' does not exist", path.display());
    }

    let file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut events = Vec::new();
    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.contains("\"_vetto\":") {
            continue;
        }
        if let Ok(event) = serde_json::from_str::<Event>(trimmed) {
            events.push(event);
        }
    }

    if events.is_empty() {
        println!("No recorded events found in {}.", path.display());
        return Ok(());
    }

    // Sort by timestamp
    events.sort_by_key(|e| e.ts());

    let speed_factor = speed.unwrap_or(0.0);
    let start_ts = events[0].ts();
    let mut prev_ts = start_ts;

    if !json_output {
        println!("=== vetto sandbox session replay: {} ===", path.display());
        println!(
            "Events: {} | Speed: {}",
            events.len(),
            if speed_factor > 0.0 {
                format!("{speed_factor}x")
            } else {
                "instant".into()
            }
        );
        println!("NOTE: Replaying sandbox security & observation telemetry, not terminal input.\n");
        println!(
            "{:<12}  {:<8}  {:<16}  {}",
            "OFFSET", "DELTA", "EVENT", "DETAILS"
        );
        println!("{:-<12}  {:-<8}  {:-<16}  {:-<40}", "", "", "", "");
    }

    for event in &events {
        let cur_ts = event.ts();
        let offset_ms = cur_ts
            .signed_duration_since(start_ts)
            .num_milliseconds()
            .max(0);
        let delta_ms = cur_ts
            .signed_duration_since(prev_ts)
            .num_milliseconds()
            .max(0);

        if speed_factor > 0.0 && delta_ms > 0 {
            let sleep_ms = ((delta_ms as f64) / speed_factor).min(5000.0) as u64;
            if sleep_ms > 0 {
                std::thread::sleep(Duration::from_millis(sleep_ms));
            }
        }
        prev_ts = cur_ts;

        if json_output {
            println!("{}", serde_json::to_string(event)?);
        } else {
            let offset_str = format_millis_offset(offset_ms as u64);
            let delta_str = format!("+{:.3}s", (delta_ms as f64) / 1000.0);
            let kind = event.kind();
            let details = describe_replay_event(event);
            println!(
                "{:<12}  {:<8}  {:<16}  {}",
                offset_str, delta_str, kind, details
            );
        }
    }

    if !json_output {
        println!("\n=== Replay complete ===");
    }

    Ok(())
}

fn format_millis_offset(ms: u64) -> String {
    let total_secs = ms / 1000;
    let millis = ms % 1000;
    let mins = total_secs / 60;
    let secs = total_secs % 60;
    format!("{mins:02}:{secs:02}.{millis:03}")
}

fn describe_replay_event(event: &Event) -> String {
    match event {
        Event::SessionStarted {
            pid,
            tier,
            net_mode,
            profile,
            ..
        } => {
            format!("pid={pid} tier={tier} net={net_mode} profile={profile}")
        }
        Event::SessionEnded {
            exit_code,
            duration_secs,
            ..
        } => {
            format!("exit_code={exit_code} duration={duration_secs}s")
        }
        Event::FileObserved {
            comm,
            pid,
            path,
            access,
            ..
        } => {
            let acc = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!("{comm}[{pid}] {acc} {path}")
        }
        Event::ExecObserved { pid, argv, .. } => {
            format!("pid={pid} exec: {}", argv.join(" "))
        }
        Event::BlockedAttempt {
            comm,
            pid,
            path,
            source,
            ..
        } => {
            format!("{comm}[{pid}] BLOCKED '{path}' via {source}")
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            format!(
                "{}:{} -> {}",
                host,
                port,
                if *allowed { "ALLOW" } else { "DENIED" }
            )
        }
        Event::SecretMasked { path, .. } => {
            format!("masked secret mount: {path}")
        }
        Event::Notice { message, .. } => message.clone(),
        Event::SessionTimeout { .. } => "session deadline reached, sandbox torn down".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn format_millis_offset_renders_correctly() {
        assert_eq!(format_millis_offset(0), "00:00.000");
        assert_eq!(format_millis_offset(1500), "00:01.500");
        assert_eq!(format_millis_offset(65432), "01:05.432");
    }

    #[test]
    fn describe_replay_event_formats_all_types() {
        let blocked = Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 42,
            comm: "cat".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        };
        let desc = describe_replay_event(&blocked);
        assert!(desc.contains("BLOCKED"));
        assert!(desc.contains("/etc/shadow"));
    }
}
