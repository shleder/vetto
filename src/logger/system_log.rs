//! System logging integration (Linux journald, Windows EventLog, macOS logger).
//!
//! Opt-in via `system_log = true` in config/policy or `--system-log`.
//! Any error in system logging is handled fail-open and never crashes or aborts the session.

use std::sync::Arc;
use tokio::sync::broadcast::Receiver;

use crate::events::{Event, EventBus};

pub struct SystemLogSink;

impl SystemLogSink {
    /// Spawn background task forwarding events to system journal.
    pub fn spawn(bus: &EventBus) {
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            run_listener(&mut rx).await;
        });
    }
}

async fn run_listener(rx: &mut Receiver<Arc<Event>>) {
    while let Ok(event) = rx.recv().await {
        let line = format_event_for_system_log(&event);
        log_to_system(&line);
    }
}

/// Format an event into a single-line summary for system logs.
pub fn format_event_for_system_log(event: &Event) -> String {
    match event {
        Event::SessionStarted {
            ts,
            pid,
            tier,
            net_mode,
            profile,
        } => {
            format!("VETTO_SESSION_START ts={ts} pid={pid} tier={tier} net={net_mode} profile={profile}")
        }
        Event::SessionEnded {
            ts,
            exit_code,
            duration_secs,
        } => {
            format!("VETTO_SESSION_END ts={ts} exit_code={exit_code} duration_s={duration_secs}")
        }
        Event::BlockedAttempt {
            ts,
            path,
            operation,
            agent_cmd,
        } => {
            format!("VETTO_BLOCKED_ATTEMPT ts={ts} path={path} op={operation} cmd={agent_cmd}")
        }
        Event::SecretMasked { ts, path } => {
            format!("VETTO_SECRET_MASKED ts={ts} path={path}")
        }
        Event::Notice { ts, message } => {
            format!("VETTO_NOTICE ts={ts} msg={message}")
        }
        Event::SessionTimeout { ts } => {
            format!("VETTO_SESSION_TIMEOUT ts={ts}")
        }
        _ => format!(
            "VETTO_EVENT ts={} desc={}",
            event.timestamp(),
            event.describe()
        ),
    }
}

/// Dispatch log line to platform system logger without failing on error.
pub fn log_to_system(message: &str) {
    #[cfg(target_os = "linux")]
    {
        log_linux(message);
    }
    #[cfg(target_os = "macos")]
    {
        log_macos(message);
    }
    #[cfg(target_os = "windows")]
    {
        log_windows(message);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = message;
    }
}

#[cfg(target_os = "linux")]
fn log_linux(message: &str) {
    use std::os::unix::net::UnixDatagram;

    // Try direct journald socket first
    let socket_path = "/run/systemd/journal/socket";
    if std::path::Path::new(socket_path).exists() {
        if let Ok(sock) = UnixDatagram::unbound() {
            let payload = format!("MESSAGE={message}\nPRIORITY=6\nSYSLOG_IDENTIFIER=vetto\n\n");
            if sock.send_to(payload.as_bytes(), socket_path).is_ok() {
                return;
            }
        }
    }

    // Fallback to logger command
    let _ = std::process::Command::new("logger")
        .args(["-t", "vetto", message])
        .output();
}

#[cfg(target_os = "macos")]
fn log_macos(message: &str) {
    let _ = std::process::Command::new("logger")
        .args(["-t", "vetto", "-s", message])
        .output();
}

#[cfg(target_os = "windows")]
fn log_windows(message: &str) {
    let _ = std::process::Command::new("eventcreate")
        .args([
            "/L",
            "APPLICATION",
            "/T",
            "INFORMATION",
            "/ID",
            "1",
            "/SO",
            "Vetto",
            "/D",
            message,
        ])
        .output();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_events_correctly() {
        let ev = Event::Notice {
            ts: "2026-08-30T12:00:00Z".into(),
            message: "test notice".into(),
        };
        let line = format_event_for_system_log(&ev);
        assert!(line.contains("VETTO_NOTICE"));
        assert!(line.contains("test notice"));
    }

    #[test]
    fn log_to_system_does_not_panic() {
        log_to_system("test message safe");
    }
}
