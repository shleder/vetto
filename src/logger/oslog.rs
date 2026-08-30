//! macOS unified log (`os_log` / `logger`) sink.
//!
//! When `oslog = true` in policy or `--oslog` on CLI, this sink writes
//! sandbox events and Seatbelt denials to the macOS unified log via `/usr/bin/logger`.
//! Logging is best-effort and non-fatal: failures never interrupt or terminate
//! the sandboxed session.

use tokio::sync::broadcast;

use crate::events::{Event, EventBus};

pub struct OsLogSink;

impl OsLogSink {
    /// Spawn the macOS unified log sink thread subscribed to the event bus.
    pub fn spawn(bus: &EventBus) -> std::thread::JoinHandle<()> {
        let rx = bus.subscribe();
        std::thread::Builder::new()
            .name("vetto-oslog".into())
            .spawn(move || sink_loop(rx))
            .expect("spawn oslog sink")
    }
}

fn sink_loop(mut rx: broadcast::Receiver<Event>) {
    while let Ok(ev) = rx.blocking_recv() {
        let msg = match &ev {
            Event::Blocked(b) => {
                format!(
                    "denial: operation={} target={} reason={}",
                    b.operation, b.target, b.reason
                )
            }
            Event::Warning(w) => {
                format!("warning: {}", w.message)
            }
            Event::Spawned(s) => {
                format!("session spawned: pid={} tier={}", s.pid, s.tier)
            }
            Event::Exited(e) => {
                format!("session exited: exit_code={}", e.exit_code)
            }
            _ => format!("{:?}", ev),
        };
        log_to_system(&msg);
    }
}

/// Log a message to macOS unified log via `/usr/bin/logger`.
/// Best-effort: errors are ignored and never fail the session.
pub fn log_to_system(message: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("/usr/bin/logger")
            .arg("-i")
            .arg("-s")
            .arg("-t")
            .arg("vetto")
            .arg(message)
            .output();
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = message;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_to_system_never_panics() {
        log_to_system("vetto test message");
    }
}
