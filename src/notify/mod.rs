//! Desktop notifications on security violations (Feature 41).
//!
//! When enabled via `notify = true` or `--notify`, serious violations
//! (blocked path access, denied network request) trigger a platform-native desktop notification:
//! - Linux: `notify-send`
//! - macOS: `osascript`
//! - Windows: PowerShell toast
//!
//! Subprocesses are executed asynchronously and errors are ignored (fail-open for notifications),
//! ensuring notification subsystem failures NEVER crash or disrupt the sandboxed session.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::events::{Event, EventBus};

/// Minimum interval between notifications to prevent alert storms (1 second).
const MIN_NOTIFICATION_INTERVAL_MILLIS: u64 = 1000;

#[derive(Clone)]
pub struct DesktopNotifier {
    enabled: bool,
    last_notified_millis: Arc<AtomicU64>,
}

impl DesktopNotifier {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            last_notified_millis: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Dispatch a desktop notification if enabled and rate limit allows.
    pub fn notify(&self, title: &str, message: &str) {
        if !self.enabled {
            return;
        }

        let now_millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let prev = self.last_notified_millis.load(Ordering::Relaxed);
        if now_millis.saturating_sub(prev) < MIN_NOTIFICATION_INTERVAL_MILLIS {
            return;
        }
        self.last_notified_millis
            .store(now_millis, Ordering::Relaxed);

        let title_owned = title.to_string();
        let message_owned = message.to_string();

        // Dispatch in a separate thread so notification spawning is non-blocking
        std::thread::Builder::new()
            .name("vetto-notify".into())
            .spawn(move || {
                let _ = send_platform_notification(&title_owned, &message_owned);
            })
            .ok();
    }

    /// Check an incoming event and notify on serious violations.
    pub fn handle_event(&self, event: &Event) {
        if !self.enabled {
            return;
        }

        match event {
            Event::BlockedAttempt {
                comm, path, source, ..
            } => {
                let title = "vetto: blocked access";
                let message = format!("Process '{comm}' blocked accessing '{path}' ({source})");
                self.notify(title, &message);
            }
            Event::NetRequest {
                host,
                port,
                allowed: false,
                ..
            } => {
                let title = "vetto: network escape blocked";
                let message = format!("Blocked outbound connection to {host}:{port}");
                self.notify(title, &message);
            }
            _ => {}
        }
    }

    /// Spawn an event bus subscriber for notifications.
    pub fn spawn(bus: &EventBus, enabled: bool) -> std::thread::JoinHandle<()> {
        let notifier = Self::new(enabled);
        let mut rx = bus.subscribe();
        std::thread::Builder::new()
            .name("vetto-notifier-sink".into())
            .spawn(move || loop {
                match rx.blocking_recv() {
                    Ok(event) => {
                        notifier.handle_event(&event);
                        if matches!(event, Event::SessionEnded { .. }) {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            })
            .expect("spawn notifier sink")
    }
}

/// Platform-specific notification runner. Errors are deliberately ignored.
fn send_platform_notification(title: &str, message: &str) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut child = std::process::Command::new("notify-send")
            .arg("-u")
            .arg("critical")
            .arg("-a")
            .arg("vetto")
            .arg(title)
            .arg(message)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let _ = child.wait();
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            escape_applescript(message),
            escape_applescript(title)
        );
        let mut child = std::process::Command::new("osascript")
            .arg("-e")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let _ = child.wait();
        Ok(())
    }

    #[cfg(target_os = "windows")]
    {
        let script = format!(
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; \
             $template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); \
             $textNodes = $template.GetElementsByTagName('text'); \
             $textNodes.Item(0).AppendChild($template.CreateTextNode('{}')) > $null; \
             $textNodes.Item(1).AppendChild($template.CreateTextNode('{}')) > $null; \
             $notifier = [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('vetto'); \
             $notification = [Windows.UI.Notifications.ToastNotification]::new($template); \
             $notifier.Show($notification);",
            escape_powershell(title),
            escape_powershell(message)
        );
        let mut child = std::process::Command::new("powershell")
            .arg("-NoProfile")
            .arg("-Command")
            .arg(&script)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()?;
        let _ = child.wait();
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = (title, message);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(target_os = "windows")]
fn escape_powershell(s: &str) -> String {
    s.replace('\'', "''").replace('"', "`\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::now;

    #[test]
    fn disabled_notifier_does_not_fire() {
        let notifier = DesktopNotifier::new(false);
        assert!(!notifier.is_enabled());
        notifier.notify("test", "message");
        notifier.handle_event(&Event::BlockedAttempt {
            ts: now(),
            pid: 1,
            comm: "sh".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        });
    }

    #[test]
    fn enabled_notifier_handles_events() {
        let notifier = DesktopNotifier::new(true);
        assert!(notifier.is_enabled());
        notifier.handle_event(&Event::BlockedAttempt {
            ts: now(),
            pid: 1,
            comm: "sh".into(),
            path: "/etc/shadow".into(),
            source: "landlock".into(),
        });
        notifier.handle_event(&Event::NetRequest {
            ts: now(),
            host: "evil.com".into(),
            port: 443,
            allowed: false,
        });
        // Non-violation events should not trigger
        notifier.handle_event(&Event::NetRequest {
            ts: now(),
            host: "crates.io".into(),
            port: 443,
            allowed: true,
        });
    }
}
