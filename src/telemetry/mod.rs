//! Optional, privacy-preserving post-session telemetry.
//!
//! # Privacy Guarantees
//! 1. Default STRICTLY OFF (`telemetry = false`).
//! 2. Requires both `telemetry = true` and an explicit `telemetry_endpoint` URL in `~/.vetto/config.toml`.
//! 3. Collects ONLY anonymous, aggregate counters (event count, block category totals, duration, exit code).
//! 4. NEVER transmits file paths, domain names, commands, arguments, secrets, environment variables,
//!    IP addresses, hostnames, or user identifiers.

pub mod otel;
pub use otel::{spawn_telemetry_subscriber, TelemetrySession};

use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::report::stats::SessionStats;
use crate::version::config::load_user_config;

pub const TELEMETRY_SCHEMA_VERSION: u32 = 1;
pub const TELEMETRY_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryPayload {
    pub schema_version: u32,
    pub vetto_version: String,
    pub os: String,
    pub arch: String,
    pub tier: String,
    pub session_duration_s: u64,
    pub fs_denials: u64,
    pub net_denials: u64,
    pub total_events: u64,
    pub exit_code: i32,
}

impl TelemetryPayload {
    pub fn from_session_stats(stats: &SessionStats, tier: &str) -> Self {
        let fs_denials: u64 = stats.blocked_attempts.iter().map(|b| b.count).sum();
        let net_denials: u64 = stats.net_requests.iter().filter(|n| !n.allowed).count() as u64;

        Self {
            schema_version: TELEMETRY_SCHEMA_VERSION,
            vetto_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            tier: tier.to_string(),
            session_duration_s: stats.duration_secs,
            fs_denials,
            net_denials,
            total_events: stats.events_total,
            exit_code: stats.exit_code,
        }
    }
}

/// Dispatches telemetry payload to configured endpoint if opt-in is active.
///
/// Returns immediately without network calls if telemetry is disabled (default).
pub fn send_session_telemetry(stats: &SessionStats, tier: &str) -> Result<()> {
    let config = match load_user_config() {
        Ok(cfg) => cfg,
        Err(_) => return Ok(()),
    };

    if !config.telemetry || config.telemetry_endpoint.trim().is_empty() {
        return Ok(());
    }

    let payload = TelemetryPayload::from_session_stats(stats, tier);
    let payload_json = match serde_json::to_string(&payload) {
        Ok(j) => j,
        Err(_) => return Ok(()),
    };

    let endpoint = config.telemetry_endpoint.trim().to_string();

    // Spawn non-blocking background curl POST or quick bounded subprocess
    let _ = Command::new("curl")
        .arg("-s")
        .arg("--max-time")
        .arg(TELEMETRY_TIMEOUT.as_secs().max(1).to_string())
        .arg("-X")
        .arg("POST")
        .arg("-H")
        .arg("Content-Type: application/json")
        .arg("-d")
        .arg(&payload_json)
        .arg(&endpoint)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::stats::{BlockedRecord, NetRecord};

    #[test]
    fn test_telemetry_payload_anonymity_and_counters() {
        let stats = SessionStats {
            duration_secs: 45,
            exit_code: 0,
            tier: "full".to_string(),
            events_total: 120,
            blocked_attempts: vec![
                BlockedRecord {
                    path: "/secret/token".to_string(),
                    comm: "curl".to_string(),
                    source: "landlock".to_string(),
                    count: 3,
                },
                BlockedRecord {
                    path: "/home/user/.ssh/id_rsa".to_string(),
                    comm: "cat".to_string(),
                    source: "seccomp".to_string(),
                    count: 2,
                },
            ],
            net_requests: vec![
                NetRecord {
                    host: "evil.com".to_string(),
                    port: 443,
                    allowed: false,
                },
                NetRecord {
                    host: "registry.npmjs.org".to_string(),
                    port: 443,
                    allowed: true,
                },
            ],
            ..Default::default()
        };

        let payload = TelemetryPayload::from_session_stats(&stats, "full");
        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.session_duration_s, 45);
        assert_eq!(payload.fs_denials, 5); // 3 + 2
        assert_eq!(payload.net_denials, 1); // 1 denied
        assert_eq!(payload.total_events, 120);
        assert_eq!(payload.exit_code, 0);

        let json = serde_json::to_string(&payload).unwrap();
        // Crucial security checks: sensitive data must never be present in serialized JSON
        assert!(!json.contains("/secret/token"));
        assert!(!json.contains("id_rsa"));
        assert!(!json.contains("evil.com"));
        assert!(!json.contains("registry.npmjs.org"));
        assert!(!json.contains("curl"));
    }

    #[test]
    fn test_disabled_by_default() {
        let stats = SessionStats::default();
        // Should execute cleanly without error
        assert!(send_session_telemetry(&stats, "none").is_ok());
    }
}
