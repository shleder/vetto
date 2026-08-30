use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Security-relevant event observed during a vetto session.
///
/// NOTE on honesty: `FileObserved` events come from a best-effort /proc
/// poller and MISS sub-100ms opens. `BlockedAttempt` events only appear when
/// an optional observation channel (--observe-seccomp or a readable kernel
/// audit feed) is available. Enforcement NEVER depends on these events.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    SessionStarted {
        ts: DateTime<Utc>,
        pid: u32,
        tier: String,
        net_mode: String,
        profile: String,
    },
    /// An allowed file open observed via the /proc/<pid>/fd poller.
    FileObserved {
        ts: DateTime<Utc>,
        pid: u32,
        comm: String,
        path: String,
        access: FileAccess,
    },
    /// A new process appeared in the sandboxed subtree.
    ExecObserved {
        ts: DateTime<Utc>,
        pid: u32,
        argv: Vec<String>,
    },
    /// A blocked attempt reported by an optional observation channel.
    BlockedAttempt {
        ts: DateTime<Utc>,
        pid: u32,
        comm: String,
        path: String,
        source: String,
    },
    /// CONNECT-level request seen by the allowlist broker.
    NetRequest {
        ts: DateTime<Utc>,
        host: String,
        port: u16,
        allowed: bool,
    },
    /// DNS resolution recorded by the network broker.
    DnsResolved {
        ts: DateTime<Utc>,
        host: String,
        ips: Vec<String>,
    },
    /// Established network connection with transfer counts.
    NetEgress {
        ts: DateTime<Utc>,
        host: String,
        ip: String,
        port: u16,
        bytes_tx: u64,
        bytes_rx: u64,
    },
    /// Network transfer quota exceeded for a domain.
    NetQuotaExceeded {
        ts: DateTime<Utc>,
        host: String,
        limit_bytes: u64,
        used_bytes: u64,
    },
    /// A secret path was masked with a mount overlay (Tier FULL).
    SecretMasked { ts: DateTime<Utc>, path: String },
    /// Honest-notice text surfaced to statusline/doctor/reports.
    Notice { ts: DateTime<Utc>, message: String },
    /// The session exceeded `--timeout` and vetto tore the sandbox down.
    SessionTimeout { ts: DateTime<Utc> },
    SessionEnded {
        ts: DateTime<Utc>,
        exit_code: i32,
        duration_secs: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileAccess {
    Read,
    Write,
    Unknown,
}

impl Event {
    pub fn ts(&self) -> DateTime<Utc> {
        match self {
            Event::SessionStarted { ts, .. }
            | Event::FileObserved { ts, .. }
            | Event::ExecObserved { ts, .. }
            | Event::BlockedAttempt { ts, .. }
            | Event::NetRequest { ts, .. }
            | Event::DnsResolved { ts, .. }
            | Event::NetEgress { ts, .. }
            | Event::NetQuotaExceeded { ts, .. }
            | Event::SecretMasked { ts, .. }
            | Event::Notice { ts, .. }
            | Event::SessionTimeout { ts }
            | Event::SessionEnded { ts, .. } => *ts,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Event::SessionStarted { .. } => "session_started",
            Event::FileObserved { .. } => "file_observed",
            Event::ExecObserved { .. } => "exec_observed",
            Event::BlockedAttempt { .. } => "blocked_attempt",
            Event::NetRequest { .. } => "net_request",
            Event::DnsResolved { .. } => "dns_resolved",
            Event::NetEgress { .. } => "net_egress",
            Event::NetQuotaExceeded { .. } => "net_quota_exceeded",
            Event::SecretMasked { .. } => "secret_masked",
            Event::Notice { .. } => "notice",
            Event::SessionTimeout { .. } => "session_timeout",
            Event::SessionEnded { .. } => "session_ended",
        }
    }

    /// Returns the path associated with a filesystem observation, when the
    /// event carries one.  Keeping this projection here lets the TUI and the
    /// multi-agent aggregator share the exact same event semantics without
    /// duplicating the enum match in each consumer.
    pub fn path(&self) -> Option<&str> {
        match self {
            Event::FileObserved { path, .. }
            | Event::BlockedAttempt { path, .. }
            | Event::SecretMasked { path, .. } => Some(path),
            _ => None,
        }
    }

    /// Returns the network target for a request, when present.
    pub fn network_target(&self) -> Option<(&str, u16, bool)> {
        match self {
            Event::NetRequest {
                host,
                port,
                allowed,
                ..
            } => Some((host, *port, *allowed)),
            _ => None,
        }
    }
}

pub fn now() -> DateTime<Utc> {
    Utc::now()
}
