//! Session statistics collector: a bus subscriber thread aggregating counts
//! and interesting records for the post-session reports.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::events::{Event, EventBus, FileAccess};

/// Event streams are attacker-influenced. Keep unique path/subject keys
/// bounded so a noisy process cannot turn reporting into an unbounded-memory
/// sink. Repeated keys continue to aggregate after the cap is reached.
const MAX_DISTINCT_RECORDS: usize = 4_096;

#[derive(Debug, Clone, Serialize)]
pub struct BlockedRecord {
    pub path: String,
    pub comm: String,
    pub source: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetRecord {
    pub host: String,
    pub port: u16,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuspiciousRecord {
    pub category: String,
    pub severity: String,
    pub subject: String,
    pub reason: String,
    pub count: u64,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SessionStats {
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_secs: u64,
    pub exit_code: i32,
    pub tier: String,
    pub net_mode: String,
    pub profile: String,
    pub events_total: u64,
    pub counts: BTreeMap<String, u64>,
    pub op_counts: BTreeMap<String, u64>,
    pub file_reads: u64,
    pub file_writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub blocked_attempts: Vec<BlockedRecord>,
    pub net_requests: Vec<NetRecord>,
    /// Best-effort audit hints. These records never affect enforcement.
    pub suspicious_signals: Vec<SuspiciousRecord>,
    pub notices: Vec<String>,
}

impl SessionStats {
    pub fn io_summary(&self) -> String {
        format!(
            "read {} bytes ({} ops), written {} bytes ({} ops)",
            self.bytes_read, self.read_ops, self.bytes_written, self.write_ops
        )
    }
}

#[derive(Default)]
struct Inner {
    stats: SessionStats,
    blocked: BTreeMap<(String, String, String), u64>, // (path, comm, source)
    suspicious: BTreeMap<(String, String, String, String), u64>,
}

pub struct StatsCollector {
    inner: Arc<Mutex<Inner>>,
}

impl StatsCollector {
    /// Spawn the collector thread (subscribes immediately).
    pub fn spawn(bus: &EventBus) -> Self {
        let rx = bus.subscribe();
        let inner = Arc::new(Mutex::new(Inner::default()));
        let thread_inner = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("vetto-stats".into())
            .spawn(move || collect_loop(rx, thread_inner))
            .expect("spawn stats collector");
        Self { inner }
    }

    /// Snapshot; blocked attempts are aggregated and sorted by count.
    pub fn snapshot(&self) -> SessionStats {
        let Ok(inner) = self.inner.lock() else {
            return SessionStats::default();
        };
        let mut stats = inner.stats.clone();
        let mut blocked: Vec<BlockedRecord> = inner
            .blocked
            .iter()
            .map(|((path, comm, source), count)| BlockedRecord {
                path: path.clone(),
                comm: comm.clone(),
                source: source.clone(),
                count: *count,
            })
            .collect();
        blocked.sort_by(|a, b| b.count.cmp(&a.count).then(a.path.cmp(&b.path)));
        stats.blocked_attempts = blocked;
        let mut suspicious: Vec<SuspiciousRecord> = inner
            .suspicious
            .iter()
            .map(
                |((category, severity, subject, reason), count)| SuspiciousRecord {
                    category: category.clone(),
                    severity: severity.clone(),
                    subject: subject.clone(),
                    reason: reason.clone(),
                    count: *count,
                },
            )
            .collect();
        suspicious.sort_by(|a, b| {
            b.count
                .cmp(&a.count)
                .then(a.category.cmp(&b.category))
                .then(a.subject.cmp(&b.subject))
        });
        stats.suspicious_signals = suspicious;
        stats
    }
}

fn collect_loop(mut rx: broadcast::Receiver<Event>, inner: Arc<Mutex<Inner>>) {
    loop {
        match rx.blocking_recv() {
            Ok(ev) => {
                let Ok(mut inner) = inner.lock() else { break };
                ingest(&mut inner, ev);
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn ingest(inner: &mut Inner, ev: Event) {
    if let Some(signal) = crate::classifier::classify_event(&ev) {
        let key = (
            signal.category.to_string(),
            signal.severity.label().to_string(),
            signal.subject,
            signal.reason.to_string(),
        );
        if inner.suspicious.contains_key(&key) || inner.suspicious.len() < MAX_DISTINCT_RECORDS {
            *inner.suspicious.entry(key).or_insert(0) += 1;
        }
    }
    let st = &mut inner.stats;
    st.events_total += 1;
    *st.counts.entry(ev.kind().to_string()).or_insert(0) += 1;
    match ev {
        Event::SessionStarted {
            ts,
            tier,
            net_mode,
            profile,
            ..
        } => {
            st.started_at = Some(ts);
            st.tier = tier;
            st.net_mode = net_mode;
            st.profile = profile;
        }
        Event::SessionEnded {
            ts,
            exit_code,
            duration_secs,
        } => {
            st.ended_at = Some(ts);
            st.exit_code = exit_code;
            st.duration_secs = duration_secs;
        }
        Event::FileObserved {
            ref path, access, ..
        } => {
            // fd-derived access beats extension heuristics when available.
            let op = match access {
                FileAccess::Write => crate::classifier::Operation::FsWrite,
                FileAccess::Read => crate::classifier::classify_path(path),
                FileAccess::Unknown => crate::classifier::classify_path(path),
            };
            *st.op_counts.entry(op.label().to_string()).or_insert(0) += 1;
            let file_size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            match access {
                FileAccess::Read => {
                    st.file_reads += 1;
                    st.read_ops += 1;
                    st.bytes_read += file_size;
                }
                FileAccess::Write => {
                    st.file_writes += 1;
                    st.write_ops += 1;
                    st.bytes_written += file_size;
                }
                FileAccess::Unknown => {}
            }
        }
        Event::BlockedAttempt {
            path, comm, source, ..
        } => {
            let key = (path, comm, source);
            if inner.blocked.contains_key(&key) || inner.blocked.len() < MAX_DISTINCT_RECORDS {
                *inner.blocked.entry(key).or_insert(0) += 1;
            }
        }
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            *st.op_counts
                .entry(crate::classifier::Operation::Net.label().to_string())
                .or_insert(0) += 1;
            if st.net_requests.len() < 500 {
                st.net_requests.push(NetRecord {
                    host,
                    port,
                    allowed,
                });
            }
        }
        Event::Notice { message, .. } => {
            *st.op_counts
                .entry(crate::classifier::Operation::Other.label().to_string())
                .or_insert(0) += 1;
            if st.notices.len() < 100 {
                st.notices.push(message);
            }
        }
        // SessionTimeout is a session-level marker: it is counted into
        // events_total and counts["session_timeout"] above like every event;
        // it carries no per-operation data of its own.
        Event::ExecObserved { .. } | Event::SecretMasked { .. } | Event::SessionTimeout { .. } => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::types::now;

    #[test]
    fn attacker_controlled_record_keys_are_bounded_but_repeats_aggregate() {
        let mut inner = Inner::default();
        for index in 0..(MAX_DISTINCT_RECORDS + 32) {
            ingest(
                &mut inner,
                Event::BlockedAttempt {
                    ts: now(),
                    pid: 1,
                    comm: "agent".into(),
                    path: format!("/tmp/path-{index}"),
                    source: "test".into(),
                },
            );
        }
        assert_eq!(inner.blocked.len(), MAX_DISTINCT_RECORDS);

        for _ in 0..3 {
            ingest(
                &mut inner,
                Event::BlockedAttempt {
                    ts: now(),
                    pid: 1,
                    comm: "agent".into(),
                    path: "/tmp/path-0".into(),
                    source: "test".into(),
                },
            );
        }
        assert_eq!(
            inner
                .blocked
                .get(&("/tmp/path-0".into(), "agent".into(), "test".into()))
                .copied(),
            Some(4)
        );

        for index in 0..(MAX_DISTINCT_RECORDS + 32) {
            ingest(
                &mut inner,
                Event::FileObserved {
                    ts: now(),
                    pid: 1,
                    comm: "agent".into(),
                    path: format!("/tmp/.env.{index}"),
                    access: FileAccess::Read,
                },
            );
        }
        assert_eq!(inner.suspicious.len(), MAX_DISTINCT_RECORDS);
    }
}
