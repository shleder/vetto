//! Session statistics collector: a bus subscriber thread aggregating counts
//! and interesting records for the post-session reports.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DnsRecord {
    pub host: String,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EgressRecord {
    pub host: String,
    pub ip: String,
    pub port: u16,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

#[derive(Debug, Clone, Default, Serialize, serde::Deserialize)]
pub struct DomainStats {
    pub requests: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DomainTransferStats {
    pub requests: u64,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
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

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct IoMetrics {
    pub file_reads: u64,
    pub file_writes: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub files_created: u64,
    pub files_modified: u64,
    pub files_deleted: u64,
}

pub struct SessionStats {
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub duration_secs: u64,
    pub exit_code: i32,
    pub tier: String,
    pub net_mode: String,
    pub profile: String,
    pub events_total: u64,
    pub io_metrics: IoMetrics,
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
    pub dns_resolutions: Vec<DnsRecord>,
    pub egress_connections: Vec<EgressRecord>,
    pub network_summary: BTreeMap<String, DomainStats>,
    pub total_egress_bytes_tx: u64,
    pub total_egress_bytes_rx: u64,
    pub domain_egress: std::collections::HashMap<String, DomainTransferStats>,
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
        Event::DnsResolved { host, ips, .. } => {
            *st.op_counts
                .entry(crate::classifier::Operation::Net.label().to_string())
                .or_insert(0) += 1;
            if st.dns_resolutions.len() < 500 {
                st.dns_resolutions.push(DnsRecord { host, ips });
            }
        }
        Event::NetEgress {
            host,
            ip,
            port,
            bytes_tx,
            bytes_rx,
            ..
        } => {
            *st.op_counts
                .entry(crate::classifier::Operation::Net.label().to_string())
                .or_insert(0) += 1;
            st.total_egress_bytes_tx += bytes_tx;
            st.total_egress_bytes_rx += bytes_rx;
            let domain_stat = st.domain_egress.entry(host.clone()).or_default();
            domain_stat.requests += 1;
            domain_stat.bytes_tx += bytes_tx;
            domain_stat.bytes_rx += bytes_rx;
            let summary = st.network_summary.entry(host.clone()).or_default();
            summary.requests += 1;
            summary.bytes_tx += bytes_tx;
            summary.bytes_rx += bytes_rx;
            if st.egress_connections.len() < 500 {
                st.egress_connections.push(EgressRecord {
                    host,
                    ip,
                    port,
                    bytes_tx,
                    bytes_rx,
                });
            }
        }
        Event::NetQuotaExceeded {
            host,
            limit_bytes,
            used_bytes,
            ..
        } => {
            *st.op_counts
                .entry(crate::classifier::Operation::Net.label().to_string())
                .or_insert(0) += 1;
            let msg =
                format!("network quota exceeded for {host}: {used_bytes}/{limit_bytes} bytes");
            if st.notices.len() < 100 {
                st.notices.push(msg);
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
        
        Event::FsMutation { mutation, bytes, .. } => {
            let io = &mut st.io_metrics;
            if mutation == "read" {
                io.file_reads += 1;
                if let Some(b) = bytes {
                    io.bytes_read += b;
                }
            } else {
                io.file_writes += 1;
                match mutation.as_str() {
                    "create" => io.files_created += 1,
                    "modify" => io.files_modified += 1,
                    "delete" | "unlink" => io.files_deleted += 1,
                    _ => {}
                }
                if let Some(b) = bytes {
                    io.bytes_written += b;
                }
            }
        }
        Event::ExecObserved { .. } | Event::SecretMasked { .. } | Event::SessionTimeout { .. } => {}
    }
}

#[cfg(test)]
mod tests {

    #[test]
    fn fs_mutation_aggregates_io_metrics() {
        let mut inner = Inner::default();
        ingest(
            &mut inner,
            Event::FsMutation {
                ts: now(),
                path: "/tmp/new".into(),
                mutation: "create".into(),
                bytes: Some(1024),
            },
        );
        ingest(
            &mut inner,
            Event::FsMutation {
                ts: now(),
                path: "/tmp/mod".into(),
                mutation: "modify".into(),
                bytes: Some(512),
            },
        );
        ingest(
            &mut inner,
            Event::FsMutation {
                ts: now(),
                path: "/tmp/del".into(),
                mutation: "delete".into(),
                bytes: None,
            },
        );
        
        let io = &inner.stats.io_metrics;
        assert_eq!(io.files_created, 1);
        assert_eq!(io.files_modified, 1);
        assert_eq!(io.files_deleted, 1);
        assert_eq!(io.file_writes, 3);
        assert_eq!(io.bytes_written, 1536);
    }

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

    #[test]
    fn net_egress_aggregates_totals_and_per_domain_stats() {
        let mut inner = Inner::default();

        ingest(
            &mut inner,
            Event::NetEgress {
                ts: now(),
                host: "api.anthropic.com".into(),
                ip: "104.18.2.1".into(),
                port: 443,
                bytes_tx: 100,
                bytes_rx: 500,
            },
        );

        ingest(
            &mut inner,
            Event::NetEgress {
                ts: now(),
                host: "api.anthropic.com".into(),
                ip: "104.18.2.2".into(),
                port: 443,
                bytes_tx: 200,
                bytes_rx: 700,
            },
        );

        ingest(
            &mut inner,
            Event::NetEgress {
                ts: now(),
                host: "crates.io".into(),
                ip: "151.101.1.6".into(),
                port: 443,
                bytes_tx: 50,
                bytes_rx: 250,
            },
        );

        let st = &inner.stats;
        assert_eq!(st.total_egress_bytes_tx, 350);
        assert_eq!(st.total_egress_bytes_rx, 1450);

        assert_eq!(
            st.domain_egress.get("api.anthropic.com"),
            Some(&DomainTransferStats {
                requests: 2,
                bytes_tx: 300,
                bytes_rx: 1200,
            })
        );

        assert_eq!(
            st.domain_egress.get("crates.io"),
            Some(&DomainTransferStats {
                requests: 1,
                bytes_tx: 50,
                bytes_rx: 250,
            })
        );
    }

    #[test]
    fn stats_snapshot_preserves_net_egress_aggregation() {
        let mut inner = Inner::default();
        ingest(
            &mut inner,
            Event::NetEgress {
                ts: now(),
                host: "api.openai.com".into(),
                ip: "104.18.6.1".into(),
                port: 443,
                bytes_tx: 400,
                bytes_rx: 1600,
            },
        );

        let collector = StatsCollector {
            inner: Arc::new(Mutex::new(inner)),
        };
        let snap = collector.snapshot();

        assert_eq!(snap.total_egress_bytes_tx, 400);
        assert_eq!(snap.total_egress_bytes_rx, 1600);
        assert_eq!(
            snap.domain_egress.get("api.openai.com"),
            Some(&DomainTransferStats {
                requests: 1,
                bytes_tx: 400,
                bytes_rx: 1600,
            })
        );
    }
}
