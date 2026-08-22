//! Session statistics collector: a bus subscriber thread aggregating counts
//! and interesting records for the post-session reports.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::events::{Event, EventBus, FileAccess};

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
    pub blocked_attempts: Vec<BlockedRecord>,
    pub net_requests: Vec<NetRecord>,
    pub notices: Vec<String>,
}

#[derive(Default)]
struct Inner {
    stats: SessionStats,
    blocked: BTreeMap<(String, String, String), u64>, // (path, comm, source)
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
            match access {
                FileAccess::Read => st.file_reads += 1,
                FileAccess::Write => st.file_writes += 1,
                FileAccess::Unknown => {}
            }
        }
        Event::BlockedAttempt {
            path, comm, source, ..
        } => {
            *inner.blocked.entry((path, comm, source)).or_insert(0) += 1;
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
        Event::ExecObserved { .. } | Event::SecretMasked { .. } => {}
    }
}
