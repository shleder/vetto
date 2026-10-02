//! Session context eliminating global runtime atomics.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProductionSessionContext {
    pub session_id: String,
    pub metrics: Arc<SessionExecutionMetrics>,
    pub signals: Arc<SessionSignalState>,
    pub evidence: Arc<SessionEvidenceState>,
}

impl ProductionSessionContext {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            metrics: Arc::new(SessionExecutionMetrics::default()),
            signals: Arc::new(SessionSignalState::default()),
            evidence: Arc::new(SessionEvidenceState::default()),
        }
    }
}

#[derive(Debug, Default)]
pub struct SessionExecutionMetrics {
    backend_entered: AtomicU64,
    spawn_count: AtomicU64,
}

impl SessionExecutionMetrics {
    #[inline]
    pub fn record_backend_entered(&self) {
        self.backend_entered.fetch_add(1, Ordering::SeqCst);
    }
    #[inline]
    pub fn record_spawn(&self) {
        self.spawn_count.fetch_add(1, Ordering::SeqCst);
    }
    #[inline]
    pub fn backend_entered(&self) -> u64 {
        self.backend_entered.load(Ordering::SeqCst)
    }
    #[inline]
    pub fn spawn_count(&self) -> u64 {
        self.spawn_count.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Default)]
pub struct SessionSignalState {
    pub target_pid: AtomicI32,
    pub sigint_count: AtomicUsize,
    pub term_requested: AtomicBool,
    pub win_resized: AtomicBool,
}

#[derive(Debug)]
pub struct SessionEvidenceState {
    pub channel_intact: AtomicBool,
    pub buffer_overflows: AtomicU64,
    pub packet_drops: AtomicU64,
    pub blocked_syscalls: AtomicU64,
}

impl Default for SessionEvidenceState {
    fn default() -> Self {
        Self {
            channel_intact: AtomicBool::new(true),
            buffer_overflows: AtomicU64::new(0),
            packet_drops: AtomicU64::new(0),
            blocked_syscalls: AtomicU64::new(0),
        }
    }
}
