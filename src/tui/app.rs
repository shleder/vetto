//! Shared UI state: bounded event ring + counters, fed from the event bus.

use std::collections::VecDeque;

use tokio::sync::broadcast;

use crate::events::{Event, FileAccess};

pub const RING_CAP: usize = 1000;

pub struct AppState {
    pub tier: String,
    pub net: String,
    pub profile: String,
    pub events: VecDeque<Event>,
    pub blocked: u64,
    pub files: u64,
    pub execs: u64,
    pub net_requests: u64,
    pub notices: u64,
    pub last_line: String,
}

impl AppState {
    pub fn new(tier: &str, net: &str, profile: &str) -> Self {
        Self {
            tier: tier.to_string(),
            net: net.to_string(),
            profile: profile.to_string(),
            events: VecDeque::with_capacity(64),
            blocked: 0,
            files: 0,
            execs: 0,
            net_requests: 0,
            notices: 0,
            last_line: String::new(),
        }
    }

    pub fn ingest(&mut self, ev: Event) {
        match &ev {
            Event::FileObserved { .. } => self.files += 1,
            Event::ExecObserved { .. } => self.execs += 1,
            Event::BlockedAttempt { .. } => self.blocked += 1,
            Event::NetRequest { .. } => self.net_requests += 1,
            Event::Notice { .. } => self.notices += 1,
            Event::SessionStarted { .. } | Event::SessionEnded { .. } | Event::SecretMasked { .. } => {}
        }
        self.last_line = describe(&ev);
        self.events.push_back(ev);
        while self.events.len() > RING_CAP {
            self.events.pop_front();
        }
    }

    /// Pull everything currently queued on the bus into the ring.
    pub fn drain(&mut self, rx: &mut broadcast::Receiver<Event>) {
        loop {
            match rx.try_recv() {
                Ok(ev) => self.ingest(ev),
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
            }
        }
    }

    /// One compact statusline cell: badges + counters + last event.
    pub fn status_text(&self, cols: u16) -> String {
        let head = format!(
            " vetto [tier={}] [net={}] blocked={} files={} exec={} ",
            self.tier, self.net, self.blocked, self.files, self.execs
        );
        let budget = cols as usize;
        if head.len() >= budget.saturating_sub(1) {
            truncate_chars(&head, budget)
        } else {
            let tail_budget = budget - head.len() - 1;
            format!("{head}| {}", truncate_chars(&self.last_line, tail_budget))
        }
    }
}

pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

/// Short one-line rendering of an event for statusline/overlay.
pub fn describe(ev: &Event) -> String {
    let t = ev.ts().format("%H:%M:%S");
    match ev {
        Event::SessionStarted { pid, .. } => format!("[{t}] session started (agent subtree root {pid})"),
        Event::SessionEnded { exit_code, .. } => format!("[{t}] session ended (exit {exit_code})"),
        Event::FileObserved {
            comm,
            path,
            access,
            ..
        } => {
            let a = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!("[{t}] {comm} {a} {path}")
        }
        Event::ExecObserved { argv, .. } => {
            format!("[{t}] exec {}", argv.first().map(String::as_str).unwrap_or("?"))
        }
        Event::BlockedAttempt {
            comm, path, source, ..
        } => format!("[{t}] BLOCKED [{source}] {comm} -> {path}"),
        Event::NetRequest {
            host,
            port,
            allowed,
            ..
        } => {
            if *allowed {
                format!("[{t}] net allow {host}:{port}")
            } else {
                format!("[{t}] net DENY {host}:{port}")
            }
        }
        Event::SecretMasked { path, .. } => format!("[{t}] secret masked: {path}"),
        Event::Notice { message, .. } => format!("[{t}] {message}"),
    }
}
