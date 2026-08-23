//! Shared, backend-independent state for the statusline and full dashboards.
//!
//! The state is deliberately fed by the event bus instead of by a periodic
//! sampler. This keeps repaint work bounded and makes the state useful in
//! tests (and for the multi-agent dashboard) without requiring a terminal.

use std::collections::{BTreeMap, VecDeque};
use std::path::Path;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::broadcast;

use crate::events::{Event, FileAccess};

pub const RING_CAP: usize = 1000;
pub const ACTIVITY_CAP: usize = 120;

/// Which event subset is currently visible in a dashboard.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum EventFilter {
    #[default]
    All,
    Blocked,
    Files,
    Network,
    Suspicious,
    Notices,
    Search(String),
}

impl EventFilter {
    pub fn label(&self) -> &str {
        match self {
            Self::All => "all",
            Self::Blocked => "blocked",
            Self::Files => "files",
            Self::Network => "network",
            Self::Suspicious => "suspicious",
            Self::Notices => "notices",
            Self::Search(_) => "search",
        }
    }

    pub fn matches(&self, event: &Event) -> bool {
        match self {
            Self::All => true,
            Self::Blocked => {
                matches!(event, Event::BlockedAttempt { .. })
                    || matches!(event, Event::NetRequest { allowed: false, .. })
            }
            Self::Files => matches!(event, Event::FileObserved { .. }),
            Self::Network => matches!(event, Event::NetRequest { .. }),
            Self::Suspicious => crate::classifier::classify_event(event).is_some(),
            Self::Notices => matches!(event, Event::Notice { .. }),
            Self::Search(query) => {
                let q = query.trim().to_ascii_lowercase();
                q.is_empty() || describe(event).to_ascii_lowercase().contains(&q)
            }
        }
    }
}

/// One bucket of the activity sparkline. Counts are observations, not
/// enforcement decisions; the event model documents that distinction.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ActivitySample {
    pub at: DateTime<Utc>,
    pub events: u64,
    pub blocked: u64,
    pub network: u64,
    pub suspicious: u64,
}

impl Default for ActivitySample {
    fn default() -> Self {
        Self {
            at: Utc::now(),
            events: 0,
            blocked: 0,
            network: 0,
            suspicious: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct NetworkSummary {
    pub total: u64,
    pub allowed: u64,
    pub blocked: u64,
}

pub struct AppState {
    pub tier: String,
    pub net: String,
    pub profile: String,
    pub events: VecDeque<Event>,
    pub events_total: u64,
    pub blocked: u64,
    pub files: u64,
    pub file_reads: u64,
    pub file_writes: u64,
    pub execs: u64,
    pub net_requests: u64,
    pub notices: u64,
    pub suspicious: u64,
    pub last_line: String,
    pub filter: EventFilter,
    pub selected: usize,
    pub scroll: usize,
    pub paused: bool,
    pub help: bool,
    pub generation: u64,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub file_tree: BTreeMap<String, u64>,
    pub network: NetworkSummary,
    pub network_hosts: BTreeMap<(String, u16, bool), u64>,
    pub activity: VecDeque<ActivitySample>,
}

impl AppState {
    pub fn new(tier: &str, net: &str, profile: &str) -> Self {
        Self {
            tier: tier.to_string(),
            net: net.to_string(),
            profile: profile.to_string(),
            events: VecDeque::with_capacity(64),
            events_total: 0,
            blocked: 0,
            files: 0,
            file_reads: 0,
            file_writes: 0,
            execs: 0,
            net_requests: 0,
            notices: 0,
            suspicious: 0,
            last_line: String::new(),
            filter: EventFilter::All,
            selected: 0,
            scroll: 0,
            paused: false,
            help: false,
            generation: 0,
            started_at: None,
            ended_at: None,
            exit_code: None,
            file_tree: BTreeMap::new(),
            network: NetworkSummary::default(),
            network_hosts: BTreeMap::new(),
            activity: VecDeque::with_capacity(ACTIVITY_CAP),
        }
    }

    pub fn ingest(&mut self, ev: Event) {
        self.events_total = self.events_total.saturating_add(1);
        let mut sample = ActivitySample {
            at: ev.ts(),
            ..ActivitySample::default()
        };
        if crate::classifier::classify_event(&ev).is_some() {
            self.suspicious = self.suspicious.saturating_add(1);
            sample.suspicious = 1;
        }
        match &ev {
            Event::SessionStarted { ts, .. } => self.started_at = Some(*ts),
            Event::SessionEnded { ts, exit_code, .. } => {
                self.ended_at = Some(*ts);
                self.exit_code = Some(*exit_code);
            }
            Event::FileObserved { path, access, .. } => {
                self.files += 1;
                sample.events = 1;
                let key = file_tree_key(path);
                *self.file_tree.entry(key).or_insert(0) += 1;
                match access {
                    FileAccess::Read => self.file_reads += 1,
                    FileAccess::Write => self.file_writes += 1,
                    FileAccess::Unknown => {}
                }
            }
            Event::ExecObserved { .. } => {
                self.execs += 1;
                sample.events = 1;
            }
            Event::BlockedAttempt { path, .. } => {
                self.blocked += 1;
                sample.events = 1;
                sample.blocked = 1;
                *self.file_tree.entry(file_tree_key(path)).or_insert(0) += 1;
            }
            Event::NetRequest {
                host,
                port,
                allowed,
                ..
            } => {
                self.net_requests += 1;
                self.network.total += 1;
                *self
                    .network_hosts
                    .entry((host.clone(), *port, *allowed))
                    .or_insert(0) += 1;
                if *allowed {
                    self.network.allowed += 1;
                } else {
                    self.network.blocked += 1;
                }
                sample.events = 1;
                sample.network = 1;
            }
            Event::Notice { .. } => {
                self.notices += 1;
                sample.events = 1;
            }
            Event::SecretMasked { path, .. } => {
                *self.file_tree.entry(file_tree_key(path)).or_insert(0) += 1;
                sample.events = 1;
            }
        }
        self.last_line = describe(&ev);
        self.events.push_back(ev);
        while self.events.len() > RING_CAP {
            self.events.pop_front();
        }
        if sample.events > 0 {
            push_activity(&mut self.activity, sample);
        }
        self.selected = self.selected.min(self.filtered_len().saturating_sub(1));
        self.generation = self.generation.wrapping_add(1);
    }

    /// Pull everything currently queued on the bus into the ring.
    pub fn drain(&mut self, rx: &mut broadcast::Receiver<Event>) {
        loop {
            match rx.try_recv() {
                Ok(ev) => self.ingest(ev),
                Err(broadcast::error::TryRecvError::Empty)
                | Err(broadcast::error::TryRecvError::Closed) => break,
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    self.generation = self.generation.wrapping_add(1);
                    continue;
                }
            }
        }
    }

    pub fn set_filter(&mut self, filter: EventFilter) {
        self.filter = filter;
        self.selected = 0;
        self.scroll = 0;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn toggle_help(&mut self) {
        self.help = !self.help;
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn filtered_events(&self) -> Vec<&Event> {
        self.events
            .iter()
            .filter(|event| self.filter.matches(event))
            .collect()
    }

    pub fn filtered_len(&self) -> usize {
        self.events
            .iter()
            .filter(|event| self.filter.matches(event))
            .count()
    }

    pub fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let next = if delta.is_negative() {
            self.selected.saturating_sub(delta.unsigned_abs())
        } else {
            self.selected.saturating_add(delta as usize)
        };
        self.selected = next.min(len - 1);
        self.generation = self.generation.wrapping_add(1);
    }

    pub fn scroll_by(&mut self, delta: isize) {
        if delta.is_negative() {
            self.scroll = self.scroll.saturating_sub(delta.unsigned_abs());
        } else {
            self.scroll = self.scroll.saturating_add(delta as usize);
        }
        self.generation = self.generation.wrapping_add(1);
    }

    /// Export the bounded event ring as JSONL. The operation is explicit and
    /// synchronous so a failed write is shown to the user instead of being
    /// silently lost in a background task.
    pub fn export_events(&self, path: &Path) -> std::io::Result<usize> {
        let mut text = String::new();
        for event in &self.events {
            let mut value = serde_json::to_value(event).map_err(std::io::Error::other)?;
            crate::report::sanitize_json_strings(&mut value);
            let line = serde_json::to_string(&value).map_err(std::io::Error::other)?;
            text.push_str(&line);
            text.push('\n');
        }
        crate::report::write_new_report(path, &text)?;
        Ok(self.events.len())
    }

    /// One compact statusline cell: badges + counters + last event.
    pub fn status_text(&self, cols: u16) -> String {
        let state = if self.paused { "paused" } else { "live" };
        let head = format!(
            " vetto [{state}] [tier={}] [net={}] blocked={} suspicious={} files={} exec={} ",
            self.tier, self.net, self.blocked, self.suspicious, self.files, self.execs
        );
        let budget = cols as usize;
        if budget == 0 {
            return String::new();
        }
        if head.len() >= budget.saturating_sub(1) {
            truncate_chars(&head, budget)
        } else {
            let tail_budget = budget - head.len() - 1;
            format!("{head}| {}", truncate_chars(&self.last_line, tail_budget))
        }
    }
}

fn push_activity(activity: &mut VecDeque<ActivitySample>, sample: ActivitySample) {
    // Events arriving in the same second share one bucket. This makes the
    // graph stable at the 4–5fps repaint cap and avoids a timer-driven UI.
    if let Some(last) = activity.back_mut() {
        if last.at.timestamp() == sample.at.timestamp() {
            last.events += sample.events;
            last.blocked += sample.blocked;
            last.network += sample.network;
            last.suspicious += sample.suspicious;
            return;
        }
    }
    activity.push_back(sample);
    while activity.len() > ACTIVITY_CAP {
        activity.pop_front();
    }
}

fn file_tree_key(path: &str) -> String {
    let path = Path::new(path);
    let mut parts = path.components();
    let Some(first) = parts.next() else {
        return "/".to_string();
    };
    let mut key = first.as_os_str().to_string_lossy().into_owned();
    if let Some(second) = parts.next() {
        key.push(std::path::MAIN_SEPARATOR);
        key.push_str(&second.as_os_str().to_string_lossy());
    }
    key
}

pub fn truncate_chars(s: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
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
        Event::SessionStarted { pid, .. } => {
            format!("[{t}] session started (agent subtree root {pid})")
        }
        Event::SessionEnded { exit_code, .. } => format!("[{t}] session ended (exit {exit_code})"),
        Event::FileObserved {
            comm, path, access, ..
        } => {
            let a = match access {
                FileAccess::Read => "read",
                FileAccess::Write => "write",
                FileAccess::Unknown => "open",
            };
            format!("[{t}] {comm} {a} {path}")
        }
        Event::ExecObserved { argv, .. } => {
            format!(
                "[{t}] exec {}",
                argv.first().map(String::as_str).unwrap_or("?")
            )
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn blocked(path: &str) -> Event {
        Event::BlockedAttempt {
            ts: Utc::now(),
            pid: 1,
            comm: "agent".into(),
            path: path.into(),
            source: "test".into(),
        }
    }

    #[test]
    fn filtering_and_navigation_are_deterministic() {
        let mut state = AppState::new("full", "off", "default");
        state.ingest(blocked("/tmp/a"));
        state.ingest(Event::Notice {
            ts: Utc::now(),
            message: "hello".into(),
        });
        state.set_filter(EventFilter::Blocked);
        assert_eq!(state.filtered_len(), 1);
        state.move_selection(1);
        assert_eq!(state.selected, 0);
    }

    #[test]
    fn export_contains_only_the_bounded_ring() {
        let mut state = AppState::new("full", "off", "default");
        state.ingest(blocked("/tmp/a"));
        let temp =
            std::fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let path = temp.join(format!("vetto-tui-{}.jsonl", std::process::id()));
        let count = state.export_events(&path).expect("export");
        assert_eq!(count, 1);
        let text = std::fs::read_to_string(&path).expect("read export");
        assert!(text.contains("blocked_attempt"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn export_redacts_user_strings_and_keeps_json_lines_valid() {
        let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let mut state = AppState::new("full", "off", "default");
        state.ingest(Event::Notice {
            ts: Utc::now(),
            message: format!("token={secret}"),
        });
        let temp =
            std::fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let path = temp.join(format!(
            "vetto-tui-secret-{}-{}.jsonl",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        state.export_events(&path).expect("export");
        let text = std::fs::read_to_string(&path).expect("read export");
        assert!(!text.contains(secret), "secret leaked: {text}");
        assert!(text
            .lines()
            .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok()));
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn export_refuses_symlinked_parent() {
        use std::os::unix::fs::symlink;

        let suffix = format!(
            "{}-{}",
            std::process::id(),
            Utc::now().timestamp_nanos_opt().unwrap_or_default()
        );
        let temp =
            std::fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let real = temp.join(format!("vetto-tui-real-{suffix}"));
        let link = temp.join(format!("vetto-tui-link-{suffix}"));
        std::fs::create_dir(&real).expect("create real export directory");
        symlink(&real, &link).expect("create export symlink");

        let mut state = AppState::new("full", "off", "default");
        state.ingest(blocked("/tmp/a"));
        let path = link.join("events.jsonl");
        assert!(state.export_events(&path).is_err());
        assert!(!real.join("events.jsonl").exists());

        std::fs::remove_file(&link).expect("remove export symlink");
        std::fs::remove_dir(&real).expect("remove real export directory");
    }
}
