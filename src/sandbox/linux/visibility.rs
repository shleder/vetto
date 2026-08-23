//! Best-effort /proc visibility poller (ALLOWED operations only).
//!
//! Walks `/proc/<pid>/fd/` every 50ms while active, backing off to 500ms
//! after five seconds and 2s after thirty seconds for processes in the sandboxed
//! subtree and publishes FileObserved/ExecObserved events. Honest limits:
//! misses sub-100ms opens; fd flags come from `/proc/<pid>/fdinfo`; this is
//! observation, never enforcement.

use crate::events::{bus::EventBus, Event, FileAccess};
use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

pub const POLL_INTERVAL_MS: u64 = 50;
pub const ACTIVE_POLL_INTERVAL_MS: u64 = 50;
pub const IDLE_POLL_INTERVAL_MS: u64 = 500;
pub const LONG_IDLE_POLL_INTERVAL_MS: u64 = 2_000;
pub const IDLE_AFTER_MS: u64 = 5_000;
pub const LONG_IDLE_AFTER_MS: u64 = 30_000;
pub const MAX_PATH_CACHE_ENTRIES: usize = 10_000;
const MAX_EVENTS_PER_TICK: usize = 200;

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct LifecycleToken {
    pub pid: u32,
    pub start_time: u64,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct InvalidationToken {
    pub process: LifecycleToken,
    pub fd: i32,
}

#[derive(Debug, Clone)]
struct PathCacheEntry {
    path: String,
    generation: u64,
}

/// Bounded LRU cache for observed `/proc/<pid>/fd/<n>` targets.
///
/// The process start time is part of every key, so PID reuse cannot inherit a
/// prior process's path observations. Callers can explicitly invalidate a
/// descriptor or all descriptors for a process when a lifecycle token changes.
pub struct PathCache {
    capacity: usize,
    generation: u64,
    entries: HashMap<InvalidationToken, PathCacheEntry>,
    lru: VecDeque<(InvalidationToken, u64)>,
}

impl Default for PathCache {
    fn default() -> Self {
        Self::new(MAX_PATH_CACHE_ENTRIES)
    }
}

impl PathCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.clamp(1, MAX_PATH_CACHE_ENTRIES),
            generation: 0,
            entries: HashMap::new(),
            lru: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Record a target and return true when it is new or changed.
    pub fn observe(&mut self, token: InvalidationToken, path: &str) -> bool {
        self.generation = self.generation.wrapping_add(1);
        if let Some(entry) = self.entries.get_mut(&token) {
            let changed = entry.path != path;
            entry.path.clear();
            entry.path.push_str(path);
            entry.generation = self.generation;
            self.lru.push_back((token, self.generation));
            self.compact_lru_if_needed();
            return changed;
        }
        self.entries.insert(
            token,
            PathCacheEntry {
                path: path.to_string(),
                generation: self.generation,
            },
        );
        self.lru.push_back((token, self.generation));
        self.evict_oldest();
        self.compact_lru_if_needed();
        true
    }

    pub fn invalidate(&mut self, token: InvalidationToken) {
        self.entries.remove(&token);
    }

    pub fn invalidate_process(&mut self, process: LifecycleToken) {
        self.entries.retain(|token, _| token.process != process);
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.lru.clear();
    }

    fn compact_lru_if_needed(&mut self) {
        // Every refresh appends a generation marker. Compact stale markers so
        // the metadata queue cannot grow without bound during a long session,
        // even though the entry map itself is already capacity-bounded.
        let threshold = self.capacity.saturating_mul(2).max(64);
        if self.lru.len() <= threshold {
            return;
        }
        let mut live: Vec<_> = self
            .entries
            .iter()
            .map(|(token, entry)| (*token, entry.generation))
            .collect();
        live.sort_unstable_by_key(|(_, generation)| *generation);
        self.lru = live.into_iter().collect();
    }

    fn evict_oldest(&mut self) {
        while self.entries.len() > self.capacity {
            let Some((token, generation)) = self.lru.pop_front() else {
                self.entries.clear();
                return;
            };
            if self
                .entries
                .get(&token)
                .is_some_and(|entry| entry.generation == generation)
            {
                self.entries.remove(&token);
            }
        }
    }
}

/// One changed, user-visible descriptor found by [`scan_fds`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FdObservation {
    pub pid: u32,
    pub fd: i32,
    pub path: String,
    pub access: FileAccess,
    pub comm: String,
}

/// Scan one process's `/proc/<pid>/fd` directory and return newly observed or
/// changed user-visible descriptors.
///
/// This extracted primitive performs observation only. It does not publish
/// events, alter the process, or enforce policy. The caller owns the cache so
/// repeated scans can model the poller's normal steady-state cost.
pub fn scan_fds(pid: u32, path_cache: &mut PathCache) -> Vec<FdObservation> {
    let Some(process) = lifecycle_token(pid) else {
        return Vec::new();
    };
    let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    let comm = read_comm(pid);
    let mut observations = Vec::new();
    for entry in fds.flatten() {
        let name_os = entry.file_name();
        let Some(name) = name_os.to_str() else {
            continue;
        };
        let Ok(fd_num) = name.parse::<i32>() else {
            continue;
        };
        let token = InvalidationToken {
            process,
            fd: fd_num,
        };
        let Ok(target) = std::fs::read_link(entry.path()) else {
            path_cache.invalidate(token);
            continue;
        };
        let target_str = target.to_string_lossy().to_string();
        if !path_cache.observe(token, &target_str) {
            continue;
        }
        // Keep the feed useful by omitting kernel-internal descriptors.
        if target_str.starts_with("anon_inode:")
            || target_str.starts_with("pipe:[")
            || target_str == "/dev/null"
            || target_str.starts_with("/dev/pts/")
        {
            continue;
        }
        if observations.len() >= MAX_EVENTS_PER_TICK {
            break;
        }
        observations.push(FdObservation {
            pid,
            fd: fd_num,
            access: fd_access(pid, fd_num),
            path: target_str,
            comm: comm.clone(),
        });
    }
    observations
}

/// Explicit alias for callers that want the process/fd terminology in a
/// benchmark name without depending on the poller's event bus.
pub fn scan_process_fds(pid: u32, path_cache: &mut PathCache) -> Vec<FdObservation> {
    scan_fds(pid, path_cache)
}

/// Poll interval selected from the time since the last observed activity.
pub fn poll_interval_ms(idle_for: Duration) -> u64 {
    let idle_ms = idle_for.as_millis() as u64;
    if idle_ms >= LONG_IDLE_AFTER_MS {
        LONG_IDLE_POLL_INTERVAL_MS
    } else if idle_ms >= IDLE_AFTER_MS {
        IDLE_POLL_INTERVAL_MS
    } else {
        ACTIVE_POLL_INTERVAL_MS
    }
}

/// Capture a PID plus Linux's monotonic process start time. A start time is
/// the lifecycle invalidation token that prevents PID reuse confusion.
pub fn lifecycle_token(pid: u32) -> Option<LifecycleToken> {
    Some(LifecycleToken {
        pid,
        start_time: process_start_time(pid)?,
    })
}

/// Spawn the poller task. `roots` are outer-visible pids of the sandbox.
pub fn spawn_poller(bus: EventBus, roots: Vec<u32>) {
    let roots: Vec<LifecycleToken> = roots.into_iter().filter_map(lifecycle_token).collect();
    if roots.is_empty() {
        return;
    }
    spawn_poller_with_lifecycle(bus, roots);
}

pub fn spawn_poller_with_lifecycle(bus: EventBus, roots: Vec<LifecycleToken>) {
    if roots.is_empty() {
        return;
    }
    std::thread::Builder::new()
        .name("vetto-visibility".into())
        .spawn(move || poll_loop(bus, roots))
        .expect("spawn visibility thread");
}

fn poll_loop(bus: EventBus, roots: Vec<LifecycleToken>) {
    let root_pids: Vec<u32> = roots.iter().map(|root| root.pid).collect();
    let mut path_cache = PathCache::default();
    let mut seen_pids: HashSet<LifecycleToken> = HashSet::new();
    let mut known_processes: HashSet<LifecycleToken> = HashSet::new();
    let mut last_activity = Instant::now();

    loop {
        if !roots.iter().any(process_is_alive) {
            break;
        }
        let tree = collect_subtree(&root_pids);
        let mut active_processes = HashSet::new();
        let mut process_tokens = Vec::new();
        for pid in tree {
            let Some(token) = lifecycle_token(pid) else {
                continue;
            };
            active_processes.insert(token);
            process_tokens.push(token);
        }
        for old in known_processes.difference(&active_processes) {
            path_cache.invalidate_process(*old);
            seen_pids.remove(old);
        }
        known_processes = active_processes;
        let mut emitted = 0usize;
        let mut activity = false;

        for process in &process_tokens {
            let pid = process.pid;
            // New process appeared?
            if seen_pids.insert(*process) {
                let argv = read_cmdline(pid);
                bus.publish(Event::ExecObserved {
                    ts: crate::events::types::now(),
                    pid,
                    argv,
                });
                activity = true;
            }

            for observation in scan_fds(pid, &mut path_cache) {
                if emitted >= MAX_EVENTS_PER_TICK {
                    break; // drop silently; documented best-effort behavior
                }
                emitted += 1;
                bus.publish(Event::FileObserved {
                    ts: crate::events::types::now(),
                    pid: observation.pid,
                    comm: observation.comm,
                    path: observation.path,
                    access: observation.access,
                });
                activity = true;
            }
            if emitted >= MAX_EVENTS_PER_TICK {
                break;
            }
        }

        if activity {
            last_activity = Instant::now();
        }
        let interval = poll_interval_ms(last_activity.elapsed());
        std::thread::sleep(Duration::from_millis(interval));
        if path_cache.len() > MAX_PATH_CACHE_ENTRIES {
            path_cache.clear();
        }
    }
}

fn process_is_alive(token: &LifecycleToken) -> bool {
    let Some(current) = lifecycle_token(token.pid) else {
        return false;
    };
    (token.start_time != 0 && token.start_time == current.start_time)
        && !process_is_zombie(token.pid)
}

fn process_is_zombie(pid: u32) -> bool {
    let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
        return true;
    };
    status
        .lines()
        .find(|line| line.starts_with("State:"))
        .map(|line| line["State:".len()..].trim_start().starts_with('Z'))
        .unwrap_or(true)
}

/// Read the kernel-assigned process start time from `/proc/<pid>/stat`.
///
/// The second field (`comm`) is parenthesized and may itself contain spaces,
/// so split only after the final `) ` before indexing the remaining fields.
/// Field 22 is `starttime`; after field 2 has been removed it is index 19.
fn process_start_time(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end_comm = stat.rfind(") ")?;
    stat[end_comm + 2..]
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()
}

/// BFS over PPid links from the sandbox roots.
pub fn collect_subtree(roots: &[u32]) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(ppid) = read_ppid(pid) {
                children.entry(ppid).or_default().push(pid);
            }
        }
    }
    let mut out = Vec::new();
    let mut queue: std::collections::VecDeque<u32> = roots.iter().copied().collect();
    let mut visited: HashSet<u32> = roots.iter().copied().collect();
    while let Some(pid) = queue.pop_front() {
        out.push(pid);
        if let Some(descendants) = children.get(&pid) {
            for &child in descendants {
                if !visited.insert(child) {
                    continue;
                }
                queue.push_back(child);
            }
        }
    }
    out
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("PPid:"))?;
    line["PPid:".len()..].trim().parse().ok()
}

fn read_comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "?".into())
}

fn read_cmdline(pid: u32) -> Vec<String> {
    std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
        .map(|s| {
            s.split('\0')
                .filter(|a| !a.is_empty())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Parse `flags:` from fdinfo to distinguish read vs write opens.
fn fd_access(pid: u32, fd: i32) -> FileAccess {
    let Ok(info) = std::fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
        return FileAccess::Unknown;
    };
    let Some(line) = info.lines().find(|l| l.starts_with("flags:")) else {
        return FileAccess::Unknown;
    };
    let Ok(flags) = u32::from_str_radix(line["flags:".len()..].trim(), 8) else {
        return FileAccess::Unknown;
    };
    match flags & 0b11 {
        0 => FileAccess::Read,      // O_RDONLY
        1 | 2 => FileAccess::Write, // O_WRONLY | O_RDWR
        _ => FileAccess::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poller_adapts_after_idle_windows() {
        assert_eq!(
            poll_interval_ms(Duration::from_millis(0)),
            ACTIVE_POLL_INTERVAL_MS
        );
        assert_eq!(
            poll_interval_ms(Duration::from_millis(IDLE_AFTER_MS)),
            IDLE_POLL_INTERVAL_MS
        );
        assert_eq!(
            poll_interval_ms(Duration::from_millis(LONG_IDLE_AFTER_MS)),
            LONG_IDLE_POLL_INTERVAL_MS
        );
    }

    #[test]
    fn path_cache_is_bounded_lru_and_explicitly_invalidatable() {
        let process = LifecycleToken {
            pid: 7,
            start_time: 11,
        };
        let mut cache = PathCache::new(2);
        let first = InvalidationToken { process, fd: 1 };
        let second = InvalidationToken { process, fd: 2 };
        let third = InvalidationToken { process, fd: 3 };

        assert!(cache.observe(first, "/tmp/a"));
        assert!(!cache.observe(first, "/tmp/a"));
        assert!(cache.observe(first, "/tmp/b"));
        assert!(cache.observe(second, "/tmp/c"));
        assert!(cache.observe(third, "/tmp/d"));
        assert_eq!(cache.capacity(), 2);
        assert!(cache.len() <= cache.capacity());
        for _ in 0..128 {
            assert!(!cache.observe(third, "/tmp/d"));
        }
        assert!(cache.lru.len() <= cache.capacity().saturating_mul(2).max(64));

        cache.invalidate(third);
        assert!(!cache.entries.contains_key(&third));
        cache.invalidate_process(process);
        assert!(cache.is_empty());
    }

    #[test]
    fn lifecycle_token_is_stable_for_current_process() {
        let pid = std::process::id();
        let first = lifecycle_token(pid).expect("current process has a /proc stat");
        let second = lifecycle_token(pid).expect("current process has a /proc stat");
        assert_eq!(first, second);
        assert!(first.start_time > 0);
    }
}
