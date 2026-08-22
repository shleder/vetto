//! Best-effort /proc visibility poller (ALLOWED operations only).
//!
//! Walks `/proc/<pid>/fd/` every ~100ms for processes in the sandboxed
//! subtree and publishes FileObserved/ExecObserved events. Honest limits:
//! misses sub-100ms opens; fd flags come from `/proc/<pid>/fdinfo`; this is
//! observation, never enforcement.

use std::collections::HashSet;
use std::path::Path;

use crate::events::{bus::EventBus, Event, FileAccess};

pub const POLL_INTERVAL_MS: u64 = 100;
const MAX_EVENTS_PER_TICK: usize = 200;

/// Spawn the poller task. `roots` are outer-visible pids of the sandbox.
pub fn spawn_poller(bus: EventBus, roots: Vec<u32>) {
    if roots.is_empty() {
        return;
    }
    std::thread::Builder::new()
        .name("vetto-visibility".into())
        .spawn(move || poll_loop(bus, roots))
        .expect("spawn visibility thread");
}

fn poll_loop(bus: EventBus, roots: Vec<u32>) {
    let mut seen_fds: HashSet<(u32, u64, String)> = HashSet::new();
    let mut seen_pids: HashSet<u32> = HashSet::new();

    loop {
        std::thread::sleep(std::time::Duration::from_millis(POLL_INTERVAL_MS));
        let tree = collect_subtree(&roots);
        let mut emitted = 0usize;

        for pid in &tree {
            // New process appeared?
            if seen_pids.insert(*pid) {
                let argv = read_cmdline(*pid);
                bus.publish(Event::ExecObserved {
                    ts: crate::events::types::now(),
                    pid: *pid,
                    argv,
                });
            }

            let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
                continue;
            };
            for entry in fds.flatten() {
                let Some(name) = entry.file_name().to_str() else {
                    continue;
                };
                let Ok(fd_num) = name.parse::<i32>() else {
                    continue;
                };
                let Ok(target) = std::fs::read_link(entry.path()) else {
                    continue;
                };
                let target_str = target.to_string_lossy().to_string();
                // Skip kernel-internal descriptors to keep the feed useful.
                if target_str.starts_with("anon_inode:")
                    || target_str.starts_with("pipe:[")
                    || target_str == "/dev/null"
                    || target_str.starts_with("/dev/pts/")
                {
                    continue;
                }
                let key = (*pid, fd_num as u64, target_str.clone());
                if !seen_fds.insert(key) {
                    continue; // unchanged since last tick
                }
                if emitted >= MAX_EVENTS_PER_TICK {
                    break; // drop silently; documented best-effort behavior
                }
                emitted += 1;
                let access = fd_access(*pid, fd_num);
                let comm = read_comm(*pid);
                bus.publish(Event::FileObserved {
                    ts: crate::events::types::now(),
                    pid: *pid,
                    comm,
                    path: target_str,
                    access,
                });
            }
            if emitted >= MAX_EVENTS_PER_TICK {
                break;
            }
        }

        // Bound dedup memory; halve when oversized (crude but honest).
        if seen_fds.len() > 200_000 {
            seen_fds.clear();
        }
    }
}

/// BFS over PPid links from the sandbox roots.
fn collect_subtree(roots: &[u32]) -> Vec<u32> {
    let mut parents: std::collections::HashMap<u32, u32> = Default::default();
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(ppid) = read_ppid(pid) {
                parents.insert(pid, ppid);
            }
        }
    }
    let mut out = Vec::new();
    let mut queue: std::collections::VecDeque<u32> = roots.iter().copied().collect();
    let mut visited: HashSet<u32> = roots.iter().copied().collect();
    while let Some(pid) = queue.pop_front() {
        out.push(pid);
        for (&child, &parent) in parents.iter() {
            if parent == pid && visited.insert(child) {
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
        0 => FileAccess::Read,          // O_RDONLY
        1 | 2 => FileAccess::Write,     // O_WRONLY | O_RDWR
        _ => FileAccess::Unknown,
    }
}

/// Used by doctor --probe: confirm a path is unreachable from this process
/// context. Returns the errno string on expected failure, None on success.
pub fn probe_unreachable(path: &Path) -> Option<String> {
    match std::fs::metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some("ENOENT".into()),
        Err(e) => Some(format!("{}", e.raw_os_error().unwrap_or(0))),
        Ok(_) => None,
    }
}
