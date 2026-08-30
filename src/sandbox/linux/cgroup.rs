//! cgroup v2 transient lifecycle and resource quota management.
//!
//! Handles cgroup creation in delegated hierarchies, writes resource ceilings
//! (memory.max, memory.swap.max, pids.max, cpu.max), migrates the child process,
//! and ensures cleanup on teardown or SIGKILL.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::error::{VettoError, VettoResult};
use crate::policy::CgroupConfig;

#[derive(Debug)]
pub struct CgroupHandle {
    path: PathBuf,
    cleaned: Arc<AtomicBool>,
}

impl CgroupHandle {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Add a process PID to this cgroup.
    pub fn add_process(&self, pid: u32) -> VettoResult<()> {
        let procs_file = self.path.join("cgroup.procs");
        fs::write(&procs_file, pid.to_string()).map_err(|e| {
            VettoError::Sandbox(format!(
                "failed to move pid {pid} into cgroup {}: {e}",
                self.path.display()
            ))
        })
    }

    /// Clean up the cgroup directory.
    pub fn cleanup(&self) {
        if self.cleaned.swap(true, Ordering::SeqCst) {
            return;
        }
        // Kill remaining procs if cgroup.kill is available (Linux 5.14+)
        let kill_file = self.path.join("cgroup.kill");
        if kill_file.exists() {
            let _ = fs::write(&kill_file, "1");
        }
        // Attempt removing the directory
        let _ = fs::remove_dir(&self.path);
    }
}

impl Drop for CgroupHandle {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Parse human-readable memory limit into bytes or string representation.
pub fn parse_memory_bytes(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") {
        return Some("max".to_string());
    }
    let (num_part, unit_part) = match s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        Some(idx) => (&s[..idx], s[idx..].trim().to_uppercase()),
        None => (s, String::new()),
    };
    let num: f64 = num_part.parse().ok()?;
    let multiplier: f64 = match unit_part.as_str() {
        "" | "B" => 1.0,
        "K" | "KB" | "KIB" => 1024.0,
        "M" | "MB" | "MIB" => 1024.0 * 1024.0,
        "G" | "GB" | "GIB" => 1024.0 * 1024.0 * 1024.0,
        "T" | "TB" | "TIB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    let bytes = (num * multiplier) as u64;
    Some(bytes.to_string())
}

/// Parse CPU limit (e.g. "50%", "100%", "200%", or raw quota/period "50000 100000").
pub fn parse_cpu_max(input: &str) -> Option<String> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") {
        return Some("max 100000".to_string());
    }
    if s.ends_with('%') {
        let pct_str = s.trim_end_matches('%').trim();
        let pct: f64 = pct_str.parse().ok()?;
        let period = 100_000u64;
        let quota = ((pct / 100.0) * period as f64) as u64;
        return Some(format!("{quota} {period}"));
    }
    if s.contains(' ') {
        return Some(s.to_string());
    }
    if let Ok(quota) = s.parse::<u64>() {
        return Some(format!("{quota} 100000"));
    }
    None
}

/// Locate a writable cgroup v2 hierarchy.
pub fn find_cgroup_root() -> Option<PathBuf> {
    let cgroup2_mount = Path::new("/sys/fs/cgroup");
    if !cgroup2_mount.join("cgroup.controllers").exists() {
        return None;
    }

    // 1. Check user slice under systemd: /sys/fs/cgroup/user.slice/user-<uid>.slice/user@<uid>.service/
    let uid = unsafe { libc::getuid() };
    let user_slice = cgroup2_mount.join(format!("user.slice/user-{uid}.slice/user@{uid}.service"));
    if is_dir_writable(&user_slice) {
        return Some(user_slice);
    }

    // 2. Check general user.slice
    let user_slice_general = cgroup2_mount.join(format!("user.slice/user-{uid}.slice"));
    if is_dir_writable(&user_slice_general) {
        return Some(user_slice_general);
    }

    // 3. Direct cgroup root if running privileged/root
    if is_dir_writable(cgroup2_mount) {
        return Some(cgroup2_mount.to_path_buf());
    }

    // 4. Check user home cgroup (~/.cgroup or $XDG_RUNTIME_DIR/cgroup)
    if let Some(runtime_dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        let runtime_cgroup = PathBuf::from(runtime_dir).join("cgroup");
        if is_dir_writable(&runtime_cgroup) {
            return Some(runtime_cgroup);
        }
    }

    None
}

fn is_dir_writable(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }
    let test_file = path.join(format!(".vetto-write-test-{}", std::process::id()));
    if fs::write(&test_file, b"test").is_ok() {
        let _ = fs::remove_file(&test_file);
        true
    } else {
        false
    }
}

/// Create a transient cgroup v2 for the session.
pub fn setup_cgroup(
    cgroup_config: Option<&CgroupConfig>,
    cpu_max_override: Option<&str>,
) -> VettoResult<Option<CgroupHandle>> {
    let effective_cgroup = match (cgroup_config, cpu_max_override) {
        (None, None) => return Ok(None),
        (Some(c), None) => c.clone(),
        (None, Some(cpu)) => CgroupConfig {
            cpu_max: Some(cpu.to_string()),
            ..CgroupConfig::default()
        },
        (Some(c), Some(cpu)) => {
            let mut merged = c.clone();
            merged.cpu_max = Some(cpu.to_string());
            merged
        }
    };

    let Some(root) = find_cgroup_root() else {
        tracing::warn!(
            "cgroup v2 is unavailable or not writable on this system; \
             continuing without cgroup resource quotas (WARNING)"
        );
        return Ok(None);
    };

    // Enable subtree controllers in parent if possible
    let subtree_file = root.join("cgroup.subtree_control");
    if subtree_file.exists() {
        let _ = fs::write(&subtree_file, "+memory +pids +cpu");
    }

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let cgroup_dir = root.join(format!("vetto-{}-{}", std::process::id(), nonce));

    if let Err(e) = fs::create_dir(&cgroup_dir) {
        tracing::warn!(
            "failed to create cgroup directory {}: {e}; continuing without cgroup",
            cgroup_dir.display()
        );
        return Ok(None);
    }

    // Write limits
    if let Some(mem) = &effective_cgroup.memory_max {
        if let Some(bytes) = parse_memory_bytes(mem) {
            let _ = fs::write(cgroup_dir.join("memory.max"), bytes);
        }
    }
    if let Some(swap) = &effective_cgroup.swap_max {
        if let Some(bytes) = parse_memory_bytes(swap) {
            let _ = fs::write(cgroup_dir.join("memory.swap.max"), bytes);
        }
    }
    if let Some(pids) = &effective_cgroup.pids_max {
        let _ = fs::write(cgroup_dir.join("pids.max"), pids);
    }
    if let Some(cpu) = &effective_cgroup.cpu_max {
        if let Some(val) = parse_cpu_max(cpu) {
            let _ = fs::write(cgroup_dir.join("cpu.max"), val);
        }
    }

    Ok(Some(CgroupHandle {
        path: cgroup_dir,
        cleaned: Arc::new(AtomicBool::new(false)),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_memory_units() {
        assert_eq!(parse_memory_bytes("2g"), Some("2147483648".into()));
        assert_eq!(parse_memory_bytes("512M"), Some("536870912".into()));
        assert_eq!(parse_memory_bytes("0"), Some("0".into()));
        assert_eq!(parse_memory_bytes("max"), Some("max".into()));
        assert_eq!(parse_memory_bytes("1024"), Some("1024".into()));
    }

    #[test]
    fn parse_cpu_percent_and_raw() {
        assert_eq!(parse_cpu_max("50%"), Some("50000 100000".into()));
        assert_eq!(parse_cpu_max("100%"), Some("100000 100000".into()));
        assert_eq!(parse_cpu_max("200%"), Some("200000 100000".into()));
        assert_eq!(parse_cpu_max("50000 100000"), Some("50000 100000".into()));
        assert_eq!(parse_cpu_max("max"), Some("max 100000".into()));
    }
}
