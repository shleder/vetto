//! Autonomous Loop & Token Burn Watchdog.
//!
//! Intercepts repeated failing commands issued by autonomous AI coding agents
//! (e.g. `cargo check`, `npm test`, `pytest`) without workspace changes, preventing
//! runaway token burn and host CPU exhaustion.

use std::env;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Persistent record of consecutive execution failures for a command in a workspace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchdogRecord {
    /// Canonicalized binary and arguments string.
    pub command: String,
    /// Number of consecutive failing executions without workspace modifications.
    pub consecutive_failures: u32,
    /// Highest modification time (nanoseconds since UNIX epoch) observed in the workspace.
    pub last_workspace_mtime: u64,
    /// Timestamp (seconds since UNIX epoch) when this record was last updated.
    pub last_updated_at: u64,
    /// Absolute path to the monitored workspace.
    #[serde(default)]
    pub workspace: String,
}

/// CLI arguments for `vetto watchdog`.
#[derive(clap::Args, Debug, Clone)]
pub struct WatchdogArgs {
    /// Clear all stored watchdog state records.
    #[arg(long)]
    pub clear: bool,

    /// Emit machine-readable JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Canonicalizes binary name and arguments into a single command string.
pub fn canonicalize_command(binary: &str, args: &[String]) -> String {
    let clean_binary = Path::new(binary)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(binary);

    let filtered: Vec<&str> = args
        .iter()
        .map(String::as_str)
        .filter(|a| *a != "--no-loop-guard")
        .collect();

    if filtered.is_empty() {
        clean_binary.to_string()
    } else {
        format!("{clean_binary} {}", filtered.join(" "))
    }
}

/// Resolves the root project directory from explicit option, shim finder, or CWD.
pub fn resolve_project_root(project_dir: Option<&Path>) -> Result<PathBuf> {
    let raw = match project_dir {
        Some(p) => p.to_path_buf(),
        None => crate::shim::find_project_root()
            .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("."))),
    };
    Ok(raw.canonicalize().unwrap_or(raw))
}

/// Directory where persistent watchdog state records are stored (`~/.vetto/watchdog`).
pub fn watchdog_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = env::var("VETTO_WATCHDOG_DIR") {
        let p = PathBuf::from(override_dir);
        if !p.as_os_str().is_empty() {
            return Ok(p);
        }
    }
    let home = env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither HOME nor USERPROFILE is set")?;
    Ok(home.join(".vetto").join("watchdog"))
}

/// Computes a SHA-256 hash string for the workspace path.
pub fn workspace_hash(root: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(root.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Resolves the file path to the persistent state JSON for a workspace.
pub fn state_file_path(root: &Path) -> Result<PathBuf> {
    let dir = watchdog_dir()?;
    let hash = workspace_hash(root);
    Ok(dir.join(format!("{hash}.json")))
}

fn is_ignored_watchdog_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "node_modules" | "target" | ".vetto" | ".vetto-reports" | "vendor" | ".cache"
    )
}

fn get_path_mtime(path: &Path) -> u64 {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// Lightweight scan of latest modification time in project workspace.
pub fn scan_workspace_mtime(root: &Path) -> u64 {
    let mut max_mtime = get_path_mtime(root);
    let mut queue = vec![root.to_path_buf()];
    let mut files_scanned = 0usize;
    const MAX_FILES: usize = 10_000;

    while let Some(current_dir) = queue.pop() {
        if files_scanned >= MAX_FILES {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&current_dir) else {
            continue;
        };
        for entry in entries.flatten() {
            files_scanned += 1;
            if files_scanned >= MAX_FILES {
                break;
            }
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_symlink() {
                continue;
            }

            let path = entry.path();
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            if file_type.is_dir() && !is_ignored_watchdog_dir(&name) {
                let dir_mtime = get_path_mtime(&path);
                if dir_mtime > max_mtime {
                    max_mtime = dir_mtime;
                }
                queue.push(path);
            } else if file_type.is_file() {
                let file_mtime = get_path_mtime(&path);
                if file_mtime > max_mtime {
                    max_mtime = file_mtime;
                }
            }
        }
    }

    max_mtime
}

fn load_state(path: &Path) -> Result<Option<WatchdogRecord>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    match serde_json::from_str::<WatchdogRecord>(&content) {
        Ok(record) => Ok(Some(record)),
        Err(_) => Ok(None),
    }
}

fn save_state(path: &Path, record: &WatchdogRecord) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = serde_json::to_string_pretty(record)?;
    let temp_file = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&temp_file, content)?;
    let _ = std::fs::rename(&temp_file, path);
    Ok(())
}

fn current_time_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Pre-execution watchdog check against autonomous command execution loops.
pub fn check_before_execution(
    binary: &str,
    args: &[String],
    project_dir: Option<&Path>,
) -> Result<()> {
    if env::var("VETTO_ALLOW_LOOP").map(|v| v == "1").unwrap_or(false)
        || args.iter().any(|a| a == "--no-loop-guard")
    {
        return Ok(());
    }

    let root = resolve_project_root(project_dir)?;
    let current_mtime = scan_workspace_mtime(&root);
    let state_file = state_file_path(&root)?;

    let state = match load_state(&state_file)? {
        Some(s) => s,
        None => return Ok(()),
    };

    let threshold = env::var("VETTO_LOOP_THRESHOLD")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(4);

    let clean_args: Vec<String> = args
        .iter()
        .filter(|a| *a != "--no-loop-guard")
        .cloned()
        .collect();
    let current_cmd = canonicalize_command(binary, &clean_args);

    if state.consecutive_failures >= threshold
        && state.command == current_cmd
        && current_mtime <= state.last_workspace_mtime
    {
        let count = state.consecutive_failures;
        if std::io::stdin().is_terminal() {
            eprintln!(
                "[VETTO WATCHDOG] Loop detected: '{current_cmd}' failed \
                 {count} times consecutively without file changes."
            );
            eprint!("Proceed anyway? [y/N]: ");
            let _ = std::io::stderr().flush();

            let mut response = String::new();
            std::io::stdin().read_line(&mut response)?;
            let trimmed = response.trim().to_ascii_lowercase();

            if trimmed == "y" || trimmed == "yes" {
                let reset_record = WatchdogRecord {
                    command: current_cmd,
                    consecutive_failures: 0,
                    last_workspace_mtime: current_mtime,
                    last_updated_at: current_time_secs(),
                    workspace: root.display().to_string(),
                };
                let _ = save_state(&state_file, &reset_record);
                return Ok(());
            } else {
                bail!("[VETTO WATCHDOG] Execution halted by user.");
            }
        } else {
            bail!(
                "[VETTO WATCHDOG] Autonomous execution loop detected: '{current_cmd}' \
                 failed {count} times consecutively without workspace modifications. \
                 Halted to prevent token burn (bypass with VETTO_ALLOW_LOOP=1)."
            );
        }
    }

    Ok(())
}

/// Post-execution recording of command exit status and failure counts.
pub fn record_after_execution(
    binary: &str,
    args: &[String],
    exit_code: i32,
    project_dir: Option<&Path>,
) -> Result<()> {
    let root = resolve_project_root(project_dir)?;
    let clean_args: Vec<String> = args
        .iter()
        .filter(|a| *a != "--no-loop-guard")
        .cloned()
        .collect();
    let current_cmd = canonicalize_command(binary, &clean_args);
    let current_mtime = scan_workspace_mtime(&root);
    let state_file = state_file_path(&root)?;
    let prev_state = load_state(&state_file)?;

    if exit_code == 0 {
        let record = WatchdogRecord {
            command: current_cmd,
            consecutive_failures: 0,
            last_workspace_mtime: current_mtime,
            last_updated_at: current_time_secs(),
            workspace: root.display().to_string(),
        };
        save_state(&state_file, &record)?;
    } else {
        let is_same_unmodified = match prev_state {
            Some(ref prev) => {
                prev.command == current_cmd && current_mtime <= prev.last_workspace_mtime
            }
            None => false,
        };

        let consecutive_failures = if is_same_unmodified {
            prev_state
                .as_ref()
                .map(|p| p.consecutive_failures.saturating_add(1))
                .unwrap_or(1)
        } else {
            1
        };

        let last_workspace_mtime = if is_same_unmodified {
            prev_state
                .as_ref()
                .map(|p| p.last_workspace_mtime.max(current_mtime))
                .unwrap_or(current_mtime)
        } else {
            current_mtime
        };

        let record = WatchdogRecord {
            command: current_cmd,
            consecutive_failures,
            last_workspace_mtime,
            last_updated_at: current_time_secs(),
            workspace: root.display().to_string(),
        };
        save_state(&state_file, &record)?;
    }

    Ok(())
}

/// Deletes all persistent watchdog state files.
pub fn clear_all_records() -> Result<usize> {
    let dir = watchdog_dir()?;
    if !dir.exists() {
        return Ok(0);
    }
    let mut cleared = 0usize;
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json")
            && std::fs::remove_file(&path).is_ok()
        {
            cleared += 1;
        }
    }
    Ok(cleared)
}

/// Lists all persisted watchdog records.
pub fn list_records() -> Result<Vec<WatchdogRecord>> {
    let dir = watchdog_dir()?;
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in std::fs::read_dir(&dir)?.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(content) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Ok(rec) = serde_json::from_str::<WatchdogRecord>(&content) {
            records.push(rec);
        }
    }
    Ok(records)
}

/// CLI entrypoint for `vetto watchdog`.
pub fn run_cli(args: &WatchdogArgs) -> Result<()> {
    if args.clear {
        let cleared = clear_all_records()?;
        println!("vetto watchdog: cleared {cleared} stored watchdog record(s).");
        return Ok(());
    }

    let records = list_records()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&records)?);
        return Ok(());
    }

    if records.is_empty() {
        println!("vetto watchdog: no active loop records found.");
        return Ok(());
    }

    println!("Vetto Autonomous Loop & Token Burn Watchdog");
    println!("Monitored Workspaces: {}", records.len());
    println!();

    for rec in &records {
        let ws = if rec.workspace.is_empty() {
            "<unspecified workspace>"
        } else {
            &rec.workspace
        };
        println!("  Workspace: {ws}");
        println!("    Failures: {}", rec.consecutive_failures);
        println!("    Command:  {}", rec.command);
        println!("    Updated:  epoch {}s", rec.last_updated_at);
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    static TEST_LOCK: Mutex<()> = Mutex::new(());
    static COUNTER: AtomicUsize = AtomicUsize::new(1);

    fn setup_test_dirs(name: &str) -> (PathBuf, PathBuf) {
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let base = env::temp_dir().join(format!("vetto_wd_{name}_{}_{id}", std::process::id()));
        let wd_dir = base.join("watchdog");
        let proj_dir = base.join("project");
        std::fs::create_dir_all(&wd_dir).unwrap();
        std::fs::create_dir_all(&proj_dir).unwrap();
        (wd_dir, proj_dir)
    }

    fn cleanup_test_dirs(wd: &Path, proj: &Path) {
        let _ = std::fs::remove_dir_all(wd);
        let _ = std::fs::remove_dir_all(proj);
        if let Some(parent) = wd.parent() {
            let _ = std::fs::remove_dir_all(parent);
        }
        env::remove_var("VETTO_WATCHDOG_DIR");
        env::remove_var("VETTO_ALLOW_LOOP");
        env::remove_var("VETTO_LOOP_THRESHOLD");
    }

    #[test]
    fn test_watchdog_resets_on_success() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("resets_on_success");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();

        let state_file = state_file_path(&temp_proj).unwrap();
        let state = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state.consecutive_failures, 2);

        record_after_execution("cargo", &args, 0, Some(&temp_proj)).unwrap();

        let state_after = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state_after.consecutive_failures, 0);

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_resets_on_workspace_modification() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("resets_on_mod");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() { // v1\n}").unwrap();

        let args = vec!["check".to_string()];
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();

        let state_file = state_file_path(&temp_proj).unwrap();
        let state = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state.consecutive_failures, 2);

        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&file_path, "fn main() { // v2 modified\n}").unwrap();

        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();

        let state_after = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state_after.consecutive_failures, 1);

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_triggers_after_threshold() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("triggers_threshold");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        for _ in 0..4 {
            record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        }

        let state_file = state_file_path(&temp_proj).unwrap();
        let state = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state.consecutive_failures, 4);

        let res = check_before_execution("cargo", &args, Some(&temp_proj));
        assert!(res.is_err(), "watchdog should trigger loop detection after 4 failures");
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains("Autonomous execution loop detected")
                || err_msg.contains("Loop detected"),
            "unexpected error message: {err_msg}"
        );

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_different_command_resets_counter() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("diff_cmd");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let cmd1 = vec!["check".to_string()];
        record_after_execution("cargo", &cmd1, 1, Some(&temp_proj)).unwrap();
        record_after_execution("cargo", &cmd1, 1, Some(&temp_proj)).unwrap();
        record_after_execution("cargo", &cmd1, 1, Some(&temp_proj)).unwrap();

        let state_file = state_file_path(&temp_proj).unwrap();
        let state = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state.consecutive_failures, 3);
        assert_eq!(state.command, "cargo check");

        let cmd2 = vec!["test".to_string()];
        record_after_execution("cargo", &cmd2, 1, Some(&temp_proj)).unwrap();

        let state_after = load_state(&state_file).unwrap().unwrap();
        assert_eq!(state_after.consecutive_failures, 1);
        assert_eq!(state_after.command, "cargo test");

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_bypass_env_var() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("bypass_env");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        for _ in 0..4 {
            record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        }

        env::set_var("VETTO_ALLOW_LOOP", "1");
        let res = check_before_execution("cargo", &args, Some(&temp_proj));
        assert!(res.is_ok(), "VETTO_ALLOW_LOOP=1 should bypass check");

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_bypass_flag() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("bypass_flag");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        for _ in 0..4 {
            record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        }

        let args_with_flag = vec!["check".to_string(), "--no-loop-guard".to_string()];
        let res = check_before_execution("cargo", &args_with_flag, Some(&temp_proj));
        assert!(res.is_ok(), "--no-loop-guard should bypass check");

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_custom_threshold() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("custom_thresh");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        env::set_var("VETTO_LOOP_THRESHOLD", "2");
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        assert!(check_before_execution("cargo", &args, Some(&temp_proj)).is_ok());

        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();
        let res = check_before_execution("cargo", &args, Some(&temp_proj));
        assert!(res.is_err(), "threshold of 2 should trigger loop detection on 2nd failure");

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }

    #[test]
    fn test_watchdog_clear_records() {
        let _guard = TEST_LOCK.lock().unwrap();
        let (temp_wd, temp_proj) = setup_test_dirs("clear_recs");
        env::set_var("VETTO_WATCHDOG_DIR", &temp_wd);
        let file_path = temp_proj.join("main.rs");
        std::fs::write(&file_path, "fn main() {}").unwrap();

        let args = vec!["check".to_string()];
        record_after_execution("cargo", &args, 1, Some(&temp_proj)).unwrap();

        let records = list_records().unwrap();
        assert_eq!(records.len(), 1);

        let cleared = clear_all_records().unwrap();
        assert_eq!(cleared, 1);

        let records_after = list_records().unwrap();
        assert_eq!(records_after.len(), 0);

        cleanup_test_dirs(&temp_wd, &temp_proj);
    }
}
