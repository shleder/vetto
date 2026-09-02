//! `vetto undo` CLI command implementation (Instant Rollback & Snapshot Management).
//!
//! Restores project files from a previous session snapshot, previews restore operations
//! via dry-run, and lists available snapshots across sessions.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

use crate::rescue::snapshot::{self, SnapshotMetadata};

/// Arguments for `vetto undo`.
#[derive(clap::Args, Debug, Clone)]
pub struct UndoArgs {
    /// Session ID to restore (defaults to the most recent snapshot for the current project)
    #[arg(value_name = "SESSION_ID")]
    pub session_id: Option<String>,

    /// List all available project snapshots with timestamps and file counts
    #[arg(short = 'l', long = "list")]
    pub list: bool,

    /// Preview files that would be restored without modifying disk
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Target directory to restore into (default: original project directory)
    #[arg(short = 't', long = "target", value_name = "PATH")]
    pub target: Option<String>,
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Execute the `vetto undo` command.
pub fn run_undo(args: &UndoArgs) -> Result<()> {
    let snapshots = snapshot::list_snapshots()?;

    if args.list {
        if snapshots.is_empty() {
            println!(
                "no snapshots found. Snapshots are created automatically before agent sessions."
            );
            return Ok(());
        }

        println!(
            "{:<16} {:<21} {:<7} {:<8} {}",
            "SESSION ID", "CREATED", "FILES", "SIZE", "PROJECT"
        );
        println!("-----------------------------------------------------------------");
        for s in &snapshots {
            let created = if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(&s.created_at) {
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            } else {
                s.created_at.chars().take(19).collect()
            };
            println!(
                "{:<16} {:<21} {:<7} {:<8} {}",
                s.session_id,
                created,
                s.file_count,
                format_bytes(s.total_size_bytes),
                s.project_dir.display()
            );
        }
        return Ok(());
    }

    if snapshots.is_empty() {
        bail!(
            "no snapshots found. Snapshots are created automatically before agent sessions."
        );
    }

    let target_snapshot: SnapshotMetadata = if let Some(ref req_id) = args.session_id {
        if let Some(s) = snapshots.iter().find(|s| s.session_id == *req_id) {
            s.clone()
        } else {
            let direct_path = Path::new(req_id);
            if direct_path.is_file() {
                SnapshotMetadata {
                    session_id: req_id.clone(),
                    created_at: String::new(),
                    project_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    archive_file: direct_path.to_path_buf(),
                    file_count: 0,
                    total_size_bytes: 0,
                }
            } else {
                let root = snapshot::snapshots_root_dir()?;
                if root.join(req_id).join("snapshot.tar").is_file() {
                    SnapshotMetadata {
                        session_id: req_id.clone(),
                        created_at: String::new(),
                        project_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                        archive_file: root.join(req_id).join("snapshot.tar"),
                        file_count: 0,
                        total_size_bytes: 0,
                    }
                } else {
                    bail!("snapshot '{req_id}' was not found");
                }
            }
        }
    } else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.clone());

        let matching = snapshots.iter().find(|s| {
            s.project_dir == cwd
                || s.project_dir
                    .canonicalize()
                    .map(|p| p == cwd_canonical)
                    .unwrap_or(false)
        });

        matching.unwrap_or(&snapshots[0]).clone()
    };

    let target_dir = args
        .target
        .as_deref()
        .map(Path::new)
        .unwrap_or(&target_snapshot.project_dir);

    if args.dry_run {
        let files = snapshot::inspect_snapshot_archive(&target_snapshot.session_id)?;
        println!(
            "vetto: previewing rollback for session '{}' (dry-run, no disk changes)",
            target_snapshot.session_id
        );
        println!("  Target: {}", target_dir.display());
        println!("  Files that would be restored ({}):", files.len());
        let mut total_bytes = 0u64;
        for (name, size) in &files {
            total_bytes += size;
            println!("    {:<50} ({} bytes)", name, size);
        }
        println!("  Total: {} file(s) | Bytes: {}", files.len(), total_bytes);
        return Ok(());
    }

    let res = snapshot::rollback_snapshot(
        &target_snapshot.session_id,
        args.target.as_deref().map(Path::new),
    )?;

    println!("vetto: restored snapshot from session {}", res.session_id);
    println!(
        "  Files restored: {} | Bytes: {}",
        res.files_restored, res.bytes_restored
    );
    println!("  Target: {}", res.target_dir.display());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-undo-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_undo_list_empty() {
        let _guard = TEST_LOCK.lock().unwrap();
        let temp_home = temp_test_dir("home-empty");
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &temp_home);

        let args = UndoArgs {
            session_id: None,
            list: true,
            dry_run: false,
            target: None,
        };

        let res = run_undo(&args);
        assert!(res.is_ok());

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        let _ = fs::remove_dir_all(&temp_home);
    }

    #[test]
    fn test_undo_restore_snapshot() {
        let _guard = TEST_LOCK.lock().unwrap();
        let temp_home = temp_test_dir("home-restore");
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &temp_home);

        let proj_dir = temp_test_dir("proj-restore");
        let file_a = proj_dir.join("a.txt");
        let sub_dir = proj_dir.join("sub");
        fs::create_dir_all(&sub_dir).unwrap();
        let file_b = sub_dir.join("b.txt");

        fs::write(&file_a, "original content a").unwrap();
        fs::write(&file_b, "original content b").unwrap();

        let session_id = format!("test-sess-restore-{}", std::process::id());
        let meta =
            snapshot::create_snapshot(&proj_dir, &session_id, snapshot::DEFAULT_MAX_SNAPSHOT_SIZE)
                .expect("create snapshot");
        assert_eq!(meta.file_count, 2);

        // Modify files
        fs::write(&file_a, "corrupted content a").unwrap();
        fs::write(&file_b, "corrupted content b").unwrap();

        let args = UndoArgs {
            session_id: Some(session_id),
            list: false,
            dry_run: false,
            target: Some(proj_dir.display().to_string()),
        };

        let res = run_undo(&args);
        assert!(res.is_ok(), "undo failed: {:?}", res);

        assert_eq!(fs::read_to_string(&file_a).unwrap(), "original content a");
        assert_eq!(fs::read_to_string(&file_b).unwrap(), "original content b");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        let _ = fs::remove_dir_all(&temp_home);
        let _ = fs::remove_dir_all(&proj_dir);
    }

    #[test]
    fn test_undo_dry_run() {
        let _guard = TEST_LOCK.lock().unwrap();
        let temp_home = temp_test_dir("home-dryrun");
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", &temp_home);

        let proj_dir = temp_test_dir("proj-dryrun");
        let file_a = proj_dir.join("a.txt");
        fs::write(&file_a, "original content a").unwrap();

        let session_id = format!("test-sess-dryrun-{}", std::process::id());
        let _meta =
            snapshot::create_snapshot(&proj_dir, &session_id, snapshot::DEFAULT_MAX_SNAPSHOT_SIZE)
                .expect("create snapshot");

        // Modify file
        fs::write(&file_a, "modified content a").unwrap();

        let args = UndoArgs {
            session_id: Some(session_id),
            list: false,
            dry_run: true,
            target: Some(proj_dir.display().to_string()),
        };

        let res = run_undo(&args);
        assert!(res.is_ok(), "dry run failed: {:?}", res);

        // Dry run must NOT modify disk
        assert_eq!(fs::read_to_string(&file_a).unwrap(), "modified content a");

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        let _ = fs::remove_dir_all(&temp_home);
        let _ = fs::remove_dir_all(&proj_dir);
    }
}
