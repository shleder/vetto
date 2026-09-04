//! `vetto diff` CLI command implementation (Autonomous Agent Session Review).
//!
//! Compares current project workspace against a session snapshot archive to surface
//! all filesystem changes (added, modified, deleted) and integrates security telemetry
//! (blocked file reads, blocked network egress, contacted domains).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::rescue::snapshot::{self, SnapshotMetadata};

/// Arguments for `vetto diff`.
#[derive(clap::Args, Debug, Clone)]
pub struct DiffArgs {
    /// Session ID to inspect (defaults to latest session for current workspace)
    #[arg(value_name = "SESSION_ID")]
    pub session_id: Option<String>,

    /// Display only summary statistics (+/- lines, file counts, security events)
    #[arg(short = 's', long = "stat")]
    pub stat: bool,

    /// Output review in structured JSON format
    #[arg(long = "json")]
    pub json: bool,

    /// Filter diff to a specific relative file or folder path
    #[arg(short = 'p', long = "path", value_name = "PATH")]
    pub path: Option<String>,
}

/// Security telemetry collected from session logs and reports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityTelemetry {
    pub blocked_file_count: u64,
    pub blocked_file_paths: Vec<String>,
    pub blocked_network_count: u64,
    pub blocked_network_destinations: Vec<String>,
    pub allowed_egress: Vec<String>,
}

/// Kind of file modification observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    Added,
    Modified,
    Deleted,
}

/// Details of a single file change between snapshot and working tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileChange {
    pub path: String,
    pub change_type: ChangeType,
    pub lines_added: usize,
    pub lines_deleted: usize,
    pub is_binary: bool,
    #[serde(skip_serializing)]
    pub color_patch: String,
    pub patch: String,
}

/// Completed session review data model.
#[derive(Debug, Clone)]
pub struct SessionReview {
    pub session_id: String,
    pub project_dir: PathBuf,
    pub security: SecurityTelemetry,
    pub files: Vec<FileChange>,
}

/// Structured JSON output representation of a session review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffReviewJson {
    pub session_id: String,
    pub project_dir: String,
    pub security: DiffSecurityJson,
    pub files: DiffFilesSummaryJson,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub diffs: Vec<DiffFilePatchJson>,
}

/// Security section in JSON review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSecurityJson {
    pub blocked_file_reads: u64,
    pub blocked_file_paths: Vec<String>,
    pub blocked_network: u64,
    pub blocked_network_destinations: Vec<String>,
    pub allowed_egress: Vec<String>,
}

/// Files change summary section in JSON review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFilesSummaryJson {
    pub added: Vec<DiffFileStatJson>,
    pub modified: Vec<DiffFileStatJson>,
    pub deleted: Vec<DiffFileStatJson>,
    pub total_changed: usize,
    pub total_lines_added: usize,
    pub total_lines_deleted: usize,
}

/// Single file statistic entry in JSON review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFileStatJson {
    pub path: String,
    pub lines_added: usize,
    pub lines_deleted: usize,
    pub is_binary: bool,
}

/// Unified diff patch entry in JSON review.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffFilePatchJson {
    pub path: String,
    pub change_type: String,
    pub patch: String,
}

impl SessionReview {
    /// Convert internal review to serializable JSON format.
    pub fn to_json(&self, include_patches: bool) -> DiffReviewJson {
        let mut added = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();
        let mut diffs = Vec::new();

        let mut total_lines_added = 0;
        let mut total_lines_deleted = 0;

        for f in &self.files {
            total_lines_added += f.lines_added;
            total_lines_deleted += f.lines_deleted;

            let stat = DiffFileStatJson {
                path: f.path.clone(),
                lines_added: f.lines_added,
                lines_deleted: f.lines_deleted,
                is_binary: f.is_binary,
            };

            match f.change_type {
                ChangeType::Added => added.push(stat),
                ChangeType::Modified => modified.push(stat),
                ChangeType::Deleted => deleted.push(stat),
            }

            if include_patches && !f.patch.is_empty() {
                diffs.push(DiffFilePatchJson {
                    path: f.path.clone(),
                    change_type: match f.change_type {
                        ChangeType::Added => "added".to_string(),
                        ChangeType::Modified => "modified".to_string(),
                        ChangeType::Deleted => "deleted".to_string(),
                    },
                    patch: f.patch.clone(),
                });
            }
        }

        DiffReviewJson {
            session_id: self.session_id.clone(),
            project_dir: self.project_dir.display().to_string(),
            security: DiffSecurityJson {
                blocked_file_reads: self.security.blocked_file_count,
                blocked_file_paths: self.security.blocked_file_paths.clone(),
                blocked_network: self.security.blocked_network_count,
                blocked_network_destinations: self.security.blocked_network_destinations.clone(),
                allowed_egress: self.security.allowed_egress.clone(),
            },
            files: DiffFilesSummaryJson {
                added,
                modified,
                deleted,
                total_changed: self.files.len(),
                total_lines_added,
                total_lines_deleted,
            },
            diffs,
        }
    }
}

/// Execute the `vetto diff` command.
pub fn run_diff(args: &DiffArgs) -> Result<()> {
    let snapshot_opt = resolve_session_and_snapshot(args.session_id.as_deref())?;

    let Some(snapshot_meta) = snapshot_opt else {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let in_git = cwd.join(".git").exists()
            || crate::policy::conditions::detect_git_branch(&cwd).is_some();

        if args.json {
            let empty_review = DiffReviewJson {
                session_id: args
                    .session_id
                    .clone()
                    .unwrap_or_else(|| "none".to_string()),
                project_dir: cwd.display().to_string(),
                security: DiffSecurityJson {
                    blocked_file_reads: 0,
                    blocked_file_paths: Vec::new(),
                    blocked_network: 0,
                    blocked_network_destinations: Vec::new(),
                    allowed_egress: Vec::new(),
                },
                files: DiffFilesSummaryJson {
                    added: Vec::new(),
                    modified: Vec::new(),
                    deleted: Vec::new(),
                    total_changed: 0,
                    total_lines_added: 0,
                    total_lines_deleted: 0,
                },
                diffs: Vec::new(),
            };
            let json_text = serde_json::to_string_pretty(&empty_review)?;
            println!("{json_text}");
            return Ok(());
        }

        println!(
            "vetto diff: no snapshot found for current workspace. \
             Snapshots are created automatically when running agents under vetto."
        );

        if in_git {
            if args.stat {
                let _ = std::process::Command::new("git")
                    .args(["status", "--short"])
                    .current_dir(&cwd)
                    .status();
            } else {
                let _ = std::process::Command::new("git")
                    .args(["diff"])
                    .current_dir(&cwd)
                    .status();
            }
        }

        return Ok(());
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let project_dir = if snapshot_meta.project_dir.is_dir() {
        snapshot_meta.project_dir.clone()
    } else {
        cwd
    };

    let archive_path = if snapshot_meta.archive_file.is_file() {
        snapshot_meta.archive_file.clone()
    } else {
        let root = snapshot::snapshots_root_dir()?;
        let fallback = root.join(&snapshot_meta.session_id).join("snapshot.tar");
        if fallback.is_file() {
            fallback
        } else {
            anyhow::bail!(
                "snapshot archive '{}' not found",
                snapshot_meta.archive_file.display()
            );
        }
    };

    let telemetry = load_security_telemetry(&snapshot_meta.session_id, &project_dir);

    let review = compare_snapshot_against_disk(
        &archive_path,
        &project_dir,
        args.path.as_deref(),
        &telemetry,
        &snapshot_meta.session_id,
    )?;

    if args.json {
        let json_val = review.to_json(!args.stat);
        let serialized = serde_json::to_string_pretty(&json_val)?;
        println!("{serialized}");
        return Ok(());
    }

    render_human_review(&review, args.stat);
    Ok(())
}

/// Print formatted human-readable terminal review.
fn render_human_review(review: &SessionReview, stat_only: bool) {
    let security = &review.security;

    let file_reads_str = if security.blocked_file_count == 0 {
        "0 (none)".to_string()
    } else {
        let paths_str = if security.blocked_file_paths.is_empty() {
            "none".to_string()
        } else if security.blocked_file_paths.len() > 4 {
            format!("{}, ...", security.blocked_file_paths[..4].join(", "))
        } else {
            security.blocked_file_paths.join(", ")
        };
        format!("{} ({})", security.blocked_file_count, paths_str)
    };

    let net_blocked_str = if security.blocked_network_count == 0 {
        "0 (none)".to_string()
    } else {
        let dests_str = if security.blocked_network_destinations.is_empty() {
            "none".to_string()
        } else if security.blocked_network_destinations.len() > 4 {
            format!(
                "{}, ...",
                security.blocked_network_destinations[..4].join(", ")
            )
        } else {
            security.blocked_network_destinations.join(", ")
        };
        format!("{} ({})", security.blocked_network_count, dests_str)
    };

    let egress_str = if security.allowed_egress.is_empty() {
        "none".to_string()
    } else if security.allowed_egress.len() > 5 {
        format!("{}, ...", security.allowed_egress[..5].join(", "))
    } else {
        security.allowed_egress.join(", ")
    };

    println!("=== Vetto Session Review: {} ===", review.session_id);
    println!("Project: {}", review.project_dir.display());
    println!("Security Interceptions:");
    println!("  • Blocked file reads: {file_reads_str}");
    println!("  • Blocked network:    {net_blocked_str}");
    println!("  • Allowed egress:     {egress_str}");
    println!("Files Modified:");

    if review.files.is_empty() {
        println!("  (no files modified)");
    } else {
        for change in &review.files {
            match change.change_type {
                ChangeType::Added => {
                    if change.is_binary {
                        println!("\x1b[32m  + {} (binary)\x1b[0m", change.path);
                    } else {
                        println!(
                            "\x1b[32m  + {} (+{} lines)\x1b[0m",
                            change.path, change.lines_added
                        );
                    }
                }
                ChangeType::Modified => {
                    if change.is_binary {
                        println!("\x1b[33m  ~ {} (binary)\x1b[0m", change.path);
                    } else {
                        println!(
                            "\x1b[33m  ~ {} (+{} / -{} lines)\x1b[0m",
                            change.path, change.lines_added, change.lines_deleted
                        );
                    }
                }
                ChangeType::Deleted => {
                    if change.is_binary {
                        println!("\x1b[31m  - {} (binary)\x1b[0m", change.path);
                    } else {
                        println!(
                            "\x1b[31m  - {} (-{} lines)\x1b[0m",
                            change.path, change.lines_deleted
                        );
                    }
                }
            }
        }
    }

    if stat_only {
        let total_added: usize = review.files.iter().map(|f| f.lines_added).sum();
        let total_deleted: usize = review.files.iter().map(|f| f.lines_deleted).sum();
        println!(
            "\nSummary: {} file(s) changed (+{} lines, -{} lines)",
            review.files.len(),
            total_added,
            total_deleted
        );
        return;
    }

    // Print clean unified color diff for modified/added files
    for change in &review.files {
        if !change.color_patch.is_empty() {
            println!();
            print!("{}", change.color_patch);
        }
    }
}

/// Resolves snapshot metadata from requested session ID or latest in current workspace.
pub fn resolve_session_and_snapshot(
    requested_session: Option<&str>,
) -> Result<Option<SnapshotMetadata>> {
    match snapshot::snapshots_root_dir() {
        Ok(dir) => resolve_session_and_snapshot_in(&dir, requested_session),
        // Same as before: unreadable HOME means "no snapshots", not an error.
        Err(_) => Ok(None),
    }
}

/// Same as [`resolve_session_and_snapshot`], but rooted at an explicit
/// directory. Production passes the real store root; tests pass a fresh
/// temp dir, which keeps them hermetic against the shared per-user store.
pub fn resolve_session_and_snapshot_in(
    snapshots_root: &Path,
    requested_session: Option<&str>,
) -> Result<Option<SnapshotMetadata>> {
    let snapshots = snapshot::list_snapshots_in(snapshots_root)?;

    if let Some(req_id) = requested_session {
        if let Some(s) = snapshots.iter().find(|s| {
            s.session_id == req_id
                || s.session_id.contains(req_id)
                || s.session_id.strip_prefix("session-") == Some(req_id)
        }) {
            return Ok(Some(s.clone()));
        }

        let direct_path = Path::new(req_id);
        if direct_path.is_file() {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            return Ok(Some(SnapshotMetadata {
                session_id: req_id.to_string(),
                created_at: String::new(),
                project_dir: cwd,
                archive_file: direct_path.to_path_buf(),
                file_count: 0,
                total_size_bytes: 0,
            }));
        }

        let candidate = snapshots_root.join(req_id).join("snapshot.tar");
        if candidate.is_file() {
            let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            return Ok(Some(SnapshotMetadata {
                session_id: req_id.to_string(),
                created_at: String::new(),
                project_dir: cwd,
                archive_file: candidate,
                file_count: 0,
                total_size_bytes: 0,
            }));
        }

        return Ok(None);
    }

    if snapshots.is_empty() {
        return Ok(None);
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.clone());

    let matching = snapshots.iter().find(|s| {
        s.project_dir == cwd
            || s.project_dir
                .canonicalize()
                .map(|p| p == cwd_canonical)
                .unwrap_or(false)
    });

    Ok(Some(matching.unwrap_or(&snapshots[0]).clone()))
}

/// Compare snapshot tar archive against disk files.
pub fn compare_snapshot_against_disk(
    archive_path: &Path,
    project_dir: &Path,
    path_filter: Option<&str>,
    telemetry: &SecurityTelemetry,
    session_id: &str,
) -> Result<SessionReview> {
    let snapshot_files = read_tar_archive(archive_path)?;
    let mut disk_files = scan_disk_files(project_dir)?;
    if let Ok(rel_archive) = archive_path.strip_prefix(project_dir) {
        let rel_str = rel_archive.to_string_lossy().replace('\\', "/");
        disk_files.remove(&rel_str);
    }

    let snapshot_keys: BTreeSet<&String> = snapshot_files.keys().collect();
    let disk_keys: BTreeSet<&String> = disk_files.keys().collect();

    let mut files = Vec::new();

    // 1. Added files: on disk, absent in snapshot
    for path in disk_keys.difference(&snapshot_keys) {
        if !matches_path_filter(path, path_filter) {
            continue;
        }
        let disk_bytes = &disk_files[*path];
        let is_bin = is_binary(disk_bytes);
        let (added, deleted, color_patch, plain_patch) = if is_bin {
            (
                0,
                0,
                format!("Binary file added: {}\n", path),
                format!("Binary file added: {}\n", path),
            )
        } else {
            let text = String::from_utf8_lossy(disk_bytes);
            let lines: Vec<&str> = text.lines().collect();
            format_unified_diff(path, &[], &lines, true, false)
        };

        files.push(FileChange {
            path: (*path).clone(),
            change_type: ChangeType::Added,
            lines_added: added,
            lines_deleted: deleted,
            is_binary: is_bin,
            color_patch,
            patch: plain_patch,
        });
    }

    // 2. Modified files: present in both, content differ
    for path in disk_keys.intersection(&snapshot_keys) {
        if !matches_path_filter(path, path_filter) {
            continue;
        }
        let snap_bytes = &snapshot_files[*path];
        let disk_bytes = &disk_files[*path];

        if snap_bytes == disk_bytes {
            continue;
        }

        let is_bin = is_binary(snap_bytes) || is_binary(disk_bytes);
        let (added, deleted, color_patch, plain_patch) = if is_bin {
            (
                0,
                0,
                format!("Binary files differ: {}\n", path),
                format!("Binary files differ: {}\n", path),
            )
        } else {
            let snap_text = String::from_utf8_lossy(snap_bytes);
            let disk_text = String::from_utf8_lossy(disk_bytes);
            let old_lines: Vec<&str> = snap_text.lines().collect();
            let new_lines: Vec<&str> = disk_text.lines().collect();
            format_unified_diff(path, &old_lines, &new_lines, false, false)
        };

        files.push(FileChange {
            path: (*path).clone(),
            change_type: ChangeType::Modified,
            lines_added: added,
            lines_deleted: deleted,
            is_binary: is_bin,
            color_patch,
            patch: plain_patch,
        });
    }

    // 3. Deleted files: present in snapshot, absent on disk
    for path in snapshot_keys.difference(&disk_keys) {
        if !matches_path_filter(path, path_filter) {
            continue;
        }
        let snap_bytes = &snapshot_files[*path];
        let is_bin = is_binary(snap_bytes);
        let (added, deleted, color_patch, plain_patch) = if is_bin {
            (
                0,
                0,
                format!("Binary file deleted: {}\n", path),
                format!("Binary file deleted: {}\n", path),
            )
        } else {
            let text = String::from_utf8_lossy(snap_bytes);
            let lines: Vec<&str> = text.lines().collect();
            format_unified_diff(path, &lines, &[], false, true)
        };

        files.push(FileChange {
            path: (*path).clone(),
            change_type: ChangeType::Deleted,
            lines_added: added,
            lines_deleted: deleted,
            is_binary: is_bin,
            color_patch,
            patch: plain_patch,
        });
    }

    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(SessionReview {
        session_id: session_id.to_string(),
        project_dir: project_dir.to_path_buf(),
        security: telemetry.clone(),
        files,
    })
}

/// Read entries and contents from a snapshot tar archive.
pub fn read_tar_archive(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open snapshot archive {}", path.display()))?;
    read_tar_entries(file)
}

/// Read tar entries from an arbitrary byte reader.
pub fn read_tar_entries<R: Read>(mut reader: R) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut entries = BTreeMap::new();
    loop {
        let mut header = [0u8; 512];
        let n = reader.read(&mut header)?;
        if n < 512 || header.iter().all(|&b| b == 0) {
            break;
        }

        let (name, size) = snapshot::parse_tar_header(&header)?;
        if name.is_empty() {
            break;
        }

        let mut data = vec![0u8; size as usize];
        reader.read_exact(&mut data)?;

        let padding = (512 - (size % 512)) % 512;
        if padding > 0 {
            let mut pad_buf = vec![0u8; padding as usize];
            reader.read_exact(&mut pad_buf)?;
        }

        let clean_path = Path::new(&name);
        if !clean_path.is_absolute()
            && !clean_path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            let normalized = name.replace('\\', "/");
            entries.insert(normalized, data);
        }
    }
    Ok(entries)
}

/// Scan current project directory, ignoring transient / toolchain folders.
pub fn scan_disk_files(root: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut queue = vec![root.to_path_buf()];

    while let Some(dir) = queue.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if !crate::policy::secretscan::is_ignored_directory(&name) {
                    queue.push(path);
                }
            } else if path.is_file() {
                if let Ok(rel) = path.strip_prefix(root) {
                    let rel_str = rel.to_string_lossy().replace('\\', "/");
                    if let Ok(bytes) = std::fs::read(&path) {
                        files.insert(rel_str, bytes);
                    }
                }
            }
        }
    }

    Ok(files)
}

/// Read and aggregate security telemetry for session from logs, reports, and history.
pub fn load_security_telemetry(session_id: &str, project_dir: &Path) -> SecurityTelemetry {
    let mut telemetry = SecurityTelemetry::default();
    let stripped = session_id.strip_prefix("session-").unwrap_or(session_id);

    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);

    // 1. Try JSONL log files
    let mut log_candidates = Vec::new();
    if let Some(ref h) = home {
        let logs_dir = h.join(".vetto").join("logs");
        log_candidates.push(logs_dir.join(format!("{session_id}.jsonl")));
        log_candidates.push(logs_dir.join(format!("{stripped}.jsonl")));
        log_candidates.push(logs_dir.join(format!("session-{session_id}.jsonl")));
        log_candidates.push(logs_dir.join(format!("session-{stripped}.jsonl")));

        if logs_dir.is_dir() {
            if let Ok(entries) = std::fs::read_dir(&logs_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    if (name.contains(session_id) || name.contains(stripped))
                        && name.ends_with(".jsonl")
                    {
                        log_candidates.push(p);
                    }
                }
            }
        }
    }

    for log_path in log_candidates {
        if log_path.is_file() {
            parse_jsonl_telemetry(&log_path, &mut telemetry);
            break;
        }
    }

    // 2. Try JSON report files in project and home
    let mut report_candidates = vec![
        project_dir.join(".vetto").join("reports"),
        project_dir.join(".vetto-reports"),
    ];
    if let Some(ref h) = home {
        report_candidates.push(h.join(".vetto").join("reports"));
    }

    for rep_dir in report_candidates {
        if !rep_dir.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&rep_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if (name.contains(session_id) || name.contains(stripped)) && name.ends_with(".json")
                {
                    parse_json_report_telemetry(&p, &mut telemetry);
                }
            }
        }
    }

    // 3. Fallback to audit history if needed
    if telemetry.blocked_file_count == 0 && telemetry.blocked_network_count == 0 {
        if let Ok(detail) = crate::audit::history::inspect_session(session_id) {
            for d in detail.filesystem_denials {
                telemetry.blocked_file_count += d.count;
                if !telemetry.blocked_file_paths.contains(&d.path) {
                    telemetry.blocked_file_paths.push(d.path);
                }
            }
            for n in detail.blocked_network {
                telemetry.blocked_network_count += n.count;
                if !telemetry
                    .blocked_network_destinations
                    .contains(&n.destination)
                {
                    telemetry.blocked_network_destinations.push(n.destination);
                }
            }
        }
    }

    telemetry.blocked_file_paths.sort();
    telemetry.blocked_file_paths.dedup();
    telemetry.blocked_network_destinations.sort();
    telemetry.blocked_network_destinations.dedup();
    telemetry.allowed_egress.sort();
    telemetry.allowed_egress.dedup();

    telemetry
}

fn parse_jsonl_telemetry(path: &Path, telemetry: &mut SecurityTelemetry) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) else {
            continue;
        };

        let event_type = val
            .get("event")
            .or_else(|| val.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        match event_type {
            "blocked_attempt" | "BlockedAttempt" => {
                let path = val.get("path").and_then(|v| v.as_str()).unwrap_or("");
                let source = val.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let count = val.get("count").and_then(|v| v.as_u64()).unwrap_or(1);
                let is_syscall = source.contains("seccomp")
                    || path.starts_with("syscall:")
                    || source == "syscall";

                if !is_syscall && !path.is_empty() {
                    telemetry.blocked_file_count += count;
                    let path_s = path.to_string();
                    if !telemetry.blocked_file_paths.contains(&path_s) {
                        telemetry.blocked_file_paths.push(path_s);
                    }
                }
            }
            "net_request" | "NetRequest" => {
                let host = val.get("host").and_then(|v| v.as_str()).unwrap_or("");
                let port = val.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
                let allowed = val.get("allowed").and_then(|v| v.as_bool()).unwrap_or(true);

                if !allowed {
                    telemetry.blocked_network_count += 1;
                    let dest = if port > 0 {
                        format!("{host}:{port}")
                    } else {
                        host.to_string()
                    };
                    if !dest.is_empty() && !telemetry.blocked_network_destinations.contains(&dest) {
                        telemetry.blocked_network_destinations.push(dest);
                    }
                } else if !host.is_empty() {
                    let host_s = host.to_string();
                    if !telemetry.allowed_egress.contains(&host_s) {
                        telemetry.allowed_egress.push(host_s);
                    }
                }
            }
            "net_quota_exceeded" | "NetQuotaExceeded" => {
                let host = val.get("host").and_then(|v| v.as_str()).unwrap_or("");
                telemetry.blocked_network_count += 1;
                if !host.is_empty() {
                    let host_s = host.to_string();
                    if !telemetry.blocked_network_destinations.contains(&host_s) {
                        telemetry.blocked_network_destinations.push(host_s);
                    }
                }
            }
            "dns_resolution" | "DnsResolution" | "egress_observed" | "EgressObserved" => {
                let host = val.get("host").and_then(|v| v.as_str()).unwrap_or("");
                if !host.is_empty() {
                    let host_s = host.to_string();
                    if !telemetry.allowed_egress.contains(&host_s) {
                        telemetry.allowed_egress.push(host_s);
                    }
                }
            }
            _ => {}
        }
    }
}

fn parse_json_report_telemetry(path: &Path, telemetry: &mut SecurityTelemetry) {
    let Ok(content) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) else {
        return;
    };

    if let Some(arr) = val.get("blocked_attempts").and_then(|v| v.as_array()) {
        for b in arr {
            let p = b.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let count = b.get("count").and_then(|v| v.as_u64()).unwrap_or(1);
            if !p.is_empty() {
                telemetry.blocked_file_count += count;
                let path_s = p.to_string();
                if !telemetry.blocked_file_paths.contains(&path_s) {
                    telemetry.blocked_file_paths.push(path_s);
                }
            }
        }
    }

    if let Some(arr) = val.get("net_requests").and_then(|v| v.as_array()) {
        for n in arr {
            let host = n.get("host").and_then(|v| v.as_str()).unwrap_or("");
            let port = n.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let allowed = n.get("allowed").and_then(|v| v.as_bool()).unwrap_or(true);
            if !allowed {
                telemetry.blocked_network_count += 1;
                let dest = if port > 0 {
                    format!("{host}:{port}")
                } else {
                    host.to_string()
                };
                if !dest.is_empty() && !telemetry.blocked_network_destinations.contains(&dest) {
                    telemetry.blocked_network_destinations.push(dest);
                }
            } else if !host.is_empty() {
                let host_s = host.to_string();
                if !telemetry.allowed_egress.contains(&host_s) {
                    telemetry.allowed_egress.push(host_s);
                }
            }
        }
    }

    if let Some(map) = val.get("network_summary").and_then(|v| v.as_object()) {
        for k in map.keys() {
            if !k.is_empty() && !telemetry.allowed_egress.contains(k) {
                telemetry.allowed_egress.push(k.clone());
            }
        }
    }

    if let Some(arr) = val.get("egress_connections").and_then(|v| v.as_array()) {
        for e in arr {
            let host = e.get("host").and_then(|v| v.as_str()).unwrap_or("");
            if !host.is_empty() {
                let host_s = host.to_string();
                if !telemetry.allowed_egress.contains(&host_s) {
                    telemetry.allowed_egress.push(host_s);
                }
            }
        }
    }
}

fn is_binary(bytes: &[u8]) -> bool {
    let probe_len = bytes.len().min(8192);
    if bytes[..probe_len].contains(&0) {
        return true;
    }
    std::str::from_utf8(bytes).is_err()
}

fn matches_path_filter(file_path: &str, filter: Option<&str>) -> bool {
    let Some(filter) = filter else {
        return true;
    };
    let norm_filter = filter
        .trim()
        .trim_start_matches("./")
        .trim_start_matches('/');
    if norm_filter.is_empty() {
        return true;
    }
    file_path == norm_filter
        || file_path.starts_with(&format!("{norm_filter}/"))
        || Path::new(file_path).starts_with(Path::new(norm_filter))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DiffOp<'a> {
    Equal(&'a str),
    Delete(&'a str),
    Insert(&'a str),
}

fn format_unified_diff(
    path: &str,
    old_lines: &[&str],
    new_lines: &[&str],
    is_added: bool,
    is_deleted: bool,
) -> (usize, usize, String, String) {
    if is_added {
        let lines_added = new_lines.len();
        let mut color_patch = format!(
            "\x1b[1;37m--- /dev/null\n+++ b/{path}\x1b[0m\n\
             \x1b[36m@@ -0,0 +1,{lines_added} @@\x1b[0m\n"
        );
        let mut plain_patch = format!(
            "--- /dev/null\n+++ b/{path}\n\
             @@ -0,0 +1,{lines_added} @@\n"
        );
        for l in new_lines {
            color_patch.push_str("\x1b[32m+");
            color_patch.push_str(l);
            color_patch.push_str("\x1b[0m\n");
            plain_patch.push('+');
            plain_patch.push_str(l);
            plain_patch.push('\n');
        }
        return (lines_added, 0, color_patch, plain_patch);
    }

    if is_deleted {
        let lines_deleted = old_lines.len();
        let mut color_patch = format!(
            "\x1b[1;37m--- a/{path}\n+++ /dev/null\x1b[0m\n\
             \x1b[36m@@ -1,{lines_deleted} +0,0 @@\x1b[0m\n"
        );
        let mut plain_patch = format!(
            "--- a/{path}\n+++ /dev/null\n\
             @@ -1,{lines_deleted} +0,0 @@\n"
        );
        for l in old_lines {
            color_patch.push_str("\x1b[31m-");
            color_patch.push_str(l);
            color_patch.push_str("\x1b[0m\n");
            plain_patch.push('-');
            plain_patch.push_str(l);
            plain_patch.push('\n');
        }
        return (0, lines_deleted, color_patch, plain_patch);
    }

    let ops = compute_diff_ops(old_lines, new_lines);
    let lines_added = ops
        .iter()
        .filter(|op| matches!(op, DiffOp::Insert(_)))
        .count();
    let lines_deleted = ops
        .iter()
        .filter(|op| matches!(op, DiffOp::Delete(_)))
        .count();

    if lines_added == 0 && lines_deleted == 0 {
        return (0, 0, String::new(), String::new());
    }

    let (color_body, plain_body) = render_hunks(&ops);
    let color_patch = format!("\x1b[1;37m--- a/{path}\n+++ b/{path}\x1b[0m\n{color_body}");
    let plain_patch = format!("--- a/{path}\n+++ b/{path}\n{plain_body}");

    (lines_added, lines_deleted, color_patch, plain_patch)
}

fn compute_diff_ops<'a>(old_lines: &[&'a str], new_lines: &[&'a str]) -> Vec<DiffOp<'a>> {
    let n = old_lines.len();
    let m = new_lines.len();

    let mut prefix_len = 0;
    while prefix_len < n && prefix_len < m && old_lines[prefix_len] == new_lines[prefix_len] {
        prefix_len += 1;
    }

    let mut suffix_len = 0;
    while suffix_len < (n - prefix_len)
        && suffix_len < (m - prefix_len)
        && old_lines[n - 1 - suffix_len] == new_lines[m - 1 - suffix_len]
    {
        suffix_len += 1;
    }

    let a = &old_lines[prefix_len..n - suffix_len];
    let b = &new_lines[prefix_len..m - suffix_len];
    let len_a = a.len();
    let len_b = b.len();

    let mut middle_ops = Vec::new();

    if len_a == 0 {
        for &line in b {
            middle_ops.push(DiffOp::Insert(line));
        }
    } else if len_b == 0 {
        for &line in a {
            middle_ops.push(DiffOp::Delete(line));
        }
    } else {
        let max_edits = len_a + len_b;
        let limit_d = max_edits.min(2000);
        let offset = max_edits as isize;
        let mut v = vec![0usize; 2 * max_edits + 1];
        let mut trace = Vec::with_capacity(limit_d + 1);
        let mut solved_d = None;

        for d in 0..=limit_d {
            trace.push(v.clone());
            let mut k = -(d as isize);
            while k <= d as isize {
                let k_idx = (k + offset) as usize;
                let mut x = if k == -(d as isize)
                    || (k != d as isize
                        && v[(k - 1 + offset) as usize] < v[(k + 1 + offset) as usize])
                {
                    v[(k + 1 + offset) as usize]
                } else {
                    v[(k - 1 + offset) as usize] + 1
                };
                let mut y = (x as isize - k) as usize;
                while x < len_a && y < len_b && a[x] == b[y] {
                    x += 1;
                    y += 1;
                }
                v[k_idx] = x;
                if x >= len_a && y >= len_b {
                    solved_d = Some(d);
                    break;
                }
                k += 2;
            }
            if solved_d.is_some() {
                break;
            }
        }

        if let Some(mut d) = solved_d {
            let mut x = len_a;
            let mut y = len_b;
            while d > 0 {
                let k = x as isize - y as isize;
                let prev_v = &trace[d];
                let prev_k = if k == -(d as isize)
                    || (k != d as isize
                        && prev_v[(k - 1 + offset) as usize] < prev_v[(k + 1 + offset) as usize])
                {
                    k + 1
                } else {
                    k - 1
                };
                let prev_x = prev_v[(prev_k + offset) as usize];
                let prev_y = (prev_x as isize - prev_k) as usize;

                while x > prev_x && y > prev_y {
                    middle_ops.push(DiffOp::Equal(a[x - 1]));
                    x -= 1;
                    y -= 1;
                }
                if x == prev_x {
                    middle_ops.push(DiffOp::Insert(b[y - 1]));
                    y -= 1;
                } else {
                    middle_ops.push(DiffOp::Delete(a[x - 1]));
                    x -= 1;
                }
                d -= 1;
            }
            while x > 0 && y > 0 {
                middle_ops.push(DiffOp::Equal(a[x - 1]));
                x -= 1;
                y -= 1;
            }
            middle_ops.reverse();
        } else {
            for &line in a {
                middle_ops.push(DiffOp::Delete(line));
            }
            for &line in b {
                middle_ops.push(DiffOp::Insert(line));
            }
        }
    }

    let mut ops = Vec::with_capacity(n + m);
    for &line in &old_lines[..prefix_len] {
        ops.push(DiffOp::Equal(line));
    }
    ops.extend(middle_ops);
    for &line in &old_lines[n - suffix_len..] {
        ops.push(DiffOp::Equal(line));
    }

    ops
}

fn render_hunks(ops: &[DiffOp]) -> (String, String) {
    let mut change_indices = Vec::new();
    for (i, op) in ops.iter().enumerate() {
        if !matches!(op, DiffOp::Equal(_)) {
            change_indices.push(i);
        }
    }

    if change_indices.is_empty() {
        return (String::new(), String::new());
    }

    let mut clusters: Vec<(usize, usize)> = Vec::new();
    let mut cur_start = change_indices[0];
    let mut cur_end = change_indices[0];

    for &idx in &change_indices[1..] {
        if idx <= cur_end + 6 {
            cur_end = idx;
        } else {
            clusters.push((cur_start, cur_end));
            cur_start = idx;
            cur_end = idx;
        }
    }
    clusters.push((cur_start, cur_end));

    let mut color_out = String::new();
    let mut plain_out = String::new();

    for (c_start, c_end) in clusters {
        let h_start = c_start.saturating_sub(3);
        let h_end = (c_end + 4).min(ops.len());

        let old_start = 1 + ops[..h_start]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_start = 1 + ops[..h_start]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();

        let old_count = ops[h_start..h_end]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Delete(_)))
            .count();
        let new_count = ops[h_start..h_end]
            .iter()
            .filter(|op| matches!(op, DiffOp::Equal(_) | DiffOp::Insert(_)))
            .count();

        let _ = writeln!(
            color_out,
            "\x1b[36m@@ -{old_start},{old_count} +{new_start},{new_count} @@\x1b[0m"
        );
        let _ = writeln!(
            plain_out,
            "@@ -{old_start},{old_count} +{new_start},{new_count} @@"
        );

        for op in &ops[h_start..h_end] {
            match op {
                DiffOp::Equal(l) => {
                    color_out.push(' ');
                    color_out.push_str(l);
                    color_out.push('\n');
                    plain_out.push(' ');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
                DiffOp::Delete(l) => {
                    color_out.push_str("\x1b[31m-");
                    color_out.push_str(l);
                    color_out.push_str("\x1b[0m\n");
                    plain_out.push('-');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
                DiffOp::Insert(l) => {
                    color_out.push_str("\x1b[32m+");
                    color_out.push_str(l);
                    color_out.push_str("\x1b[0m\n");
                    plain_out.push('+');
                    plain_out.push_str(l);
                    plain_out.push('\n');
                }
            }
        }
    }

    (color_out, plain_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_diff_empty_or_no_snapshot() {
        let args = DiffArgs {
            session_id: Some("nonexistent_session_id_404".to_string()),
            stat: false,
            json: false,
            path: None,
        };
        let result = run_diff(&args);
        assert!(
            result.is_ok(),
            "missing snapshot should be handled gracefully"
        );

        let args_none = DiffArgs {
            session_id: None,
            stat: true,
            json: true,
            path: None,
        };
        // The latest-snapshot branch depends on the shared per-user store
        // ($HOME/.vetto), which parallel tests and real dev-machine usage
        // pollute — asserting through run_diff here would be non-hermetic.
        // Exercise the resolver directly against a fresh empty store instead.
        let tmp = std::env::temp_dir().join(format!(
            "vetto-diff-test-store-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).expect("empty snapshot store");
        let result_none = resolve_session_and_snapshot_in(&tmp, args_none.session_id.as_deref())
            .expect("empty store resolves");
        assert!(
            result_none.is_none(),
            "empty snapshot store must resolve to None"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_diff_snapshot_comparison() {
        let temp_dir = std::env::temp_dir().join(format!(
            "vetto-diff-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let initial_path = temp_dir.join("initial.txt");
        let removed_path = temp_dir.join("removed.txt");
        std::fs::write(&initial_path, "line 1\nline 2\nline 3\n").unwrap();
        std::fs::write(&removed_path, "delete me\n").unwrap();

        let archive_path = temp_dir.join("snapshot.tar");
        let mut tar_file = std::fs::File::create(&archive_path).unwrap();
        snapshot::write_tar_entry(
            &mut tar_file,
            "initial.txt",
            b"line 1\nline 2\nline 3\n",
            std::time::SystemTime::now(),
        )
        .unwrap();
        snapshot::write_tar_entry(
            &mut tar_file,
            "removed.txt",
            b"delete me\n",
            std::time::SystemTime::now(),
        )
        .unwrap();
        tar_file.write_all(&[0u8; 1024]).unwrap();
        tar_file.flush().unwrap();
        drop(tar_file);

        // Modify initial.txt: change line 2, append line 4
        std::fs::write(
            &initial_path,
            "line 1\nline 2 modified\nline 3\nline 4 added\n",
        )
        .unwrap();
        // Remove removed.txt
        std::fs::remove_file(&removed_path).unwrap();
        // Add created.txt
        let created_path = temp_dir.join("created.txt");
        std::fs::write(&created_path, "new file\nsecond line\n").unwrap();

        let telemetry = SecurityTelemetry::default();
        let review = compare_snapshot_against_disk(
            &archive_path,
            &temp_dir,
            None,
            &telemetry,
            "test_session_123",
        )
        .unwrap();

        assert_eq!(review.files.len(), 3);

        let added_file = review
            .files
            .iter()
            .find(|f| f.path == "created.txt")
            .unwrap();
        assert_eq!(added_file.change_type, ChangeType::Added);
        assert_eq!(added_file.lines_added, 2);
        assert_eq!(added_file.lines_deleted, 0);

        let modified_file = review
            .files
            .iter()
            .find(|f| f.path == "initial.txt")
            .unwrap();
        assert_eq!(modified_file.change_type, ChangeType::Modified);
        assert_eq!(modified_file.lines_added, 2);
        assert_eq!(modified_file.lines_deleted, 1);

        let deleted_file = review
            .files
            .iter()
            .find(|f| f.path == "removed.txt")
            .unwrap();
        assert_eq!(deleted_file.change_type, ChangeType::Deleted);
        assert_eq!(deleted_file.lines_added, 0);
        assert_eq!(deleted_file.lines_deleted, 1);

        // Test with path filter
        let filtered_review = compare_snapshot_against_disk(
            &archive_path,
            &temp_dir,
            Some("initial.txt"),
            &telemetry,
            "test_session_123",
        )
        .unwrap();
        assert_eq!(filtered_review.files.len(), 1);
        assert_eq!(filtered_review.files[0].path, "initial.txt");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_diff_json_output() {
        let telemetry = SecurityTelemetry {
            blocked_file_count: 2,
            blocked_file_paths: vec!["/etc/shadow".to_string(), "/root/.ssh/id_rsa".to_string()],
            blocked_network_count: 1,
            blocked_network_destinations: vec!["1.2.3.4:443".to_string()],
            allowed_egress: vec!["api.anthropic.com".to_string()],
        };

        let review = SessionReview {
            session_id: "session-test-456".to_string(),
            project_dir: PathBuf::from("/home/user/myproject"),
            security: telemetry,
            files: vec![
                FileChange {
                    path: "src/main.rs".to_string(),
                    change_type: ChangeType::Modified,
                    lines_added: 5,
                    lines_deleted: 2,
                    is_binary: false,
                    color_patch: String::new(),
                    patch: "--- a/src/main.rs\n+++ b/src/main.rs\n".to_string(),
                },
                FileChange {
                    path: "scratch.py".to_string(),
                    change_type: ChangeType::Deleted,
                    lines_added: 0,
                    lines_deleted: 10,
                    is_binary: false,
                    color_patch: String::new(),
                    patch: "--- a/scratch.py\n+++ /dev/null\n".to_string(),
                },
            ],
        };

        let json_val = review.to_json(true);
        let serialized = serde_json::to_string_pretty(&json_val).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed["session_id"], "session-test-456");
        assert_eq!(parsed["project_dir"], "/home/user/myproject");
        assert_eq!(parsed["security"]["blocked_file_reads"], 2);
        assert_eq!(parsed["security"]["blocked_file_paths"][0], "/etc/shadow");
        assert_eq!(parsed["security"]["blocked_network"], 1);
        assert_eq!(
            parsed["security"]["blocked_network_destinations"][0],
            "1.2.3.4:443"
        );
        assert_eq!(parsed["security"]["allowed_egress"][0], "api.anthropic.com");

        assert_eq!(parsed["files"]["total_changed"], 2);
        assert_eq!(parsed["files"]["total_lines_added"], 5);
        assert_eq!(parsed["files"]["total_lines_deleted"], 12);
        assert_eq!(parsed["files"]["modified"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["files"]["deleted"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["files"]["added"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["diffs"].as_array().unwrap().len(), 2);
    }
}
