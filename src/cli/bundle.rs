//! Session Export & Replay Bundles (`vetto pack` and `vetto unpack`).
//!
//! Packages an incident session into a portable `.vetto-pack` bundle archive
//! containing snapshot files, logs, and security telemetry, or inspects/unpacks
//! an archive to reproduce incidents on another machine.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::cli::diff::{load_security_telemetry, read_tar_archive, read_tar_entries};
use crate::rescue::snapshot::{self, write_tar_entry, SnapshotMetadata};

/// CLI arguments for `vetto pack`.
#[derive(clap::Args, Debug, Clone)]
pub struct PackArgs {
    /// Session ID to package (defaults to the latest session for current workspace)
    #[arg(value_name = "SESSION_ID")]
    pub session_id: Option<String>,

    /// Output path for the bundle archive (default: <session_id>.vetto-pack)
    #[arg(short = 'o', long = "output", value_name = "PATH")]
    pub output: Option<String>,

    /// Include event logs in the bundle
    #[arg(long = "include-logs", default_value_t = true)]
    pub include_logs: bool,

    /// Attach redacted diagnostics (bug-report.json) for issue reports:
    /// denied paths only, no file contents or environment values
    #[arg(long = "bug")]
    pub bug: bool,
}

/// CLI arguments for `vetto unpack`.
#[derive(clap::Args, Debug, Clone)]
pub struct UnpackArgs {
    /// Path to the .vetto-pack archive
    #[arg(value_name = "BUNDLE")]
    pub bundle: String,

    /// Target directory to extract files into (defaults to ./<session_id>)
    #[arg(short = 't', long = "target", value_name = "PATH")]
    pub target: Option<String>,

    /// Display bundle metadata, security violations, and files without extracting to disk
    #[arg(short = 'i', long = "info")]
    pub info: bool,
}

/// Metadata manifest stored at `bundle.manifest.json` inside the `.vetto-pack` archive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleManifest {
    pub format_version: u32,
    pub session_id: String,
    pub created_at: String,
    pub project_dir: String,
    pub files_count: usize,
    pub snapshot_size_bytes: u64,
    pub blocked_filesystem_count: usize,
    pub blocked_network_count: usize,
    pub allowed_domains: Vec<String>,
}

/// Redacted diagnostics stored at `bug-report.json` inside the `.vetto-pack`
/// archive when packed with `vetto pack --bug`. Denied paths only — no file
/// contents, no environment values, no secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugReport {
    pub format_version: u32,
    pub vetto_version: String,
    pub os: String,
    pub arch: String,
    pub session_id: String,
    pub created_at: String,
    pub blocked_filesystem_count: usize,
    pub blocked_network_count: usize,
    pub blocked_file_paths: Vec<String>,
    pub blocked_network_destinations: Vec<String>,
}

/// Maximum denied-path entries kept in a bug report (counts are never truncated).
pub const BUG_REPORT_MAX_ENTRIES: usize = 50;

/// Computes the default bundle archive filename for a session.
pub fn default_bundle_name(session_id: &str) -> String {
    format!("{session_id}.vetto-pack")
}

/// Computes the default bundle archive path for a session.
pub fn default_bundle_path(session_id: &str) -> PathBuf {
    PathBuf::from(format!("./{session_id}.vetto-pack"))
}

/// Computes the default target extraction directory for a session.
pub fn default_target_dir(session_id: &str) -> PathBuf {
    PathBuf::from(format!("./{session_id}"))
}

/// Formats byte count into human-readable representation.
pub fn format_bytes(bytes: u64) -> String {
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

/// Resolves the target session snapshot metadata.
fn resolve_snapshot(session_id: Option<&str>) -> Result<SnapshotMetadata> {
    let snapshots = snapshot::list_snapshots()?;

    if let Some(req_id) = session_id {
        if let Some(s) = snapshots.iter().find(|s| s.session_id == req_id) {
            return Ok(s.clone());
        }

        let direct_path = Path::new(req_id);
        if direct_path.is_file() {
            return Ok(SnapshotMetadata {
                session_id: req_id.to_string(),
                created_at: String::new(),
                project_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                archive_file: direct_path.to_path_buf(),
                file_count: 0,
                total_size_bytes: 0,
            });
        }

        let root = snapshot::snapshots_root_dir()?;
        let snap_dir = root.join(req_id);
        let tar_file = snap_dir.join("snapshot.tar");
        if tar_file.is_file() {
            let meta_file = snap_dir.join("metadata.json");
            if let Ok(text) = std::fs::read_to_string(&meta_file) {
                if let Ok(meta) = serde_json::from_str::<SnapshotMetadata>(&text) {
                    return Ok(meta);
                }
            }
            return Ok(SnapshotMetadata {
                session_id: req_id.to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                project_dir: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                archive_file: tar_file,
                file_count: 0,
                total_size_bytes: 0,
            });
        }

        bail!(
            "snapshot for session '{req_id}' was not found ({} snapshot(s) visible)",
            snapshots.len()
        );
    }

    if snapshots.is_empty() {
        bail!("no snapshots found. Snapshots are created automatically before agent sessions.");
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

    Ok(matching.unwrap_or(&snapshots[0]).clone())
}

/// Package a session into a `.vetto-pack` bundle archive.
pub fn run_pack(args: &PackArgs) -> Result<()> {
    let target_snapshot = resolve_snapshot(args.session_id.as_deref())?;

    let archive_path = if target_snapshot.archive_file.is_file() {
        target_snapshot.archive_file.clone()
    } else {
        let root = snapshot::snapshots_root_dir()?;
        let fallback = root.join(&target_snapshot.session_id).join("snapshot.tar");
        if fallback.is_file() {
            fallback
        } else {
            bail!(
                "snapshot archive for session '{}' not found at '{}'",
                target_snapshot.session_id,
                target_snapshot.archive_file.display()
            );
        }
    };

    let snapshot_tar_bytes = std::fs::read(&archive_path).with_context(|| {
        format!(
            "failed to read snapshot archive '{}'",
            archive_path.display()
        )
    })?;
    let snapshot_size_bytes = snapshot_tar_bytes.len() as u64;

    let files_count = if target_snapshot.file_count > 0 {
        target_snapshot.file_count
    } else {
        read_tar_entries(&mut &snapshot_tar_bytes[..])
            .map(|m| m.len())
            .unwrap_or(0)
    };

    let telemetry =
        load_security_telemetry(&target_snapshot.session_id, &target_snapshot.project_dir);
    let blocked_filesystem_count =
        (telemetry.blocked_file_count as usize).max(telemetry.blocked_file_paths.len());
    let blocked_network_count = (telemetry.blocked_network_count as usize)
        .max(telemetry.blocked_network_destinations.len());
    let allowed_domains = telemetry.allowed_egress;

    let mut log_bytes: Option<Vec<u8>> = None;
    if args.include_logs {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from);
        if let Some(h) = home {
            let logs_dir = h.join(".vetto").join("logs");
            let sid = &target_snapshot.session_id;
            let stripped = sid.strip_prefix("session-").unwrap_or(sid);

            let candidates = [
                logs_dir.join(format!("{sid}.jsonl")),
                logs_dir.join(format!("{stripped}.jsonl")),
                logs_dir.join(format!("session-{sid}.jsonl")),
                logs_dir.join(format!("session-{stripped}.jsonl")),
            ];

            for cand in &candidates {
                if let Ok(data) = std::fs::read(cand) {
                    log_bytes = Some(data);
                    break;
                }
            }
        }
    }

    let manifest = BundleManifest {
        format_version: 1,
        session_id: target_snapshot.session_id.clone(),
        created_at: if target_snapshot.created_at.is_empty() {
            chrono::Utc::now().to_rfc3339()
        } else {
            target_snapshot.created_at.clone()
        },
        project_dir: target_snapshot.project_dir.to_string_lossy().to_string(),
        files_count,
        snapshot_size_bytes,
        blocked_filesystem_count,
        blocked_network_count,
        allowed_domains,
    };

    let manifest_json = serde_json::to_vec_pretty(&manifest)
        .context("failed to serialize bundle manifest to JSON")?;

    let mut bug_report_json: Option<Vec<u8>> = None;
    if args.bug {
        let report = BugReport {
            format_version: 1,
            vetto_version: env!("CARGO_PKG_VERSION").to_string(),
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            session_id: target_snapshot.session_id.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
            blocked_filesystem_count,
            blocked_network_count,
            blocked_file_paths: telemetry
                .blocked_file_paths
                .iter()
                .take(BUG_REPORT_MAX_ENTRIES)
                .cloned()
                .collect(),
            blocked_network_destinations: telemetry
                .blocked_network_destinations
                .iter()
                .take(BUG_REPORT_MAX_ENTRIES)
                .cloned()
                .collect(),
        };
        bug_report_json = Some(
            serde_json::to_vec_pretty(&report).context("failed to serialize bug report to JSON")?,
        );
    }

    let output_path = args
        .output
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_bundle_path(&target_snapshot.session_id));

    if let Some(parent) = output_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create output directory '{}'", parent.display()))?;
    }

    let mut out_file = File::create(&output_path)
        .with_context(|| format!("failed to create bundle file '{}'", output_path.display()))?;
    let now = std::time::SystemTime::now();

    write_tar_entry(&mut out_file, "bundle.manifest.json", &manifest_json, now)?;

    write_tar_entry(&mut out_file, "snapshot.tar", &snapshot_tar_bytes, now)?;

    if let Some(ref logs) = log_bytes {
        write_tar_entry(&mut out_file, "session.jsonl", logs, now)?;
    }

    if let Some(ref bug) = bug_report_json {
        write_tar_entry(&mut out_file, "bug-report.json", bug, now)?;
    }

    out_file.write_all(&[0u8; 1024])?;
    out_file.flush()?;

    println!("✓ Vetto session packaged: {}", output_path.display());
    println!("  Session ID: {}", manifest.session_id);
    println!(
        "  Files in snapshot: {} | Size: {}",
        manifest.files_count,
        format_bytes(manifest.snapshot_size_bytes)
    );
    println!(
        "  Security events: {} fs blocked, {} net blocked",
        manifest.blocked_filesystem_count, manifest.blocked_network_count
    );
    if args.bug {
        println!(
            "  Bug report: bug-report.json attached (denied paths only, no file contents or env)"
        );
    }
    println!("  Unpack with: vetto unpack {}", output_path.display());

    Ok(())
}

/// Unpack or inspect a `.vetto-pack` bundle archive.
pub fn run_unpack(args: &UnpackArgs) -> Result<()> {
    let bundle_path = Path::new(&args.bundle);
    if !bundle_path.is_file() {
        bail!("bundle archive not found at '{}'", bundle_path.display());
    }

    let bundle_entries = read_tar_archive(bundle_path)?;

    let manifest_bytes = bundle_entries
        .get("bundle.manifest.json")
        .or_else(|| bundle_entries.get("./bundle.manifest.json"))
        .context("bundle is invalid: missing 'bundle.manifest.json'")?;
    let manifest: BundleManifest = serde_json::from_slice(manifest_bytes)
        .context("failed to parse 'bundle.manifest.json' from bundle")?;

    if args.info {
        let domains_str = if manifest.allowed_domains.is_empty() {
            "none".to_string()
        } else {
            manifest.allowed_domains.join(", ")
        };
        println!("=== Vetto Bundle Info: {} ===", args.bundle);
        println!("Session ID:  {}", manifest.session_id);
        println!("Created:     {}", manifest.created_at);
        println!("Original:    {}", manifest.project_dir);
        println!(
            "Files:       {} ({} bytes)",
            manifest.files_count, manifest.snapshot_size_bytes
        );
        println!(
            "Security:    {} blocked fs paths, {} blocked egress",
            manifest.blocked_filesystem_count, manifest.blocked_network_count
        );
        println!("Domains:     {}", domains_str);
        if bundle_entries.contains_key("bug-report.json")
            || bundle_entries.contains_key("./bug-report.json")
        {
            println!("Bug report:  bug-report.json attached (--bug)");
        }
        return Ok(());
    }

    let target_dir = args
        .target
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(|| default_target_dir(&manifest.session_id));

    std::fs::create_dir_all(&target_dir)
        .with_context(|| format!("failed to create target dir '{}'", target_dir.display()))?;

    let mut files_restored = 0usize;

    let snapshot_entry = bundle_entries
        .get("snapshot.tar")
        .or_else(|| bundle_entries.get("./snapshot.tar"));

    if let Some(snapshot_bytes) = snapshot_entry {
        let inner_entries = read_tar_entries(&mut &snapshot_bytes[..])
            .context("failed to unpack inner 'snapshot.tar'")?;

        for (rel_path, data) in inner_entries {
            let clean_path = Path::new(&rel_path);
            if clean_path.is_absolute()
                || clean_path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                continue;
            }

            let out_path = target_dir.join(clean_path);
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&out_path, &data).with_context(|| {
                format!("failed to write restored file '{}'", out_path.display())
            })?;
            files_restored += 1;
        }
    }

    let manifest_dest = target_dir.join("bundle.manifest.json");
    std::fs::write(&manifest_dest, manifest_bytes)
        .with_context(|| format!("failed to write manifest to '{}'", manifest_dest.display()))?;

    let session_logs = bundle_entries
        .get("session.jsonl")
        .or_else(|| bundle_entries.get("./session.jsonl"));

    if let Some(logs) = session_logs {
        let log_dest = target_dir.join("session.jsonl");
        std::fs::write(&log_dest, logs)
            .with_context(|| format!("failed to write logs to '{}'", log_dest.display()))?;
    }

    let bug_report = bundle_entries
        .get("bug-report.json")
        .or_else(|| bundle_entries.get("./bug-report.json"));

    if let Some(bug) = bug_report {
        let bug_dest = target_dir.join("bug-report.json");
        std::fs::write(&bug_dest, bug)
            .with_context(|| format!("failed to write bug report to '{}'", bug_dest.display()))?;
    }

    println!("✓ Vetto bundle extracted to {}", target_dir.display());
    println!("  Files restored: {files_restored}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    use crate::cli::TEST_ENV_LOCK;

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-bundle-{tag}-{}-{}",
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
    fn test_pack_args_default_names() {
        let sid = "session-test-42";
        assert_eq!(default_bundle_name(sid), "session-test-42.vetto-pack");
        assert_eq!(
            default_bundle_path(sid),
            PathBuf::from("./session-test-42.vetto-pack")
        );
        assert_eq!(default_target_dir(sid), PathBuf::from("./session-test-42"));

        let pack_args = PackArgs {
            session_id: None,
            output: None,
            include_logs: true,
            bug: false,
        };
        assert!(pack_args.include_logs);
        assert!(pack_args.session_id.is_none());
        assert!(pack_args.output.is_none());
        assert!(!pack_args.bug);

        let unpack_args = UnpackArgs {
            bundle: "test.vetto-pack".to_string(),
            target: None,
            info: false,
        };
        assert_eq!(unpack_args.bundle, "test.vetto-pack");
        assert!(unpack_args.target.is_none());
        assert!(!unpack_args.info);
    }

    #[test]
    fn test_unpack_nonexistent_bundle_fails() {
        let args = UnpackArgs {
            bundle: "nonexistent_bundle_for_vetto_test.vetto-pack".to_string(),
            target: None,
            info: false,
        };
        let res = run_unpack(&args);
        assert!(res.is_err());
        let err_str = res.unwrap_err().to_string();
        assert!(err_str.contains("not found"));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            if bound == 0 {
                0
            } else {
                self.next() % bound
            }
        }
    }

    fn pick_piece(rng: &mut Lcg) -> &'static str {
        match rng.below(12) {
            0 => "a",
            1 => "Z",
            2 => "0",
            3 => "é",
            4 => "€",
            5 => "😀",
            6 => "\"",
            7 => "\\",
            8 => "\n",
            9 => "\0",
            10 => "/",
            _ => "",
        }
    }

    fn arb_string(rng: &mut Lcg, max_len: usize) -> String {
        let len = rng.below(max_len as u64 + 1) as usize;
        let mut s = String::new();
        for _ in 0..len {
            s.push_str(pick_piece(rng));
        }
        s
    }

    fn arb_vec(rng: &mut Lcg) -> Vec<String> {
        let n = rng.below(5) as usize;
        let mut v = Vec::new();
        for _ in 0..n {
            v.push(arb_string(rng, 24));
        }
        v
    }

    #[test]
    fn prop_bundle_manifest_roundtrip() {
        let mut rng = Lcg(0x1234_5678_9abc_def0);
        for _ in 0..128 {
            let orig = BundleManifest {
                format_version: rng.next() as u32,
                session_id: arb_string(&mut rng, 32),
                created_at: arb_string(&mut rng, 32),
                project_dir: arb_string(&mut rng, 48),
                files_count: rng.below(100_000) as usize,
                snapshot_size_bytes: rng.next(),
                blocked_filesystem_count: rng.below(1000) as usize,
                blocked_network_count: rng.below(1000) as usize,
                allowed_domains: arb_vec(&mut rng),
            };
            let json = serde_json::to_vec(&orig).expect("serialize");
            let back: BundleManifest = serde_json::from_slice(&json).expect("parse");
            assert_eq!(orig, back);
        }
    }

    #[test]
    fn prop_bug_report_roundtrip() {
        let mut rng = Lcg(0xdead_beef_cafe_f00d);
        for _ in 0..128 {
            let orig = BugReport {
                format_version: rng.next() as u32,
                vetto_version: arb_string(&mut rng, 24),
                os: arb_string(&mut rng, 16),
                arch: arb_string(&mut rng, 16),
                session_id: arb_string(&mut rng, 32),
                created_at: arb_string(&mut rng, 32),
                blocked_filesystem_count: rng.below(1000) as usize,
                blocked_network_count: rng.below(1000) as usize,
                blocked_file_paths: arb_vec(&mut rng),
                blocked_network_destinations: arb_vec(&mut rng),
            };
            let json = serde_json::to_vec(&orig).expect("serialize");
            let back: BugReport = serde_json::from_slice(&json).expect("parse");
            assert_eq!(orig.format_version, back.format_version);
            assert_eq!(orig.vetto_version, back.vetto_version);
            assert_eq!(orig.os, back.os);
            assert_eq!(orig.arch, back.arch);
            assert_eq!(orig.session_id, back.session_id);
            assert_eq!(orig.created_at, back.created_at);
            assert_eq!(orig.blocked_filesystem_count, back.blocked_filesystem_count);
            assert_eq!(orig.blocked_network_count, back.blocked_network_count);
            assert_eq!(orig.blocked_file_paths, back.blocked_file_paths);
            assert_eq!(
                orig.blocked_network_destinations,
                back.blocked_network_destinations
            );
        }
    }

    #[test]
    fn prop_bundle_manifest_huge_unicode() {
        let huge = "é€😀a".repeat(8192);
        let orig = BundleManifest {
            format_version: u32::MAX,
            session_id: huge.clone(),
            created_at: String::new(),
            project_dir: "/tmp/ünicode/€".to_string(),
            files_count: usize::MAX,
            snapshot_size_bytes: u64::MAX,
            blocked_filesystem_count: usize::MAX,
            blocked_network_count: 0,
            allowed_domains: vec![huge.clone(), String::new()],
        };
        let json = serde_json::to_vec(&orig).expect("serialize huge");
        let back: BundleManifest = serde_json::from_slice(&json).expect("parse huge");
        assert_eq!(orig, back);
    }

    #[test]
    fn prop_bundle_manifest_rejects_garbage() {
        for bad in ["", "{", "{\"format_version\":1", "null", "[]", "{}"] {
            let res: Result<BundleManifest, _> = serde_json::from_str(bad);
            assert!(res.is_err(), "input {bad:?} must fail");
        }
        for bad in ["", "{}", "null", "{\"format_version\":1}"] {
            let res: Result<BugReport, _> = serde_json::from_str(bad);
            assert!(res.is_err(), "input {bad:?} must fail");
        }
        let mut rng = Lcg(0x9e37_79b9_7f4a_7c15);
        for _ in 0..256 {
            let s = arb_string(&mut rng, 48);
            let a: Result<BundleManifest, _> = serde_json::from_str(&s);
            if let Ok(v) = a {
                let _ = serde_json::to_vec(&v).expect("reserialize");
            }
            let b: Result<BugReport, _> = serde_json::from_str(&s);
            if let Ok(v) = b {
                let _ = serde_json::to_vec(&v).expect("reserialize");
            }
        }
    }

    #[test]
    fn test_pack_and_unpack_roundtrip() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let temp_home = temp_test_dir("home-roundtrip");
        let old_home = std::env::var_os("HOME");
        let old_userprofile = std::env::var_os("USERPROFILE");
        std::env::set_var("HOME", &temp_home);
        std::env::set_var("USERPROFILE", &temp_home);

        let proj_dir = temp_test_dir("proj-roundtrip");
        let file_a = proj_dir.join("main.rs");
        let sub_dir = proj_dir.join("src");
        fs::create_dir_all(&sub_dir).unwrap();
        let file_b = sub_dir.join("lib.rs");

        fs::write(&file_a, "fn main() { println!(\"hello\"); }").unwrap();
        fs::write(&file_b, "pub fn add(a: i32, b: i32) -> i32 { a + b }").unwrap();

        let session_id = format!("test-roundtrip-{}", std::process::id());
        let meta =
            snapshot::create_snapshot(&proj_dir, &session_id, snapshot::DEFAULT_MAX_SNAPSHOT_SIZE)
                .expect("snapshot creation should succeed");
        assert_eq!(meta.file_count, 2);

        // Write a mock session log
        let logs_dir = temp_home.join(".vetto").join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        fs::write(
            logs_dir.join(format!("{session_id}.jsonl")),
            "{\"event\":\"test\"}\n",
        )
        .unwrap();

        let bundle_out = temp_test_dir("bundle-out").join("custom.vetto-pack");
        let pack_args = PackArgs {
            session_id: Some(session_id.clone()),
            output: Some(bundle_out.display().to_string()),
            include_logs: true,
            bug: true,
        };

        let pack_res = run_pack(&pack_args);
        assert!(pack_res.is_ok(), "pack failed: {:?}", pack_res);
        assert!(bundle_out.is_file(), "bundle archive file must exist");

        // Inspect with --info
        let info_args = UnpackArgs {
            bundle: bundle_out.display().to_string(),
            target: None,
            info: true,
        };
        let info_res = run_unpack(&info_args);
        assert!(info_res.is_ok(), "unpack --info failed: {:?}", info_res);

        // Unpack to target dir
        let extract_dir = temp_test_dir("extracted");
        let unpack_args = UnpackArgs {
            bundle: bundle_out.display().to_string(),
            target: Some(extract_dir.display().to_string()),
            info: false,
        };
        let unpack_res = run_unpack(&unpack_args);
        assert!(unpack_res.is_ok(), "unpack failed: {:?}", unpack_res);

        assert_eq!(
            fs::read_to_string(extract_dir.join("main.rs")).unwrap(),
            "fn main() { println!(\"hello\"); }"
        );
        assert_eq!(
            fs::read_to_string(extract_dir.join("src").join("lib.rs")).unwrap(),
            "pub fn add(a: i32, b: i32) -> i32 { a + b }"
        );
        assert!(extract_dir.join("bundle.manifest.json").is_file());
        assert!(extract_dir.join("session.jsonl").is_file());
        let bug_bytes = fs::read(extract_dir.join("bug-report.json"))
            .expect("bug-report.json must be extracted with --bug");
        let bug: BugReport =
            serde_json::from_slice(&bug_bytes).expect("bug-report.json must parse");
        assert_eq!(bug.session_id, session_id);
        assert_eq!(bug.vetto_version, env!("CARGO_PKG_VERSION"));

        if let Some(h) = old_home {
            std::env::set_var("HOME", h);
        } else {
            std::env::remove_var("HOME");
        }
        if let Some(u) = old_userprofile {
            std::env::set_var("USERPROFILE", u);
        } else {
            std::env::remove_var("USERPROFILE");
        }
        let _ = fs::remove_dir_all(&temp_home);
        let _ = fs::remove_dir_all(&proj_dir);
        let _ = fs::remove_dir_all(&extract_dir);
    }
}
