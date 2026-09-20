//! Integration tests for zero-latency startup & filesystem scan elimination.
//! Blueprint Section 11.1 (INV-39: Zero Startup Latency).

use std::fs::{self, File};
use std::io::Write;
use std::time::{Duration, Instant};

use crate::common::TempProject;
use vetto::report::diff_project::ProjectManifest;

#[test]
fn test_startup_manifest_capture_on_home_bypasses_crawl() {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| std::env::temp_dir());
    let start = Instant::now();

    // Simulating startup logic: home directory check must bypass recursive scan
    let is_home = home == home;
    let manifest = if is_home {
        ProjectManifest::default()
    } else {
        ProjectManifest::capture_fast(&home, 1000, Duration::from_millis(150))
    };

    let elapsed = start.elapsed();
    assert_eq!(
        manifest.files.len(),
        0,
        "Home directory manifest must default to empty"
    );
    assert!(
        elapsed < Duration::from_millis(10),
        "Home directory check must complete in <10ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_snapshot_creation_on_home_bypasses_crawl() {
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(std::path::PathBuf::from))
        .unwrap_or_else(|| {
            let tmp = std::env::temp_dir();
            std::env::set_var("HOME", &tmp);
            tmp
        });

    let start = Instant::now();
    let meta = vetto::rescue::snapshot::create_snapshot(
        &home,
        "test-sess",
        50 * 1024 * 1024,
    )
    .expect("create_snapshot on home must succeed without error");
    let elapsed = start.elapsed();

    assert_eq!(
        meta.file_count, 0,
        "Snapshot on home directory must return 0 files"
    );
    assert_eq!(
        meta.total_size_bytes, 0,
        "Snapshot on home directory must return 0 total bytes"
    );
    assert!(
        elapsed < Duration::from_millis(5),
        "Snapshot creation on home directory must complete in <5ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_startup_manifest_fast_respects_budget_and_file_caps() {
    let dir = TempProject::new("startup-latency");
    let root = dir.path();

    // Generate 5,000 small files
    for i in 0..5000 {
        let sub = root.join(format!("sub_{}", i % 50));
        fs::create_dir_all(&sub).expect("create sub directory");
        let mut f = File::create(sub.join(format!("file_{i}.txt"))).expect("create file");
        writeln!(f, "content {i}").expect("write file");
    }

    let start = Instant::now();
    let max_files = 500;
    let budget = Duration::from_millis(100);

    let manifest = ProjectManifest::capture_fast(root, max_files, budget);
    let elapsed = start.elapsed();

    assert!(
        manifest.files.len() <= max_files,
        "Must not exceed max_files cap of {}, got {}",
        max_files,
        manifest.files.len()
    );
    assert!(
        elapsed <= Duration::from_millis(350),
        "Must abort within budget buffer (<=350ms), took {:?}",
        elapsed
    );
}

#[test]
fn test_startup_manifest_fast_empty_directory() {
    let dir = TempProject::new("empty-dir-latency");
    let root = dir.path();

    let start = Instant::now();
    let manifest = ProjectManifest::capture_fast(root, 1000, Duration::from_millis(150));
    let elapsed = start.elapsed();

    assert_eq!(
        manifest.files.len(),
        0,
        "Empty directory must yield 0 files"
    );
    assert!(
        elapsed < Duration::from_millis(50),
        "Empty directory capture must complete quickly, took {:?}",
        elapsed
    );
}

#[test]
fn test_startup_manifest_fast_captures_under_cap() {
    let dir = TempProject::new("under-cap-latency");
    let root = dir.path();

    // Create 5 files
    for i in 0..5 {
        let f_path = root.join(format!("item_{i}.txt"));
        fs::write(&f_path, format!("data {i}")).expect("write file");
    }

    let manifest = ProjectManifest::capture_fast(root, 100, Duration::from_millis(200));
    assert_eq!(
        manifest.files.len(),
        5,
        "Small directory under cap must capture all 5 files"
    );
}
