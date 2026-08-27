//! Rescue commands are host-side, read-only operations and do not require a
//! sandbox tier. These tests run on every supported platform.

use crate::common::*;
use rusqlite::Connection;
use std::fs;
use std::process::Command;

fn run_rescue(root: &std::path::Path, trailing: &[&str]) -> std::process::Output {
    run_rescue_with_adapter("codex", root, trailing)
}

fn run_rescue_with_adapter(
    adapter: &str,
    root: &std::path::Path,
    trailing: &[&str],
) -> std::process::Output {
    let mut command = Command::new(vetto_bin());
    command
        .arg("rescue")
        .arg("--adapter")
        .arg(adapter)
        .arg("--root")
        .arg(root)
        .arg("--json")
        .args(trailing)
        .output()
        .expect("spawn rescue command")
}

fn create_codex_sqlite_index(root: &std::path::Path, paths: &[&std::path::Path]) {
    let database = root.join("state_5.sqlite");
    let connection = Connection::open(database).expect("create synthetic Codex index");
    connection
        .execute(
            "CREATE TABLE threads (id TEXT PRIMARY KEY, rollout_path TEXT)",
            [],
        )
        .expect("create synthetic threads table");
    for (index, path) in paths.iter().enumerate() {
        connection
            .execute(
                "INSERT INTO threads (id, rollout_path) VALUES (?1, ?2)",
                rusqlite::params![index.to_string(), path.to_string_lossy().to_string()],
            )
            .expect("insert synthetic rollout index row");
    }
}

#[test]
fn codex_limited_scan_fails_closed_when_session_roots_are_missing() {
    let project = TempProject::new("rescue-index-no-roots");
    let root = project.path().join("codex-home");
    fs::create_dir_all(&root).expect("codex home");
    create_codex_sqlite_index(&root, &[]);

    let output = run_rescue(&root, &["scan", "--limit", "2"]);
    assert!(
        !output.status.success(),
        "an index without verifiable session roots must fail closed"
    );
    assert!(
        stderr(&output).contains("no real sessions directory exists"),
        "stderr: {}",
        stderr(&output)
    );
}

#[cfg(unix)]
#[test]
fn claude_scan_skips_symlinked_transcripts_instead_of_following_them() {
    let project = TempProject::new("rescue-claude-symlink");
    let root = project.path().join("claude-state");
    let target = root.join("projects/demo/real.jsonl");
    write_file(&target, "{\"type\":\"user\"}\n");
    std::os::unix::fs::symlink(&target, root.join("projects/demo/session.jsonl"))
        .expect("create transcript symlink");

    let scan = run_rescue_with_adapter("claude", &root, &["scan"]);
    assert!(scan.status.success(), "scan stderr: {}", stderr(&scan));
    let value: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("Claude scan JSON output");
    let keys = value["sessions"]
        .as_array()
        .expect("sessions array")
        .iter()
        .map(|session| session["key"].as_str().unwrap_or_default().to_string())
        .collect::<Vec<_>>();
    assert_eq!(keys, vec!["projects/demo/real.jsonl".to_string()]);
}

#[test]
fn unknown_adapter_is_explicitly_unsupported() {
    let project = TempProject::new("rescue-unknown-adapter");
    let output = Command::new(vetto_bin())
        .args([
            "rescue",
            "--adapter",
            "not-a-real-adapter",
            "--root",
            project.path().to_str().expect("UTF-8 test path"),
            "--json",
            "scan",
        ])
        .output()
        .expect("spawn rescue command");
    assert!(!output.status.success(), "unknown adapter must fail closed");
    assert!(
        stderr(&output).contains("unsupported rescue adapter"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn codex_scan_rejects_limit_together_with_all_instead_of_ignoring_it() {
    let project = TempProject::new("rescue-all-limit-conflict");
    let root = project.path().join("codex-state");
    write_file(
        &root.join("sessions/2026/08/23/rollout-1.jsonl"),
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"one\"}}\n",
    );
    let output = run_rescue(&root, &["scan", "--all", "--limit", "2"]);
    assert!(
        !output.status.success(),
        "--limit together with --all must fail closed instead of being ignored"
    );
    assert!(
        stderr(&output).contains("cannot be used with '--limit"),
        "stderr: {}",
        stderr(&output)
    );
}

#[test]
fn claude_adapter_requires_explicit_root_and_keeps_schema_opaque() {
    let project = TempProject::new("rescue-claude");
    let root = project.path().join("claude-state");
    write_file(
        &root.join("projects/demo/session.jsonl"),
        "{\"type\":\"user\",\"sessionId\":\"synthetic\"}\n",
    );
    write_file(&root.join("projects/demo/credentials.jsonl"), "secret\n");

    let scan = run_rescue_with_adapter("claude", &root, &["scan"]);
    assert!(scan.status.success(), "scan stderr: {}", stderr(&scan));
    let scan_json: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("Claude scan JSON output");
    assert_eq!(scan_json["status"]["support_level"], "full-repair");
    assert_eq!(scan_json["sessions"].as_array().map(Vec::len), Some(1));
    assert!(!stdout(&scan).contains("credentials.jsonl"));

    let key = scan_json["sessions"][0]["key"]
        .as_str()
        .expect("Claude session key");
    let diagnose = run_rescue_with_adapter("claude", &root, &["diagnose", key]);
    assert!(
        diagnose.status.success(),
        "diagnose stderr: {}",
        stderr(&diagnose)
    );
    let view: serde_json::Value =
        serde_json::from_slice(&diagnose.stdout).expect("Claude diagnosis JSON output");
    assert_eq!(view["health"], "healthy");
}

#[test]
fn scan_and_diagnose_are_bounded_to_codex_session_roots() {
    let project = TempProject::new("rescue-scan");
    let root = project.path().join("codex-home");
    let session = root.join("sessions/2026/08/23/session-a.jsonl");
    write_file(
        &session,
        "{\"type\":\"session_meta\",\"payload\":{\"id\":\"example\"}}\n{\"type\":\"turn\"}\n",
    );
    write_file(&root.join("auth.json"), "DO-NOT-READ");
    write_file(&root.join("config.toml"), "DO-NOT-READ");
    write_file(
        &root.join("logs/not-a-session.jsonl"),
        "{\"secret\":true}\n",
    );

    let scan = run_rescue(&root, &["scan", "--all"]);
    assert!(scan.status.success(), "scan stderr: {}", stderr(&scan));
    let scan_json: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("scan JSON output");
    let sessions = scan_json["sessions"].as_array().expect("session array");
    assert_eq!(sessions.len(), 1, "scan output: {}", stdout(&scan));
    let key = sessions[0]["key"].as_str().expect("session key");
    assert_eq!(key, "sessions/2026/08/23/session-a.jsonl");
    let serialized = stdout(&scan);
    assert!(!serialized.contains("auth.json"));
    assert!(!serialized.contains("config.toml"));
    assert!(!serialized.contains("not-a-session"));

    let diagnose = run_rescue(&root, &["diagnose", key]);
    assert!(
        diagnose.status.success(),
        "diagnose stderr: {}",
        stderr(&diagnose)
    );
    let view: serde_json::Value =
        serde_json::from_slice(&diagnose.stdout).expect("diagnose JSON output");
    assert_eq!(view["health"], "healthy");
    assert_eq!(view["records"], 2);
    assert_eq!(view["malformed_records"], 0);
}

#[test]
fn scan_discovers_nested_sessions_beyond_the_legacy_twenty_item_window() {
    let project = TempProject::new("rescue-scan-many-nested");
    let root = project.path().join("codex-home");
    for index in 0..25 {
        write_file(
            &root.join(format!(
                "sessions/2026/08/{:02}/rollout-{index:02}.jsonl",
                index + 1
            )),
            "{\"type\":\"turn\"}\n",
        );
    }

    let scan = run_rescue(&root, &["scan", "--all"]);
    assert!(scan.status.success(), "scan stderr: {}", stderr(&scan));
    let value: serde_json::Value = serde_json::from_slice(&scan.stdout).expect("scan JSON output");
    let sessions = value["sessions"].as_array().expect("session array");
    assert_eq!(sessions.len(), 25, "scan output: {}", stdout(&scan));
    assert!(sessions
        .iter()
        .any(|session| { session["key"] == "sessions/2026/08/25/rollout-24.jsonl" }));
}

#[test]
fn codex_default_scan_uses_index_first_with_a_fifty_session_limit() {
    let project = TempProject::new("rescue-index-default");
    let root = project.path().join("codex-home");
    let paths = (0..3)
        .map(|index| {
            let path = root.join(format!("sessions/2026/08/rollout-{index:02}.jsonl"));
            write_file(&path, "{\"type\":\"turn\"}\n");
            path
        })
        .collect::<Vec<_>>();
    let path_refs = paths
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect::<Vec<_>>();
    create_codex_sqlite_index(&root, &path_refs);

    let output = run_rescue(&root, &["scan"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("scan JSON");
    let discovery = &value["discovery"];
    assert_eq!(discovery["mode"], "index-first");
    assert_eq!(discovery["scope"], "provider-index");
    assert_eq!(discovery["source"], "sqlite");
    assert_eq!(discovery["limit"], 50);
    assert_eq!(discovery["complete"], true);
    assert_eq!(discovery["candidate_count"], 3);
    assert_eq!(discovery["returned_count"], 3);
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(3));
}

#[test]
fn codex_index_scan_reports_truncation_without_claiming_state_root_completeness() {
    let project = TempProject::new("rescue-index-limit");
    let root = project.path().join("codex-home");
    let paths = (0..55)
        .map(|index| {
            let path = root.join(format!("sessions/2026/08/rollout-{index:02}.jsonl"));
            write_file(&path, "{\"type\":\"turn\"}\n");
            path
        })
        .collect::<Vec<_>>();
    let path_refs = paths
        .iter()
        .map(std::path::PathBuf::as_path)
        .collect::<Vec<_>>();
    create_codex_sqlite_index(&root, &path_refs);

    let output = run_rescue(&root, &["scan", "--limit", "2"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("scan JSON");
    let discovery = &value["discovery"];
    assert_eq!(discovery["mode"], "index-first");
    assert_eq!(discovery["scope"], "provider-index");
    assert_eq!(discovery["source"], "sqlite");
    assert_eq!(discovery["limit"], 2);
    assert_eq!(discovery["complete"], false);
    assert_eq!(discovery["candidate_count"], 55);
    assert_eq!(discovery["returned_count"], 2);
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(2));
}

#[test]
fn codex_index_end_to_end_stays_index_first_over_ten_thousand_files() {
    let project = TempProject::new("rescue-index-large-e2e");
    let root = project.path().join("codex-home");
    let indexed = root.join("sessions/indexed/target.jsonl");
    write_file(&indexed, "{\"type\":\"turn\",\"ordinal\":1}\n");

    // A full filesystem walk would exceed the default 10,000-entry budget.
    // The provider index contains exactly one rollout, so the default scan
    // must still produce a trustworthy candidate and the exact-key commands
    // must not rediscover the tree.
    for bucket in 0..101 {
        let directory = root.join(format!("sessions/unindexed/{bucket:03}"));
        fs::create_dir_all(&directory).expect("large session directory");
        for item in 0..100 {
            fs::write(
                directory.join(format!("rollout-{item:03}.jsonl")),
                b"{\"type\":\"turn\"}\n",
            )
            .expect("large unindexed rollout");
        }
    }
    create_codex_sqlite_index(&root, &[&indexed]);

    let scan = run_rescue(&root, &["scan"]);
    assert!(scan.status.success(), "scan stderr: {}", stderr(&scan));
    let scan_json: serde_json::Value =
        serde_json::from_slice(&scan.stdout).expect("large scan JSON");
    assert_eq!(scan_json["discovery"]["mode"], "index-first");
    assert_eq!(scan_json["discovery"]["candidate_count"], 1);
    assert_eq!(scan_json["sessions"].as_array().map(Vec::len), Some(1));
    let key = scan_json["sessions"][0]["key"]
        .as_str()
        .expect("indexed exact key");
    assert_eq!(key, "sessions/indexed/target.jsonl");

    let diagnose = run_rescue(&root, &["diagnose", key]);
    assert!(
        diagnose.status.success(),
        "diagnose stderr: {}",
        stderr(&diagnose)
    );
    let view: serde_json::Value =
        serde_json::from_slice(&diagnose.stdout).expect("large diagnose JSON");
    assert_eq!(
        view["health"], "healthy",
        "unexpected diagnose view: {view}"
    );
    assert_eq!(view["records"], 1);

    let recovery = project.path().join("recovery");
    fs::create_dir_all(&recovery).expect("recovery directory");
    let output_path = recovery.join("target.jsonl");
    let snapshot = Command::new(vetto_bin())
        .args([
            "rescue",
            "--adapter",
            "codex",
            "--root",
            root.to_str().expect("UTF-8 root"),
            "--json",
            "snapshot",
            key,
            "--output",
            output_path.to_str().expect("UTF-8 output"),
        ])
        .output()
        .expect("snapshot command");
    assert!(
        snapshot.status.success(),
        "snapshot stderr: {}",
        stderr(&snapshot)
    );
    assert_eq!(
        fs::read(&output_path).expect("snapshot bytes"),
        b"{\"type\":\"turn\",\"ordinal\":1}\n"
    );
}

#[test]
fn codex_index_missing_rollout_fails_closed() {
    let project = TempProject::new("rescue-index-stale-e2e");
    let root = project.path().join("codex-home");
    let real = root.join("sessions/real.jsonl");
    write_file(&real, "{\"type\":\"turn\"}\n");
    let missing = root.join("sessions/missing.jsonl");
    create_codex_sqlite_index(&root, &[&missing]);

    let output = run_rescue(&root, &["scan", "--limit", "1"]);
    assert!(
        !output.status.success(),
        "stale index unexpectedly succeeded"
    );
    let error = stderr(&output);
    assert!(
        error.contains("unavailable") || error.contains("rollout"),
        "stale index error: {error}"
    );
}

#[test]
fn codex_short_basename_is_rejected_when_sessions_are_ambiguous() {
    let project = TempProject::new("rescue-exact-key-ambiguous");
    let root = project.path().join("codex-home");
    write_file(
        &root.join("sessions/shared.jsonl"),
        "{\"type\":\"turn\",\"root\":\"sessions\"}\n",
    );
    write_file(
        &root.join("archived_sessions/shared.jsonl"),
        "{\"type\":\"turn\",\"root\":\"archived\"}\n",
    );

    let output = run_rescue(&root, &["diagnose", "shared"]);
    assert!(
        !output.status.success(),
        "ambiguous basename unexpectedly worked"
    );
    assert!(
        stderr(&output).contains("ambiguous"),
        "ambiguity error: {}",
        stderr(&output)
    );
}

#[test]
fn codex_index_scan_tolerates_an_unbounded_cli_limit_without_aborting() {
    let project = TempProject::new("rescue-index-unbounded-limit");
    let root = project.path().join("codex-home");
    let path = root.join("sessions/2026/08/rollout-00.jsonl");
    write_file(&path, "{\"type\":\"turn\"}\n");
    create_codex_sqlite_index(&root, &[path.as_path()]);

    let output = run_rescue(&root, &["scan", "--limit", "1000000000000000"]);
    assert!(
        output.status.success(),
        "an unbounded --limit must not abort on allocation; stderr: {}",
        stderr(&output)
    );
}

#[test]
fn codex_all_scan_uses_the_bounded_filesystem_source() {
    let project = TempProject::new("rescue-index-all");
    let root = project.path().join("codex-home");
    let indexed = root.join("sessions/indexed.jsonl");
    let unindexed = root.join("sessions/unindexed.jsonl");
    write_file(&indexed, "{\"type\":\"turn\"}\n");
    write_file(&unindexed, "{\"type\":\"turn\"}\n");
    create_codex_sqlite_index(&root, &[&indexed]);

    let output = run_rescue(&root, &["scan", "--all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("scan JSON");
    let discovery = &value["discovery"];
    assert_eq!(discovery["mode"], "filesystem-all");
    assert_eq!(discovery["scope"], "session-roots");
    assert_eq!(discovery["source"], "session-roots");
    assert_eq!(discovery["limit"], serde_json::Value::Null);
    assert_eq!(discovery["complete"], true);
    assert_eq!(discovery["candidate_count"], 2);
    assert_eq!(discovery["returned_count"], 2);
    let sessions = value["sessions"].as_array().expect("session array");
    assert_eq!(sessions.len(), 2);
    assert!(sessions
        .iter()
        .any(|session| session["key"] == "sessions/indexed.jsonl"));
    assert!(sessions
        .iter()
        .any(|session| session["key"] == "sessions/unindexed.jsonl"));
}

#[test]
fn diagnose_reports_malformed_and_unterminated_jsonl() {
    let project = TempProject::new("rescue-corrupt");
    let root = project.path().join("codex-home");
    write_file(
        &root.join("sessions/corrupt.jsonl"),
        "{\"type\":\"turn\"}\nnot-json",
    );

    let output = run_rescue(&root, &["diagnose", "corrupt"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let view: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("diagnose JSON output");
    assert_eq!(view["health"], "corrupt");
    assert_eq!(view["malformed_records"], 1);
    assert_eq!(view["terminated_with_newline"], false);
}

#[test]
fn snapshot_is_copy_only_exclusive_and_outside_agent_state() {
    let project = TempProject::new("rescue-snapshot");
    let root = project.path().join("codex-home");
    let source = root.join("sessions/source.jsonl");
    let source_bytes = b"{\"type\":\"turn\",\"ordinal\":1}\n";
    fs::create_dir_all(source.parent().expect("source parent")).expect("source parent");
    fs::write(&source, source_bytes).expect("source fixture");
    let recovery = project.path().join("recovery");
    fs::create_dir_all(&recovery).expect("recovery directory");
    let output_path = recovery.join("source-copy.jsonl");

    let first = Command::new(vetto_bin())
        .arg("rescue")
        .arg("--root")
        .arg(&root)
        .arg("--json")
        .arg("snapshot")
        .arg("source")
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("snapshot command");
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    assert_eq!(
        fs::read(&source).expect("source after snapshot"),
        source_bytes
    );
    assert_eq!(
        fs::read(&output_path).expect("snapshot bytes"),
        source_bytes
    );

    let second = Command::new(vetto_bin())
        .arg("rescue")
        .arg("--root")
        .arg(&root)
        .arg("snapshot")
        .arg("source")
        .arg("--output")
        .arg(&output_path)
        .output()
        .expect("collision command");
    assert!(!second.status.success(), "collision unexpectedly succeeded");
    assert_eq!(
        fs::read(&output_path).expect("snapshot preserved"),
        source_bytes
    );

    let inside_root = root.join("sessions/forbidden-copy.jsonl");
    let forbidden = Command::new(vetto_bin())
        .arg("rescue")
        .arg("--root")
        .arg(&root)
        .arg("snapshot")
        .arg("source")
        .arg("--output")
        .arg(&inside_root)
        .output()
        .expect("inside-root command");
    assert!(!forbidden.status.success());
    assert!(!inside_root.exists());
}

#[test]
fn json_scan_is_repeatable_and_sanitizes_user_derived_session_names() {
    let project = TempProject::new("rescue-json-contract");
    let root = project.path().join("codex-home");
    let secret = "ghp_0123456789abcdefghijklmnopqrstuv";
    write_file(
        &root.join(format!("sessions/{secret}.jsonl")),
        "{\"type\":\"turn\"}\n",
    );

    let first = run_rescue(&root, &["scan", "--all"]);
    let second = run_rescue(&root, &["scan", "--all"]);
    assert!(first.status.success(), "stderr: {}", stderr(&first));
    assert!(second.status.success(), "stderr: {}", stderr(&second));
    assert_eq!(
        stdout(&first),
        stdout(&second),
        "stable input must produce stable rescue JSON"
    );
    let value: serde_json::Value =
        serde_json::from_slice(&first.stdout).expect("sanitized scan JSON");
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(1));
    assert!(
        stdout(&first).contains("ghp_[REDACTED]"),
        "user-derived token-shaped path was not sanitized: {}",
        stdout(&first)
    );
    assert!(
        !stdout(&first).contains(secret),
        "token-shaped path leaked into JSON: {}",
        stdout(&first)
    );
}

#[test]
fn missing_root_is_reported_as_unavailable_without_guessing() {
    let project = TempProject::new("rescue-missing");
    let missing = project.path().join("missing-codex-home");
    let output = run_rescue(&missing, &["scan"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON output");
    assert_eq!(value["status"]["availability"], "unavailable");
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(0));
}

#[cfg(unix)]
#[test]
fn scan_does_not_follow_session_symlinks() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new("rescue-symlink");
    let root = project.path().join("codex-home");
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).expect("sessions directory");
    let outside = project.path().join("outside.jsonl");
    write_file(&outside, "{\"type\":\"outside\"}\n");
    symlink(&outside, sessions.join("linked.jsonl")).expect("session symlink");

    let output = run_rescue(&root, &["scan", "--all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON output");
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(0));
}

#[cfg(unix)]
#[test]
fn scan_does_not_accept_hardlinked_session_aliases() {
    let project = TempProject::new("rescue-hardlink");
    let root = project.path().join("codex-home");
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).expect("sessions directory");
    let outside = project.path().join("outside.jsonl");
    write_file(&outside, "{\"type\":\"outside\"}\n");
    fs::hard_link(&outside, sessions.join("linked.jsonl")).expect("session hardlink");

    let output = run_rescue(&root, &["scan", "--all"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON output");
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(0));
}

#[cfg(unix)]
#[test]
fn snapshot_refuses_final_symlink_without_touching_its_target() {
    use std::os::unix::fs::symlink;

    let project = TempProject::new("rescue-snapshot-symlink");
    let root = project.path().join("codex-home");
    let source = root.join("sessions/source.jsonl");
    write_file(&source, "{\"type\":\"turn\"}\n");
    let recovery = project.path().join("recovery");
    fs::create_dir_all(&recovery).expect("recovery directory");
    let victim = recovery.join("victim.txt");
    let output_path = recovery.join("snapshot.jsonl");
    fs::write(&victim, b"sentinel\n").expect("victim");
    symlink(&victim, &output_path).expect("destination symlink");

    let output = Command::new(vetto_bin())
        .args([
            "rescue",
            "--root",
            root.to_str().expect("UTF-8 root"),
            "snapshot",
            "source",
            "--output",
        ])
        .arg(&output_path)
        .output()
        .expect("snapshot command");
    assert!(
        !output.status.success(),
        "destination symlink must be refused"
    );
    assert_eq!(
        fs::read(&victim).expect("victim after refusal"),
        b"sentinel\n"
    );
}
