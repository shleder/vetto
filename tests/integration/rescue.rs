//! Rescue commands are host-side, read-only operations and do not require a
//! sandbox tier. These tests run on every supported platform.

use crate::common::*;
use std::fs;
use std::process::Command;

fn run_rescue(root: &std::path::Path, trailing: &[&str]) -> std::process::Output {
    let mut command = Command::new(vetto_bin());
    command
        .arg("rescue")
        .arg("--adapter")
        .arg("codex")
        .arg("--root")
        .arg(root)
        .arg("--json")
        .args(trailing)
        .output()
        .expect("spawn rescue command")
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
    write_file(&root.join("logs/not-a-session.jsonl"), "{\"secret\":true}\n");

    let scan = run_rescue(&root, &["scan"]);
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
    assert_eq!(fs::read(&source).expect("source after snapshot"), source_bytes);
    assert_eq!(fs::read(&output_path).expect("snapshot bytes"), source_bytes);

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
    assert_eq!(fs::read(&output_path).expect("snapshot preserved"), source_bytes);

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

    let output = run_rescue(&root, &["scan"]);
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("scan JSON output");
    assert_eq!(value["sessions"].as_array().map(Vec::len), Some(0));
}

