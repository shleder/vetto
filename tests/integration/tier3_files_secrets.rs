//! Integration tests for Tier 3: Files and Secrets (Features 25–36).

use std::fs;

use super::common::*;

#[test]
fn test_feature_25_scan_secrets_cli_and_auto_deny() {
    let proj = TempProject::new("feat25-scan");
    let secret_file = proj.path().join("config.env");
    write_file(
        &secret_file,
        "AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLEEXAMPLE\n",
    );
    let clean_file = proj.path().join("main.rs");
    write_file(&clean_file, "fn main() {}\n");

    // Run scan-secrets CLI
    let out = run_vetto_in(proj.path(), &["scan-secrets", "--json"]);
    assert_eq!(out.status.code(), Some(1));
    let json_str = stdout(&out);
    assert!(json_str.contains("AWS_SECRET_ACCESS_KEY"));

    // Run scan-secrets CLI clean
    let clean_proj = TempProject::new("feat25-clean");
    write_file(&clean_proj.path().join("main.rs"), "fn main() {}\n");
    let clean_out = run_vetto_in(clean_proj.path(), &["scan-secrets"]);
    assert_eq!(clean_out.status.code(), Some(0));
    let clean_txt = stdout(&clean_out);
    assert!(clean_txt.contains("clean: no secrets detected"));
}

#[test]
fn test_feature_27_deny_presets() {
    let proj = TempProject::new("feat27-presets");
    let policy_path = proj.path().join("vetto.toml");
    write_file(
        &policy_path,
        r#"
[filesystem]
allow_read = ["$PROJECT"]
allow_write = ["$PROJECT"]
deny_preset = ["ssh", "aws", "gcp", "kube", "docker"]
"#,
    );

    let out = run_vetto_in(proj.path(), &["policy", "explain", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    // Should resolve paths for presets
    assert!(s.contains(".ssh") || s.contains("deny_resolved") || s.contains(".aws"));
}

#[test]
fn test_feature_28_deny_glob() {
    let proj = TempProject::new("feat28-glob");
    let cert = proj.path().join("certs/server.pem");
    write_file(
        &cert,
        "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----\n",
    );

    let policy_path = proj.path().join("vetto.toml");
    write_file(
        &policy_path,
        r#"
[filesystem]
allow_read = ["$PROJECT"]
allow_write = ["$PROJECT"]
deny_glob = ["**/*.pem"]
"#,
    );

    let out = run_vetto_in(proj.path(), &["policy", "explain", "--json"]);
    assert_eq!(out.status.code(), Some(0));
    let s = stdout(&out);
    assert!(s.contains("server.pem"));
}

#[test]
fn test_feature_30_diff_report() {
    let proj = TempProject::new("feat30-diff");
    let file_a = proj.path().join("initial.txt");
    write_file(&file_a, "initial content\n");

    let manifest = vetto::report::diff::ProjectManifest::capture(proj.path());
    assert_eq!(manifest.files.len(), 1);

    // Modify file and add new file
    write_file(&file_a, "modified content\n");
    let file_b = proj.path().join("created.txt");
    write_file(&file_b, "created content\n");

    let diff = vetto::report::diff::ProjectDiff::compute(&manifest, proj.path());
    assert_eq!(diff.modified.len(), 1);
    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.deleted.len(), 0);
    assert!(diff.summary().contains("agent modified:"));
}

#[test]
fn test_feature_31_git_guard_branch_and_push() {
    // Test branch check
    let proj = TempProject::new("feat31-git");
    let git_dir = proj.path().join(".git");
    fs::create_dir_all(&git_dir).expect("create .git");
    write_file(&git_dir.join("HEAD"), "ref: refs/heads/main\n");

    let policy_path = proj.path().join("vetto.toml");
    write_file(
        &policy_path,
        r#"
[security]
git_guard = true

[filesystem]
allow_read = ["$PROJECT"]
allow_write = ["$PROJECT"]
"#,
    );

    let out = run_vetto_in(proj.path(), &["--", "echo", "test"]);
    assert_ne!(out.status.code(), Some(0));
    let err = stderr(&out);
    assert!(err.contains("git_guard: working copy is on branch 'main'"));

    // Test destructive push detection in shim
    assert!(vetto::shim::is_destructive_git_push(&["push".into(), "--force".into()]).is_some());
    assert!(vetto::shim::is_destructive_git_push(&[
        "push".into(),
        "origin".into(),
        "--delete".into(),
        "feat".into()
    ])
    .is_some());
    assert!(
        vetto::shim::is_destructive_git_push(&["push".into(), "origin".into(), "feat".into()])
            .is_none()
    );
}

#[test]
fn test_feature_32_snapshot_and_rollback() {
    let proj = TempProject::new("feat32-snap");
    let f1 = proj.path().join("src/lib.rs");
    write_file(&f1, "pub fn original() {}\n");

    let session_id = "test-session-rollback-1";
    let meta = vetto::rescue::snapshot::create_snapshot(
        proj.path(),
        session_id,
        vetto::rescue::snapshot::DEFAULT_MAX_SNAPSHOT_SIZE,
    )
    .expect("create snapshot");

    assert_eq!(meta.file_count, 1);
    assert!(meta.archive_file.exists());

    // Modify file
    write_file(&f1, "pub fn corrupted() {}\n");

    // Perform rollback
    let roll = vetto::rescue::snapshot::rollback_snapshot(session_id, Some(proj.path()))
        .expect("rollback");
    assert_eq!(roll.files_restored, 1);

    let restored_content = fs::read_to_string(&f1).expect("read restored");
    assert_eq!(restored_content, "pub fn original() {}\n");
}

#[test]
fn test_feature_26_cred_broker_env_and_headers() {
    let mut envs = std::collections::BTreeMap::new();
    envs.insert(
        std::ffi::OsString::from("ANTHROPIC_API_KEY"),
        std::ffi::OsString::from("sk-ant-123456"),
    );
    envs.insert(
        std::ffi::OsString::from("PATH"),
        std::ffi::OsString::from("/usr/bin"),
    );

    let proxies = vec!["ANTHROPIC_API_KEY".to_string()];
    vetto::cred_broker::filter_proxy_secrets(&mut envs, &proxies);

    assert!(!envs.contains_key(&std::ffi::OsString::from("ANTHROPIC_API_KEY")));
    assert!(envs.contains_key(&std::ffi::OsString::from("PATH")));

    // Test header injection
    let mut headers = std::collections::BTreeMap::new();
    vetto::cred_broker::inject_credential_header("ANTHROPIC_API_KEY", "sk-ant-test", &mut headers);
    assert_eq!(headers.get("x-api-key"), Some(&"sk-ant-test".to_string()));
}

#[test]
fn test_feature_36_io_metrics() {
    let mut stats = vetto::report::stats::SessionStats::default();
    stats.bytes_read = 2048;
    stats.bytes_written = 1024;
    stats.read_ops = 5;
    stats.write_ops = 2;

    let summary = stats.io_summary();
    assert!(summary.contains("read 2048 bytes (5 ops)"));
    assert!(summary.contains("written 1024 bytes (2 ops)"));
}
