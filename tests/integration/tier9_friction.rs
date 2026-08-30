//! Integration tests for Tier 9 features (UX polish, friction reduction).

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::common::vetto_cmd;

#[test]
fn test_feature_87_version_json() {
    let output = vetto_cmd()
        .args(["--version", "--json"])
        .output()
        .expect("vetto --version --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json output");

    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert!(json["tier"].is_string());
    assert!(json["commit"].is_string());
}

#[test]
fn test_feature_88_stable_exit_codes() {
    // 127: Command not found
    let output = vetto_cmd()
        .args(["--", "non_existent_binary_xyz_123"])
        .output()
        .expect("run missing command");
    assert_eq!(output.status.code(), Some(127));

    // 0: Success
    #[cfg(unix)]
    {
        let output = vetto_cmd()
            .args(["--tui=none", "--", "true"])
            .output()
            .expect("run true command");
        assert_eq!(output.status.code(), Some(0));
    }
}

#[test]
fn test_feature_89_quiet_and_verbose() {
    let output = vetto_cmd()
        .args(["-q", "doctor"])
        .output()
        .expect("vetto -q doctor");
    assert!(output.status.success());

    let output_v = vetto_cmd()
        .args(["-v", "doctor"])
        .output()
        .expect("vetto -v doctor");
    assert!(output_v.status.success());
}

#[test]
fn test_feature_91_shell_env() {
    let output = vetto_cmd()
        .args([
            "shell-env",
            "--session-id",
            "test-sess",
            "--tier",
            "full",
            "--profile",
            "strict",
        ])
        .output()
        .expect("vetto shell-env");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("export VETTO_SANDBOX=1"));
    assert!(stdout.contains("export VETTO_SESSION_ID=\"test-sess\""));
    assert!(stdout.contains("export VETTO_TIER=\"full\""));
    assert!(stdout.contains("export VETTO_PROFILE=\"strict\""));
}

#[test]
fn test_feature_92_status_command() {
    let output = vetto_cmd()
        .args(["status", "--json"])
        .output()
        .expect("vetto status --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(json.is_array());
}

#[test]
fn test_feature_93_install_script() {
    let script = Path::new("scripts/install.sh");
    assert!(script.exists(), "scripts/install.sh exists");
    let docs = Path::new("docs/INSTALL.md");
    assert!(docs.exists(), "docs/INSTALL.md exists");
}

#[test]
fn test_feature_94_auto_timeout_calculation() {
    let temp = std::env::temp_dir().join(format!("vetto-t9-timeout-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp);
    fs::create_dir_all(&temp).unwrap();

    let computed = vetto::history::compute_auto_timeout(&temp, "codex");
    assert_eq!(computed, None);

    for d in [20, 40, 60, 80, 100] {
        vetto::history::append_session_history(
            &temp,
            &vetto::history::SessionHistoryRecord {
                agent: "codex".into(),
                duration_secs: d,
                ts: "2026-08-30T12:00:00Z".into(),
                exit_code: 0,
            },
        )
        .unwrap();
    }

    let computed = vetto::history::compute_auto_timeout(&temp, "codex");
    assert_eq!(computed, Some(std::time::Duration::from_secs(300))); // 5 minute lower floor

    let _ = fs::remove_dir_all(&temp);
}

#[test]
fn test_feature_95_workspace_profiles() {
    let temp_prof_dir = std::env::temp_dir().join(format!("vetto-t9-prof-{}", std::process::id()));
    let storage = vetto::profile::ProfileStorage::with_dir(temp_prof_dir.clone());

    let prof = vetto::profile::WorkspaceProfile {
        name: "test-proj".into(),
        cwd: std::env::current_dir().unwrap(),
        agent: vec!["true".into()],
        policy_path: None,
        net: "off".into(),
        profile: "default".into(),
        created_at: 12345,
    };

    storage.save(&prof).unwrap();
    assert_eq!(storage.load("test-proj").unwrap(), prof);
    assert_eq!(storage.list().unwrap().len(), 1);

    storage.delete("test-proj").unwrap();
    assert!(storage.load("test-proj").is_err());

    let _ = fs::remove_dir_all(&temp_prof_dir);
}

#[test]
fn test_feature_96_why_slow() {
    let temp_file = std::env::temp_dir().join(format!("vetto-slow-{}.json", std::process::id()));
    let report_content = r#"{
        "tier": "fs-only",
        "duration_secs": 15,
        "setup_ms": 40,
        "teardown_ms": 10,
        "events_total": 100
    }"#;
    fs::write(&temp_file, report_content).unwrap();

    let output = vetto_cmd()
        .args(["why-slow", temp_file.to_str().unwrap(), "--json"])
        .output()
        .expect("vetto why-slow --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert_eq!(json["tier"], "fs-only");
    assert_eq!(json["setup_ms"], 40);

    let _ = fs::remove_file(&temp_file);
}

#[test]
fn test_feature_97_gen_sbom_script() {
    let script = Path::new("scripts/gen-sbom.sh");
    assert!(script.exists(), "scripts/gen-sbom.sh exists");
    let docs = Path::new("docs/SBOM.md");
    assert!(docs.exists(), "docs/SBOM.md exists");
}

#[test]
fn test_feature_98_landlock_abi_hints() {
    #[cfg(target_os = "linux")]
    {
        let hints = vetto::sandbox::linux::landlock::abi_feature_hints(5);
        assert!(!hints.is_empty());
        assert!(hints.iter().any(|h| h.contains("IOCTL_DEV")));
    }
}

#[test]
fn test_feature_99_gen_changelog_script() {
    let script = Path::new("scripts/gen-changelog.py");
    assert!(script.exists(), "scripts/gen-changelog.py exists");
}

#[test]
fn test_feature_100_policy_show_effective() {
    let output = vetto_cmd()
        .args(["policy", "show", "--effective", "--json"])
        .output()
        .expect("vetto policy show --effective --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("valid json");
    assert!(json["write_roots"].is_array());
    assert!(json["limits"].is_object());
}
