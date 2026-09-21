//! Integration tests for Tier 9 features (UX polish, friction reduction).

use std::fs;
use std::path::Path;
use std::process::Command;

use crate::common::vetto_bin;

fn vetto_cmd() -> Command {
    Command::new(vetto_bin())
}

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

#[test]
fn test_actionable_remediation_in_session_recap() {
    let input = vetto::audit::SessionRecapInput {
        exit_code: 0,
        duration_secs: 5,
        events_total: 10,
        top_denied: vec![("/etc/shadow".to_string(), 3)],
        denials_total: 3,
        egress_denied: vec![("api.blocked-service.com:443".to_string(), 1)],
        egress_allowed: vec!["api.anthropic.com".to_string()],
        op_counts: std::collections::BTreeMap::new(),
        files_changed: 0,
        verify_status: "off".to_string(),
    };
    let lines = vetto::audit::format_session_recap(&input).expect("recap lines");
    let allow_line = lines
        .iter()
        .find(|l| l.starts_with("to allow:"))
        .expect("remediation guidance line present");
    assert!(allow_line.contains("run `vetto allow /etc/shadow`"));
    assert!(allow_line.contains("run `vetto allow --net api.blocked-service.com`"));
}

#[cfg(unix)]
#[test]
fn test_app_describe_actionable_remediation_hint() {
    let blocked_file = vetto::events::Event::BlockedAttempt {
        ts: vetto::events::types::now(),
        pid: 1234,
        comm: "agent".to_string(),
        path: "/var/secret".to_string(),
        source: "landlock".to_string(),
    };
    let desc_file = vetto::tui::app::describe(&blocked_file);
    assert!(desc_file.contains("to allow: run `vetto allow /var/secret`"));

    let denied_net = vetto::events::Event::NetRequest {
        ts: vetto::events::types::now(),
        host: "custom-api.internal".to_string(),
        port: 443,
        allowed: false,
    };
    let desc_net = vetto::tui::app::describe(&denied_net);
    assert!(desc_net.contains("to allow: run `vetto allow --net custom-api.internal`"));
}

#[test]
fn test_cli_allow_and_deny_operations() {
    let temp_dir =
        std::env::temp_dir().join(format!("vetto-cli-allow-deny-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    let fake_home = temp_dir.join("home");
    fs::create_dir_all(&fake_home).unwrap();

    // 1. Allow writable path
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "/opt/test_scratch"])
        .output()
        .expect("vetto allow /opt/test_scratch");
    assert!(output.status.success());
    let policy_path = temp_dir.join("vetto.toml");
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"/opt/test_scratch\""));

    // 2. Allow read-only path
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "--read-only", "/usr/local/share/data"])
        .output()
        .expect("vetto allow --read-only");
    assert!(output.status.success());
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"/usr/local/share/data\""));

    // 3. Allow wildcard network domain with port
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "--net", "*.anthropic.com:443"])
        .output()
        .expect("vetto allow --net");
    assert!(output.status.success());
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"*.anthropic.com\""));
    assert!(content.contains("mode = \"allowlist\""));

    // 4. Allow network preset via --net
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "--net", "npm"])
        .output()
        .expect("vetto allow --net npm");
    assert!(output.status.success());
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"npm\""));
    assert!(content.contains("net_presets = ["));

    // 5. Allow network preset via --preset
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "--preset", "cargo"])
        .output()
        .expect("vetto allow --preset cargo");
    assert!(output.status.success());
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"cargo\""));

    // 6. Deny secret path
    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["deny", "$HOME/.ssh/id_rsa"])
        .output()
        .expect("vetto deny");
    assert!(output.status.success());
    let content = fs::read_to_string(&policy_path).expect("read vetto.toml");
    assert!(content.contains("\"$HOME/.ssh/id_rsa\""));
    assert!(content.contains("[display_only_deny]"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_cli_allow_respects_existing_dot_vetto_policy() {
    let temp_dir =
        std::env::temp_dir().join(format!("vetto-dot-hierarchy-{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    let dot_vetto = temp_dir.join(".vetto");
    fs::create_dir_all(&dot_vetto).unwrap();
    let dot_policy = dot_vetto.join("policy.toml");
    fs::write(&dot_policy, "# existing dot-vetto policy\n").unwrap();
    let fake_home = temp_dir.join("home");
    fs::create_dir_all(&fake_home).unwrap();

    let output = vetto_cmd()
        .current_dir(&temp_dir)
        .env("HOME", &fake_home)
        .env("USERPROFILE", &fake_home)
        .args(["allow", "/custom/path"])
        .output()
        .expect("vetto allow");
    assert!(output.status.success());

    // Verified: written to .vetto/policy.toml
    let content = fs::read_to_string(&dot_policy).expect("read dot_policy");
    assert!(content.contains("\"/custom/path\""));

    // Verified: vetto.toml was NOT created
    assert!(!temp_dir.join("vetto.toml").exists());

    let _ = fs::remove_dir_all(&temp_dir);
}
