//! Integration tests for Tier 1: Onboarding and Zero-Friction Entry.

use super::common::{run_vetto_in, stderr, stdout, write_file, TempProject};

#[test]
fn man_command_renders_troff_manpage() {
    let project = TempProject::new("man");
    let out = run_vetto_in(project.path(), &["man"]);
    assert!(out.status.success(), "vetto man must succeed");
    let text = stdout(&out);
    assert!(text.contains(".TH vetto"));
    assert!(text.contains("NAME"));
    assert!(text.contains("SYNOPSIS"));
}

#[test]
fn completions_command_renders_shell_completions() {
    let project = TempProject::new("completions");
    for shell in ["bash", "zsh", "fish", "powershell", "elvish"] {
        let out = run_vetto_in(project.path(), &["completions", shell]);
        assert!(out.status.success(), "completions for {shell} must succeed");
        let text = stdout(&out);
        assert!(
            !text.is_empty(),
            "completions for {shell} must not be empty"
        );
    }
}

#[test]
fn init_command_creates_commented_policy_toml() {
    let project = TempProject::new("init");
    write_file(
        &project.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n",
    );

    let out = run_vetto_in(project.path(), &["init"]);
    assert!(out.status.success(), "vetto init must succeed");

    let policy_path = project.path().join("policy.toml");
    assert!(policy_path.is_file(), "policy.toml must be created");

    let text = std::fs::read_to_string(&policy_path).expect("read generated policy");
    assert!(text.contains("[metadata]"));
    assert!(text.contains("[security]"));
    assert!(text.contains("[filesystem]"));
    assert!(text.contains("[display_only_deny]"));
    assert!(text.contains("[environment]"));
    assert!(text.contains("[network]"));
    assert!(text.contains("[limits]"));
    assert!(text.contains("allow_write = ["));
    assert!(text.contains("target/"));
}

#[test]
fn doctor_fix_flag_runs_and_prints_remediation() {
    let project = TempProject::new("doctor-fix");
    let out = run_vetto_in(project.path(), &["doctor", "--fix"]);
    assert!(out.status.success(), "vetto doctor --fix must succeed");
    let text = stdout(&out);
    assert!(text.contains("doctor"));
}

#[test]
fn policy_explain_why_evaluates_paths() {
    let project = TempProject::new("explain-why");
    write_file(&project.path().join("src/main.rs"), "fn main() {}\n");
    write_file(&project.path().join(".env"), "SECRET=true\n");

    // 1. Text explanation
    let out = run_vetto_in(
        project.path(),
        &["policy", "explain", "--why", "src/main.rs"],
    );
    assert!(out.status.success(), "explain why src/main.rs must succeed");
    let text = stdout(&out);
    assert!(text.contains("vetto policy explain --why"));
    assert!(text.contains("WRITABLE") || text.contains("READ_ONLY"));

    // 2. JSON explanation
    let out_json = run_vetto_in(
        project.path(),
        &["policy", "explain", "--why", ".env", "--json"],
    );
    assert!(
        out_json.status.success(),
        "explain why .env --json must succeed"
    );
    let json_text = stdout(&out_json);
    let parsed: serde_json::Value = serde_json::from_str(&json_text).expect("valid json output");
    assert_eq!(parsed["access"], "DENIED");
    assert_eq!(parsed["denied"], true);
    assert_eq!(parsed["rule_type"], "display_only_deny");
}

#[test]
fn presets_dry_run_reflects_preset_configuration() {
    let project = TempProject::new("presets-dryrun");
    write_file(&project.path().join("src/main.rs"), "fn main() {}\n");

    for preset in ["paranoid", "balanced", "yolo"] {
        let out = run_vetto_in(
            project.path(),
            &["--dry-run", "--preset", preset, "--", "echo", "test"],
        );
        assert!(
            out.status.success(),
            "dry-run with preset {preset} must succeed"
        );
        let text = stdout(&out);
        assert!(text.contains(&format!("preset: {preset}")));
    }
}

#[test]
fn shadow_mode_dry_run_reflects_shadow_flag() {
    let project = TempProject::new("shadow-dryrun");
    let out = run_vetto_in(
        project.path(),
        &["--dry-run", "--shadow", "--", "echo", "test"],
    );
    assert!(out.status.success(), "dry-run with --shadow must succeed");
    let text = stdout(&out);
    assert!(text.contains("shadow: enabled (policy layer only)"));
}

#[test]
fn policy_import_claude_settings() {
    let project = TempProject::new("import-claude");
    let claude_json = r#"{
        "permissions": {
            "allow": ["/var/log", "/opt/tools"],
            "deny": ["/root"]
        },
        "network": {
            "allowed_hosts": ["api.anthropic.com", "github.com"]
        }
    }"#;
    let input_path = project.path().join("claude_settings.json");
    let output_path = project.path().join("imported_policy.toml");
    write_file(&input_path, claude_json);

    let out = run_vetto_in(
        project.path(),
        &[
            "policy",
            "import",
            "--from",
            "claude",
            "--path",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "policy import from claude must succeed"
    );
    assert!(output_path.is_file(), "imported policy must be created");

    let text = std::fs::read_to_string(&output_path).expect("read imported policy");
    assert!(text.contains("api.anthropic.com"));
    assert!(text.contains("github.com"));
    assert!(text.contains("/var/log"));
    assert!(text.contains("/opt/tools"));
}

#[test]
fn policy_import_codex_config() {
    let project = TempProject::new("import-codex");
    let codex_toml = r#"
allowed_domains = ["api.openai.com"]
sandbox_write_roots = ["/tmp/build"]
"#;
    let input_path = project.path().join("codex_config.toml");
    let output_path = project.path().join("codex_policy.toml");
    write_file(&input_path, codex_toml);

    let out = run_vetto_in(
        project.path(),
        &[
            "policy",
            "import",
            "--from",
            "codex",
            "--path",
            input_path.to_str().unwrap(),
            "-o",
            output_path.to_str().unwrap(),
        ],
    );
    assert!(
        out.status.success(),
        "policy import from codex must succeed"
    );
    assert!(output_path.is_file(), "imported policy must be created");

    let text = std::fs::read_to_string(&output_path).expect("read imported policy");
    assert!(text.contains("api.openai.com"));
    assert!(text.contains("/tmp/build"));
}

#[test]
fn zero_config_fails_cleanly_with_agent_guidance_when_no_agent_found() {
    let project = TempProject::new("zero-config-empty");
    let out = run_vetto_in(project.path(), &[]);
    assert!(
        !out.status.success(),
        "vetto with no agent and no markers must fail"
    );
    let err_text = stderr(&out);
    assert!(err_text.contains("could not auto-detect AI agent"));
    assert!(err_text.contains("Supported agents:"));
}
