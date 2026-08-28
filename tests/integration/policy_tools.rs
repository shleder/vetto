//! Integration tests for the policy tooling subcommands: `policy explain`,
//! `policy lint`, and the `--limits` CLI spec merge. Every test drives the
//! compiled vetto binary as a child process.

use crate::common::*;

#[test]
fn explain_prints_tier_and_roots() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("explain-text");
    let out = run_vetto_in(proj.path(), &["policy", "explain"]);
    assert!(
        out.status.success(),
        "explain must succeed; stderr: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("tier"), "tier section missing: {text}");
    assert!(
        text.contains("write roots"),
        "write roots section missing: {text}"
    );
}

#[test]
fn explain_json_parses() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("explain-json");
    let out = run_vetto_in(proj.path(), &["policy", "explain", "--json"]);
    assert!(
        out.status.success(),
        "explain --json must succeed; stderr: {}",
        stderr(&out)
    );
    let value: serde_json::Value =
        serde_json::from_str(&stdout(&out)).expect("explain --json emits valid JSON");
    assert!(
        value.get("tier").is_some(),
        "JSON must carry the tier: {value}"
    );
    assert!(
        value.get("profile").is_some(),
        "JSON must carry the profile: {value}"
    );
}

#[test]
fn lint_is_clean_or_warns_on_default() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    // Credential material exists in the isolated test HOME, so the default
    // profile resolves its deny paths and lint must not fail (non-strict).
    ensure_fake_ssh_key();
    let proj = TempProject::new("lint-default");
    let out = run_vetto_in(proj.path(), &["policy", "lint"]);
    assert!(
        out.status.success(),
        "non-strict lint must always exit 0; exit={:?} stderr: {}",
        out.status.code(),
        stderr(&out)
    );
}

#[test]
fn lint_strict_fails_on_home_write_root() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("lint-home-write");
    // A CLI policy layer that makes the isolated test HOME a write root.
    // The loader treats --policy paths as extra TOML layers after the
    // profile, with the same [filesystem].allow_write schema.
    let home = test_home().display().to_string();
    let layer = proj.path().join("home-write-root.toml");
    write_file(
        &layer,
        &format!(
            r#"
[metadata]
name = "lint-home-write"

[filesystem]
allow_write = ["{home}"]
"#
        ),
    );
    let out = run_vetto_in(
        proj.path(),
        &[
            "--policy",
            layer.to_str().expect("utf8 layer path"),
            "policy",
            "lint",
            "--strict",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "strict lint must exit 1 on a $HOME write root; stderr: {}",
        stderr(&out)
    );
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("home"), "output must mention home: {text}");
}

#[test]
fn limits_flag_applies_cleanly() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-flag");
    let out = run_vetto_in(
        proj.path(),
        &["--limits", "cpu=1", "--dry-run", "--", "true"],
    );
    assert!(
        out.status.success(),
        "--limits cpu=1 --dry-run must succeed; stderr: {}",
        stderr(&out)
    );
}
