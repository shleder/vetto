//! `vetto verify` subcommand and the `--verify` supervised preflight: the
//! boundary battery must pass on healthy tiers and surface its verdict.

use crate::common::*;

#[test]
fn verify_subcommand_passes_on_a_healthy_tier() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("verify");
    let out = run_vetto_in(proj.path(), &["verify"]);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "healthy tier must verify clean: {text}\nstderr: {}",
        stderr(&out)
    );
    assert!(
        text.contains("leaks=0"),
        "summary must report leaks: {text}"
    );
}

#[test]
fn verify_json_is_parseable() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("verify-json");
    let out = run_vetto_in(proj.path(), &["verify", "--json"]);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "verify --json must pass: {text}\nstderr: {}",
        stderr(&out)
    );
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|error| panic!("verify --json must emit JSON: {error}\n{text}"));
    let checks = value
        .get("checks")
        .and_then(|checks| checks.as_array())
        .expect("verify --json must carry a checks array");
    assert!(
        !checks
            .iter()
            .any(|check| check.get("status").and_then(|status| status.as_str()) == Some("LEAK")),
        "no check may report a leak: {value}"
    );
}

#[test]
fn verify_flag_allows_clean_sessions() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("verify-flag");
    let out = run_vetto_in(proj.path(), &["--verify", "--", "/bin/true"]);
    assert!(
        out.status.success(),
        "--verify must not block a clean session: {}\nstderr: {}",
        stdout(&out),
        stderr(&out)
    );
}

#[test]
fn fs_only_verify_still_passes() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("verify-fsonly");
    let out = run_vetto_env_in(proj.path(), &["verify"], &[("VETTO_FORCE_TIER", "fs-only")]);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "fs-only tier must verify clean: {text}\nstderr: {}",
        stderr(&out)
    );
    assert!(
        text.contains("fs-only"),
        "output must name the tier: {text}"
    );
}
