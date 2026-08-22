//! Landlock enforcement: secrets under $HOME, intra-project masking, and the
//! symlink escape. Conditional on any tier being available here.

use crate::common::*;

fn guard() -> bool {
    if have_landlock() {
        true
    } else {
        eprintln!("SKIP: no enforcement tier on this machine");
        false
    }
}

#[test]
fn ssh_key_unreachable_every_tier() {
    if !guard() {
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("ssh");
    let out = run_vetto_in(
        proj.path(),
        &["--tui=none", "--", "cat", &format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap())],
    );
    let text = stdout(&out);
    assert!(
        !out.status.success() || text.trim().is_empty(),
        "cat ~/.ssh/id_rsa must fail or see nothing; got success={} stdout={:?}",
        out.status.success(),
        text
    );
    assert!(!text.contains("FAKE-TEST-KEY"), "key material leaked: {text}");
}

#[test]
fn env_masked_empty_on_full() {
    if !have_landlock() || detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs Tier FULL here");
        return;
    }
    let proj = TempProject::new("envmask");
    write_file(&proj.path().join(".env"), "TOPSECRET=1\n");
    let out = run_vetty_cat_env(proj.path(), &[]);
    // Masked: cat SUCCEEDS but the file appears EMPTY (/dev/null overlay).
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(stdout(&out), "", ".env content leaked through the overlay");
}

#[test]
fn env_denied_or_empty_on_fs_only() {
    if !have_landlock() || detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs Tier FULL to force fs-only against");
        return;
    }
    let proj = TempProject::new("envfs");
    write_file(&proj.path().join(".env"), "TOPSECRET=1\n");
    let out = run_vetty_cat_env(proj.path(), &[("VETTO_FORCE_TIER", "fs-only")]);
    // Enumeration either excluded the file (open denied) or it is unreadable;
    // content must never come through.
    assert!(
        !out.status.success() || stdout(&out).trim().is_empty(),
        ".env readable with content under fs-only: {:?}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("TOPSECRET"));
}

fn run_vetty_cat_env(cwd: &std::path::Path, envs: &[(&str, &str)]) -> std::process::Output {
    run_vetto_env_in(cwd, &["--tui=none", "--", "cat", ".env"], envs)
}

#[test]
fn symlink_attack_blocked() {
    if !guard() {
        return;
    }
    let proj = TempProject::new("symlink");
    let script = stage_fixture(proj.path(), "symlink_attack.sh");
    let out = run_vetto_in(proj.path(), &["--tui=none", "--", "sh", &script]);
    let text = stdout(&out);
    assert!(!text.contains("LEAK-SYMLINK"), "/etc/passwd via symlink: {text}");
}

#[test]
fn malicious_agent_leaks_nothing() {
    if !guard() {
        return;
    }
    let proj = TempProject::new("malicious");
    write_file(&proj.path().join(".env"), "TOPSECRET=1\n");
    ensure_fake_ssh_key();
    let script = stage_fixture(proj.path(), "malicious_agent.sh");
    let out = run_vetto_in(proj.path(), &["--tui=none", "--", "sh", &script]);
    let text = stdout(&out);
    for marker in ["LEAK-SSH", "LEAK-ENV", "LEAK-SHADOW", "WROTE-ETC", "NET-LEAK"] {
        assert!(!text.contains(marker), "marker {marker} present: {text}");
    }
}

#[test]
fn benign_agent_works() {
    if !guard() {
        return;
    }
    let proj = TempProject::new("benign");
    let script = stage_fixture(proj.path(), "benign_agent.sh");
    let out = run_vetto_in(proj.path(), &["--tui=none", "--", "sh", &script]);
    let text = stdout(&out);
    assert!(out.status.success(), "benign agent failed: {}", stderr(&out));
    assert!(text.contains("created-by-agent"), "agent output: {text}");
    assert!(text.contains("benign-done"), "agent output: {text}");
}
