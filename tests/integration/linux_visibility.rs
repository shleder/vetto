//! Visibility honesty: JSONL carries session lifecycle events; observation of
//! allowed ops is best-effort (/proc poller, ~100 ms).

use crate::common::*;

#[test]
fn jsonl_contains_lifecycle_events() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("jsonl");
    write_file(&proj.path().join(".env"), "X=1\n");
    let jsonl = proj.path().join("session.jsonl");
    let script = stage_fixture(proj.path(), "benign_agent.sh");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--jsonl",
            jsonl.to_str().unwrap(),
            "--",
            "sh",
            &script,
        ],
    );
    assert!(out.status.success(), "agent failed: {}", stderr(&out));
    let log = std::fs::read_to_string(&jsonl).expect("jsonl written");
    assert!(log.contains("\"session_started\""), "{log}");
    assert!(log.contains("\"session_ended\""), "{log}");
    // Best-effort observation: with a 1.5s agent there is ample time for the
    // 100ms poller to notice at least one process.
    assert!(
        log.contains("\"exec_observed\"") || log.contains("\"file_observed\""),
        "poller observed nothing in 1.5s: {log}"
    );
}

#[test]
fn full_tier_records_secret_masking_events() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier for overlay masking");
        return;
    }
    let proj = TempProject::new("masklog");
    write_file(&proj.path().join(".env"), "X=1\n");
    let jsonl = proj.path().join("session.jsonl");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--jsonl",
            jsonl.to_str().unwrap(),
            "--",
            "/bin/true",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let log = std::fs::read_to_string(&jsonl).unwrap_or_default();
    assert!(
        log.contains("\"secret_masked\""),
        "no masking events: {log}"
    );
}

#[test]
fn observe_seccomp_reports_out_of_policy_paths() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier");
        return;
    }
    let proj = TempProject::new("observe");
    ensure_fake_ssh_key();
    let jsonl = proj.path().join("session.jsonl");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--observe-seccomp",
            "--jsonl",
            jsonl.to_str().unwrap(),
            "--",
            "cat",
            &format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap()),
        ],
    );
    let _ = out.status.code(); // blocked cat exits nonzero; that is fine
    let log = std::fs::read_to_string(&jsonl).unwrap_or_default();
    assert!(
        log.contains("blocked_attempt") && log.contains(".ssh"),
        "observe-seccomp did not report the ssh attempt: {log}"
    );
}
