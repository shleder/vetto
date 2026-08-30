//! `--timeout` enforcement: at the deadline vetto publishes session_timeout,
//! tears the sandbox down through SandboxHandle::terminate and exits 124
//! (mirrors GNU timeout(1)).

use crate::common::*;

#[test]
fn timeout_kills_and_exits_124() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("timeout-kill");
    let out = run_vetto_in(
        proj.path(),
        &["--timeout", "1s", "--tui=none", "--", "sleep", "30"],
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "expected GNU-timeout exit code 124; stderr: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("session timeout"),
        "stderr must report the session timeout; got: {}",
        stderr(&out)
    );
}

#[test]
fn timeout_not_triggered_when_agent_finishes() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("timeout-finish");
    let out = run_vetto_in(
        proj.path(),
        &["--timeout", "30s", "--tui=none", "--", "true"],
    );
    assert!(
        out.status.success(),
        "agent finishing first must not be killed by the deadline; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn timeout_event_lands_in_jsonl() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("timeout-jsonl");
    // The sink is written by the vetto parent, so it may live outside the
    // sandboxed project; keeping it inside the TempProject gets free cleanup.
    let sink = proj.path().join("session.jsonl");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--jsonl",
            sink.to_str().expect("utf-8 sink path"),
            "--timeout",
            "1s",
            "--tui=none",
            "--",
            "sleep",
            "30",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "expected exit 124; stderr: {}",
        stderr(&out)
    );
    let content = std::fs::read_to_string(&sink).expect("jsonl sink file written");
    assert!(
        content.contains("session_timeout"),
        "jsonl must contain the session_timeout event; got:\n{content}"
    );
}
