//! `--timeout` enforcement: at the deadline vetto publishes session_timeout,
//! tears the sandbox down through SandboxHandle::terminate and exits 124
//! (mirrors GNU timeout(1)).
//!
//! Phase 3 extensions: tree-kill, residual fail-closed (125 > 124), signal
//! escalation (SIGTERM -> grace period -> SIGKILL), and graceful SIGTERM exit.

use crate::common::*;
use std::process::Command;
use std::time::{Duration, Instant};

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

/// Timeout on a multi-level process tree: at deadline all branches and leaf
/// grandchildren are terminated, extinction proof verifies 0 survivors, exit 124.
#[test]
fn timeout_kills_tree_and_exits_124() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("timeout-tree");
    let marker = format!("tree-leaf-{}", std::process::id());
    let script = format!("sh -c 'sleep 30 # {marker}' & sh -c 'sleep 30 # {marker}' & sleep 30");
    let out = run_vetto_in(
        proj.path(),
        &["--timeout", "1s", "--tui=none", "--", "sh", "-c", &script],
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "expected exit 124 on tree timeout; stderr: {}",
        stderr(&out)
    );
    assert!(
        stderr(&out).contains("session timeout"),
        "stderr must report session timeout; got: {}",
        stderr(&out)
    );

    let pgrep = Command::new("pgrep")
        .args(["-f", &marker])
        .output()
        .expect("pgrep");
    assert!(
        pgrep.stdout.is_empty(),
        "processes from tree survived timeout kill: {}",
        String::from_utf8_lossy(&pgrep.stdout)
    );
}

/// Invariant: residual processes override timeout 124 with fail-closed exit 125.
#[test]
fn timeout_with_residual_forces_exit_125() {
    use vetto::exit_codes::{map_session_exit_code, EXIT_FAIL_CLOSED, EXIT_TIMEOUT};
    use vetto::proctree::{ExtinctionVerifier, PlatformExtinctionTier};

    // Timeout occurred, but ExtinctionVerifier detects 1 surviving residual process
    let breach = ExtinctionVerifier::verify(
        PlatformExtinctionTier::LinuxTier1Proven,
        1, // surviving_processes > 0
        0,
        100,
    )
    .unwrap_err();

    assert_eq!(breach.exit_code, EXIT_FAIL_CLOSED);
    assert_eq!(breach.exit_code, 125);

    // map_session_exit_code must ensure 125 strictly dominates timeout 124
    let mapped = map_session_exit_code(breach.exit_code, true, false);
    assert_eq!(
        mapped, EXIT_FAIL_CLOSED,
        "residual extinction breach (125) must dominate timeout (124)"
    );
    assert_ne!(mapped, EXIT_TIMEOUT);
}

/// Signal escalation: process traps SIGTERM and ignores it; killer escalates
/// to SIGKILL after the grace period, terminating the process and exiting 124.
#[test]
fn timeout_signal_escalation_trapped_sigterm_to_sigkill() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("trap-sigterm");
    let log_file = proj.path().join("term.log");
    let script = format!(
        "trap 'echo TRAPPED >> \"{}\"' TERM; while true; do sleep 0.05; done",
        log_file.display()
    );
    let start = Instant::now();
    let out = run_vetto_in(
        proj.path(),
        &["--timeout", "1s", "--tui=none", "--", "sh", "-c", &script],
    );
    let elapsed = start.elapsed();

    assert_eq!(
        out.status.code(),
        Some(124),
        "expected exit 124 after escalation; stderr: {}",
        stderr(&out)
    );
    if log_file.exists() {
        let content = std::fs::read_to_string(&log_file).unwrap_or_default();
        assert!(
            content.contains("TRAPPED"),
            "agent should have received and trapped SIGTERM before SIGKILL; got: {content}"
        );
    }
    assert!(
        elapsed < Duration::from_secs(6),
        "escalation took too long: {:?}",
        elapsed
    );
}

/// Graceful shutdown on SIGTERM: process traps SIGTERM and exits cleanly
/// within grace period, avoiding forceful SIGKILL.
#[test]
fn timeout_graceful_exit_on_sigterm_avoids_sigkill() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("graceful-sigterm");
    let log_file = proj.path().join("exit.log");
    let script = format!(
        "trap 'echo CLEAN_SHUTDOWN >> \"{}\"; exit 0' TERM; while true; do sleep 0.05; done",
        log_file.display()
    );
    let out = run_vetto_in(
        proj.path(),
        &["--timeout", "1s", "--tui=none", "--", "sh", "-c", &script],
    );
    assert_eq!(
        out.status.code(),
        Some(124),
        "expected exit 124 on timeout; stderr: {}",
        stderr(&out)
    );
    let content = std::fs::read_to_string(&log_file).unwrap_or_default();
    assert!(
        content.contains("CLEAN_SHUTDOWN"),
        "agent should have performed clean shutdown on SIGTERM; got: {content}"
    );
}
