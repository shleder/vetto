//! `--limits` CLI flag: values must survive the whole spawn chain and reach
//! the agent process as real rlimits, and malformed specs must be rejected.

use crate::common::*;

#[test]
fn limits_reach_the_agent_ulimit() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-cli");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "nofile=64,fsize=1024",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo N=$(ulimit -n); dd if=/dev/zero bs=2048 count=1 of=./too-big 2>/dev/null; true",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed; stderr: {}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(
        so.contains("N=64"),
        "RLIMIT_NOFILE not applied; stdout: {so}"
    );
    // RLIMIT_FSIZE=1024 must cap the 2048-byte write: SIGXFSZ kills dd at
    // (at most) the limit, so more than 1024 bytes can never land. This is
    // shell-independent, unlike ulimit -f (dash prints 512-byte units).
    let written = std::fs::metadata(proj.path().join("too-big"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        written <= 1024,
        "RLIMIT_FSIZE not applied: {written} bytes written past a 1024-byte limit"
    );
}

#[test]
fn limits_merge_with_policy() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-merge");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "cpu=1",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo C=$(ulimit -t)",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed; stderr: {}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(
        so.contains("C=1"),
        "CLI --limits must merge over the policy limits; stdout: {so}"
    );
}

#[test]
fn bad_limits_spec_is_rejected() {
    // No tier guard: the coarse --limits syntax check fires while parsing the
    // CLI config, before any sandbox or agent is involved.
    let proj = TempProject::new("limits-bad");
    let out = run_vetto_in(
        proj.path(),
        &["--limits", "bogus", "--dry-run", "--", "true"],
    );
    assert!(
        !out.status.success(),
        "a malformed --limits spec must be rejected; stdout: {}",
        stdout(&out)
    );
    assert!(
        stderr(&out).contains("limits"),
        "rejection must mention limits; stderr: {}",
        stderr(&out)
    );
}
