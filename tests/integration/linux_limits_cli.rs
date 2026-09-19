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

#[test]
fn cli_limits_cannot_loosen_policy_limits() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-no-loosen");
    let policy = r#"
[limits]
cpu_seconds = 2
open_files = 32
file_size_bytes = 1024
"#;
    write_file(&proj.path().join("policy.toml"), policy);

    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "nofile=1024,cpu=100,fsize=10485760",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo N=$(ulimit -n); echo C=$(ulimit -t); dd if=/dev/zero bs=2048 count=1 of=./too-big 2>/dev/null; true",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed; stderr: {}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(
        so.contains("N=32"),
        "CLI must not loosen open_files from 32 to 1024; stdout: {so}"
    );
    assert!(
        so.contains("C=2"),
        "CLI must not loosen cpu_seconds from 2 to 100; stdout: {so}"
    );

    let written = std::fs::metadata(proj.path().join("too-big"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        written <= 1024,
        "CLI must not loosen file_size_bytes from 1024 to 10MB: {written} bytes written"
    );
}

#[test]
fn cli_limits_tightens_base_policy_limits() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-tighten");
    let policy = r#"
[limits]
cpu_seconds = 100
open_files = 1024
file_size_bytes = 10485760
"#;
    write_file(&proj.path().join("policy.toml"), policy);

    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "nofile=48,cpu=3,fsize=512",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo N=$(ulimit -n); echo C=$(ulimit -t); dd if=/dev/zero bs=2048 count=1 of=./too-big 2>/dev/null; true",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed; stderr: {}",
        stderr(&out)
    );
    let so = stdout(&out);
    assert!(
        so.contains("N=48"),
        "CLI should tighten open_files to 48; stdout: {so}"
    );
    assert!(
        so.contains("C=3"),
        "CLI should tighten cpu_seconds to 3; stdout: {so}"
    );

    let written = std::fs::metadata(proj.path().join("too-big"))
        .map(|m| m.len())
        .unwrap_or(0);
    assert!(
        written <= 512,
        "CLI should tighten file_size_bytes to 512: {written} bytes written"
    );
}

#[test]
fn cli_limits_memory_aliases() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-mem-alias");

    // Test 'mem' alias with binary units (128 MiB = 131072 KiB)
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "mem=128mib",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo M=$(ulimit -v)",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed with mem=128mib; stderr: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("M=131072"),
        "mem=128mib must set address space to 131072 KiB; stdout: {}",
        stdout(&out)
    );

    // Test 'as' alias with binary units (64 MiB = 65536 KiB)
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "as=64mib",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo M=$(ulimit -v)",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed with as=64mib; stderr: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("M=65536"),
        "as=64mib must set address space to 65536 KiB; stdout: {}",
        stdout(&out)
    );

    // Test 'memory' alias with binary units (256 MiB = 262144 KiB)
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "memory=256mib",
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo M=$(ulimit -v)",
        ],
    );
    assert!(
        out.status.success(),
        "vetto failed with memory=256mib; stderr: {}",
        stderr(&out)
    );
    assert!(
        stdout(&out).contains("M=262144"),
        "memory=256mib must set address space to 262144 KiB; stdout: {}",
        stdout(&out)
    );
}

#[test]
fn cli_limits_process_aliases() {
    let proj = TempProject::new("limits-proc-alias");

    // Test 'pids' alias via dry-run
    let out = run_vetto_in(
        proj.path(),
        &["--limits", "pids=55", "--dry-run", "--", "true"],
    );
    assert!(
        out.status.success(),
        "vetto failed with pids=55; stderr: {}",
        stderr(&out)
    );

    // Test 'procs' alias via dry-run
    let out = run_vetto_in(
        proj.path(),
        &["--limits", "procs=45", "--dry-run", "--", "true"],
    );
    assert!(
        out.status.success(),
        "vetto failed with procs=45; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn cli_limits_cpu_quota_and_percent_parameters() {
    let proj = TempProject::new("limits-cpu-params");

    // Valid cpu_percent
    let out = run_vetto_in(
        proj.path(),
        &["--limits", "cpu_percent=50%", "--dry-run", "--", "true"],
    );
    assert!(
        out.status.success(),
        "valid cpu_percent=50% must be accepted; stderr: {}",
        stderr(&out)
    );

    // Valid cpu_max with quota and period
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "cpu_max=50000 100000",
            "--dry-run",
            "--",
            "true",
        ],
    );
    assert!(
        out.status.success(),
        "valid cpu_max=50000 100000 must be accepted; stderr: {}",
        stderr(&out)
    );

    // Invalid cpu_percent rejected
    let out_bad_pct = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "cpu_percent=invalid%",
            "--dry-run",
            "--",
            "true",
        ],
    );
    assert!(
        !out_bad_pct.status.success(),
        "invalid cpu_percent must be rejected; stdout: {}",
        stdout(&out_bad_pct)
    );
    assert!(
        stderr(&out_bad_pct).contains("limits"),
        "rejection must mention limits; stderr: {}",
        stderr(&out_bad_pct)
    );

    // Invalid cpu_max rejected
    let out_bad_max = run_vetto_in(
        proj.path(),
        &["--limits", "cpu_max=bogus_quota", "--dry-run", "--", "true"],
    );
    assert!(
        !out_bad_max.status.success(),
        "invalid cpu_max must be rejected; stdout: {}",
        stdout(&out_bad_max)
    );
    assert!(
        stderr(&out_bad_max).contains("limits"),
        "rejection must mention limits; stderr: {}",
        stderr(&out_bad_max)
    );
}

#[test]
fn cli_limits_strictest_within_same_spec() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("limits-intra-spec");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--limits",
            "cpu=10,cpu=2,cpu=5",
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
    assert!(
        stdout(&out).contains("C=2"),
        "strictest value within spec must win; stdout: {}",
        stdout(&out)
    );
}

#[test]
fn cli_limits_cgroup_unavailable_fails_closed_125() {
    let proj = TempProject::new("limits-cg-unavailable");
    let out = run_vetto_env_in(
        proj.path(),
        &[
            "--limits",
            "cpu_max=50000 100000",
            "--tui=none",
            "--",
            "true",
        ],
        &[("VETTO_TEST_NO_CGROUP", "1")],
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "mandated cgroup quota on unavailable cgroup must fail-closed with exit code 125; stderr: {}",
        stderr(&out)
    );
}
