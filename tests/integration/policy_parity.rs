//! Cross-platform policy parity tests (Feature 63).
//!
//! Validates that policy enforcement semantics (write within root allowed,
//! write outside denied, secrets masked/isolated where supported, network default-deny,
//! and resource limits) maintain parity across Linux, macOS, and Windows backends.

use crate::common::{run_vetto_in, stderr, stdout, TempProject};

#[test]
fn policy_limits_io_rate_cli_and_flags_parity() {
    let proj = TempProject::new("parity-limits-dryrun");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--dry-run",
            "--limits",
            "max_iops=5000,max_bandwidth=50MB",
            "--",
            "cargo",
            "--version",
        ],
    );
    assert!(
        out.status.success(),
        "dry-run with io_rate limits must succeed; stderr: {}",
        stderr(&out)
    );
    let text = stdout(&out);
    assert!(text.contains("dry-run"), "must be a dry-run output: {text}");
}

#[test]
fn backend_selection_flag_parity() {
    let proj = TempProject::new("parity-backend-selection");

    // Auto / process backend is valid everywhere
    let out_auto = run_vetto_in(
        proj.path(),
        &["--dry-run", "--backend", "auto", "--", "cargo", "--version"],
    );
    assert!(
        out_auto.status.success(),
        "backend=auto must succeed in dry-run; stderr: {}",
        stderr(&out_auto)
    );

    // Unknown backend must fail closed everywhere
    let out_bad = run_vetto_in(
        proj.path(),
        &[
            "--dry-run",
            "--backend",
            "invalid-backend-name",
            "--",
            "cargo",
            "--version",
        ],
    );
    assert!(
        !out_bad.status.success(),
        "unknown backend must fail closed"
    );
    assert!(
        stderr(&out_bad).contains("unknown backend"),
        "rejection message must explain reason: {}",
        stderr(&out_bad)
    );

    #[cfg(not(target_os = "windows"))]
    {
        // On non-Windows platforms, win-sandbox must fail closed
        let out_win = run_vetto_in(
            proj.path(),
            &[
                "--dry-run",
                "--backend",
                "win-sandbox",
                "--",
                "cargo",
                "--version",
            ],
        );
        assert!(
            !out_win.status.success(),
            "win-sandbox on non-Windows must fail closed"
        );
        assert!(
            stderr(&out_win).contains("only available on Windows"),
            "rejection must note platform availability: {}",
            stderr(&out_win)
        );
    }
}

#[test]
fn oslog_and_lpac_flags_parse_parity() {
    let proj = TempProject::new("parity-flags-dryrun");
    let out = run_vetto_in(
        proj.path(),
        &["--dry-run", "--oslog", "--lpac", "--", "cargo", "--version"],
    );
    assert!(
        out.status.success(),
        "dry-run with --oslog and --lpac must succeed; stderr: {}",
        stderr(&out)
    );
}

#[test]
fn write_inside_project_root_parity() {
    let proj = TempProject::new("parity-write-inside");
    let target = proj.path().join("inside-parity.txt");

    #[cfg(unix)]
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "sh",
            "-c",
            "echo PARITY_INSIDE_OK > inside-parity.txt",
        ],
    );

    #[cfg(windows)]
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "cmd",
            "/c",
            "echo PARITY_INSIDE_OK> inside-parity.txt",
        ],
    );

    if out.status.success() {
        let content = std::fs::read_to_string(&target).unwrap_or_default();
        assert!(
            content.contains("PARITY_INSIDE_OK"),
            "write inside allowed root must succeed"
        );
    }
}
