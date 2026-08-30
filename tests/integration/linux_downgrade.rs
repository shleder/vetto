//! Tier downgrade matrix tests and fail-closed guarantee verification.

use crate::common::*;
use vetto::policy::Tier;
use vetto::sandbox::linux::{pick_tier, Probe};

#[test]
fn test_pick_tier_matrix_downgrade_guarantee() {
    // 1. Full capabilities -> Tier::Full
    let probe_full = Probe {
        kernel: "6.1.0".into(),
        landlock_abi: Some(3),
        userns_available: true,
        full_tier_available: true,
        seccomp_filter_available: true,
        seccomp_notify_available: true,
        audit_feed_readable: true,
    };
    assert_eq!(pick_tier(&probe_full).unwrap(), Tier::Full);

    // 2. No userns / mount stack -> degrades to Tier::FsOnly
    let probe_fs_only = Probe {
        kernel: "6.1.0".into(),
        landlock_abi: Some(3),
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: true,
        seccomp_notify_available: true,
        audit_feed_readable: true,
    };
    assert_eq!(pick_tier(&probe_fs_only).unwrap(), Tier::FsOnly);

    // 3. No landlock -> degrades to Tier::Seccomp
    let probe_seccomp = Probe {
        kernel: "5.10.0".into(),
        landlock_abi: None,
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: true,
        seccomp_notify_available: false,
        audit_feed_readable: false,
    };
    assert_eq!(pick_tier(&probe_seccomp).unwrap(), Tier::Seccomp);

    // 4. No landlock and no seccomp -> FAIL-CLOSED
    let probe_none = Probe {
        kernel: "4.19.0".into(),
        landlock_abi: None,
        userns_available: false,
        full_tier_available: false,
        seccomp_filter_available: false,
        seccomp_notify_available: false,
        audit_feed_readable: false,
    };
    assert!(pick_tier(&probe_none).is_err());
}

#[test]
fn test_force_tier_seccomp_micro_mode() {
    let proj = TempProject::new("downgrade_seccomp");
    let out = run_vetto_env_in(proj.path(), &["doctor"], &[("VETTO_FORCE_TIER", "seccomp")]);
    let text = stdout(&out);
    assert!(
        text.lines()
            .any(|l| l.contains("chosen tier:") && l.contains("seccomp")),
        "force seccomp must report chosen tier seccomp: {text}"
    );
}

#[test]
fn test_seccomp_tier_executes_simple_command() {
    let proj = TempProject::new("seccomp_exec");
    let out = run_vetto_env_in(
        proj.path(),
        &["--tui=none", "--ci", "--", "sh", "-c", "echo seccomp_alive"],
        &[("VETTO_FORCE_TIER", "seccomp")],
    );
    let text = stdout(&out);
    assert!(
        text.contains("seccomp_alive"),
        "seccomp micro tier execution failed: {text}"
    );
}
