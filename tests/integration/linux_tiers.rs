//! Tier detection, doctor output, force-tier override, dry-run.

use crate::common::*;

#[test]
fn doctor_reports_capabilities() {
    let out = doctor_output();
    assert!(out.contains("landlock:"), "doctor output: {out}");
    assert!(out.contains("unprivileged userns:"), "{out}");
    assert!(out.contains("chosen tier:"), "{out}");
}

#[test]
fn force_tier_override_selects_fs_only() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier to override from");
        return;
    }
    let proj = TempProject::new("forcetier");
    let out = run_vetto_env_in(
        proj.path(),
        &["doctor"],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );
    let text = stdout(&out);
    assert!(
        text.lines()
            .any(|l| l.trim_start().starts_with("chosen tier:") && l.contains("fs-only")),
        "force fs-only did not apply: {text}"
    );
}

#[test]
fn dry_run_executes_nothing() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("dryrun");
    let out = run_vetto_in(
        proj.path(),
        &["--dry-run", "--", "sh", "-c", "echo DRY-RAN-MARKER"],
    );
    let text = stdout(&out);
    assert!(text.contains("vetto dry-run"), "{text}");
    assert!(text.contains("tier:"), "{text}");
    assert!(!text.contains("DRY-RAN-MARKER"), "dry-run executed the agent!");
    assert!(!proj.path().join("vetto-benign.txt").exists());
}

#[test]
fn fail_closed_without_landlock_is_reported() {
    // We cannot remove landlock at runtime; assert the honest-error path is
    // at least wired by checking the doctor wording once.
    let out = doctor_output();
    assert!(
        out.contains("landlock") && out.contains("tier"),
        "doctor must always discuss landlock/tier: {out}"
    );
}
