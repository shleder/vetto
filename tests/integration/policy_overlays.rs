//! Overlay/enumeration masking of intra-project deny paths + doctor --probe.

use crate::common::*;

#[test]
fn globbed_pem_files_are_masked_full_tier() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier for overlays");
        return;
    }
    let proj = TempProject::new("pemmask");
    write_file(&proj.path().join("certs/server.pem"), "PRIVATE-KEY-MATERIAL\n");
    let out = run_vetto_in(
        proj.path(),
        &["--tui=none", "--", "cat", "certs/server.pem"],
    );
    // Masked via /dev/null bind: open succeeds, content is empty.
    assert!(
        !out.status.success() || stdout(&out).trim().is_empty(),
        "pem content leaked: {:?}",
        stdout(&out)
    );
    assert!(!stdout(&out).contains("PRIVATE-KEY-MATERIAL"));
}

#[test]
fn ssh_dir_listing_denied_full_tier() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier");
        return;
    }
    ensure_fake_ssh_key();
    let proj = TempProject::new("sshdir");
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "ls",
            "-A",
            &format!("{}/.ssh", std::env::var("HOME").unwrap()),
        ],
    );
    assert!(
        !out.status.success(),
        ".ssh listing must be denied (tmpfs mode=000 overlay): {:?}",
        stdout(&out)
    );
}

#[test]
fn doctor_probe_verifies_deny_paths() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("drprobe");
    write_file(&proj.path().join(".env"), "X=1\n");
    let out = run_vetto_in(proj.path(), &["doctor", "--probe"]);
    let text = stdout(&out);
    assert!(
        text.contains("verified unreachable") || text.contains("no deny paths"),
        "doctor --probe output: {text}\nstderr: {}",
        stderr(&out)
    );
    // Any LEAK line means a deny path was reachable -> nonzero exit.
    assert!(out.status.success(), "probe found leaks: {text}");
}
