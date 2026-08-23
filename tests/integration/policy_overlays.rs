//! Overlay/enumeration masking of intra-project deny paths + doctor --probe.

use crate::common::*;

#[test]
fn all_project_secret_shapes_are_masked_full_tier() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs full tier for overlays");
        return;
    }
    let proj = TempProject::new("secret-shape-mask");
    for (path, marker) in [
        (".env.local", "ENV-SECRET"),
        ("certs/server.pem", "PEM-SECRET"),
        ("certs/client.key", "KEY-SECRET"),
        ("certs/client.p12", "P12-SECRET"),
        ("certs/client.pfx", "PFX-SECRET"),
        ("vault/passwords.kdbx", "KDBX-SECRET"),
        (".ENV.production", "UPPER-ENV-SECRET"),
        ("certs/PRIVATE.PEM", "UPPER-PEM-SECRET"),
        ("vault/UPPER.KDBX", "UPPER-KDBX-SECRET"),
    ] {
        write_file(&proj.path().join(path), &format!("{marker}\n"));
    }
    let out = run_vetto_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "sh",
            "-c",
            "cat .env.local certs/server.pem certs/client.key certs/client.p12 \
             certs/client.pfx vault/passwords.kdbx .ENV.production \
             certs/PRIVATE.PEM vault/UPPER.KDBX",
        ],
    );
    // Masked via /dev/null bind: open succeeds, content is empty.
    assert!(
        !out.status.success() || stdout(&out).trim().is_empty(),
        "project secret content leaked: {:?}",
        stdout(&out)
    );
    for marker in [
        "ENV-SECRET",
        "PEM-SECRET",
        "KEY-SECRET",
        "P12-SECRET",
        "PFX-SECRET",
        "KDBX-SECRET",
        "UPPER-ENV-SECRET",
        "UPPER-PEM-SECRET",
        "UPPER-KDBX-SECRET",
    ] {
        assert!(!stdout(&out).contains(marker), "leaked marker {marker}");
    }
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
            &format!("{}/.ssh", test_home().display()),
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
