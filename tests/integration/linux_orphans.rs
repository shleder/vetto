//! Orphan kill: vetto's death must not leave sandboxed children alive.
//! Tested per tier (pidns variant; pdeathsig+pgroup variant).

use crate::common::*;
use std::process::{Command, Stdio};
use std::time::Duration;

fn orphan_check(envs: &[(&str, &str)], tag: &str, graceless: bool) {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let marker = format!("vetto-orphan-{}-{}", tag, std::process::id());
    let proj = TempProject::new(tag);

    let mut child = Command::new(vetto_bin())
        .args([
            "--tui=none",
            "--",
            "sh",
            "-c",
            &format!("sleep 30 # {marker}"),
        ])
        .current_dir(proj.path())
        .env("HOME", test_home())
        .envs(envs.iter().copied())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn vetto");

    // Let the sandbox come up.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(child.try_wait().unwrap().is_none(), "vetto exited early");

    // FULL tier survives the worst case (SIGKILL, no cleanup runs — the
    // pidns kernel-side kill covers it). FS-ONLY tests its documented
    // graceful path: SIGTERM-triggered kill(-pgid) across the mid-depth tree.
    if graceless {
        child.kill().expect("kill vetto");
    } else {
        kill_term(child.id());
    }
    let _ = child.wait();
    std::thread::sleep(Duration::from_millis(1500));

    let pgrep = Command::new("pgrep")
        .args(["-f", &marker])
        .output()
        .expect("pgrep");
    assert!(
        pgrep.stdout.is_empty(),
        "orphans survived vetto death ({}): {}",
        tag,
        String::from_utf8_lossy(&pgrep.stdout)
    );
}

fn kill_term(pid: u32) {
    let r = Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("kill -TERM");
    assert!(r.success(), "kill -TERM failed");
}

#[test]
fn no_orphans_full_tier_sigkill() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: FULL tier unavailable");
        return;
    }
    orphan_check(&[], "full", true);
}

#[test]
fn no_orphans_fs_only_tier_graceful() {
    let tier = detected_tier();
    if tier.is_none() {
        eprintln!("SKIP: no enforcement tier");
        return;
    }
    let forced = [("VETTO_FORCE_TIER", "fs-only")];
    let envs = if tier.as_deref() == Some("full") {
        forced.as_slice()
    } else {
        &[]
    };
    orphan_check(envs, "fsonly", false);
}
