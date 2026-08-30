//! Orphan kill: vetto's death must not leave sandboxed children alive.
//! Tested per tier (pidns variant; pdeathsig+pgroup variant).

use crate::common::*;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

/// FS-ONLY worst case: a grandchild that escapes kill(-pgid) by moving to its
/// own session with setsid(). Closing mechanism under test: vetto registers
/// as a child sub-reaper before the fork, so when the agent child terminates
/// the escaper is reparented to vetto, and teardown (terminate() on the
/// timeout path, the armed exit hook on the normal path) sweeps it with a
/// bounded SIGKILL pass. Detected tier must be "full" so the forced fs-only
/// tier is a deliberate downgrade, not a capability limit.
#[test]
fn no_fs_only_orphan_setsid_grandchild() {
    if detected_tier().as_deref() != Some("full") {
        eprintln!("SKIP: needs FULL available to force the fs-only tier");
        return;
    }
    let proj = TempProject::new("orphan-setsid");
    let out = run_vetto_env_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "sh",
            "-c",
            "setsid sleep 9999 >/dev/null 2>&1 & echo go",
        ],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );
    assert!(
        out.status.success(),
        "vetto failed; stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );

    // vetto has exited here (the exit hook ran before exit(0) completed);
    // poll briefly so a just-killed escaper that vanished between scans
    // cannot flake the test.
    let deadline = Instant::now() + Duration::from_secs(6);
    loop {
        let leaks = scan_cmdlines("sleep 9999");
        if leaks.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "fs-only setsid grandchild survived vetto teardown: {}",
                leaks.join("; ")
            );
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Scan /proc/*/cmdline for a substring; returns "pid: cmdline" entries.
fn scan_cmdlines(needle: &str) -> Vec<String> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return found;
    };
    for entry in entries.flatten() {
        let Ok(cmdline) = std::fs::read_to_string(entry.path().join("cmdline")) else {
            continue; // kernel threads, zombies, vanished pids
        };
        let joined = cmdline.replace('\0', " ");
        if joined.contains(needle) {
            found.push(format!(
                "{}: {}",
                entry.file_name().to_string_lossy(),
                joined.trim()
            ));
        }
    }
    found
}
