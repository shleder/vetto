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
/// own session with setsid().
///
/// In Phase 3, this setsid escape is an honest degradation/failure: Vetto must
/// NOT report a fake PASS (exit 0). Instead, the containment gap triggers
/// fail-closed reporting with exit code 125, while the sub-reaper bounded sweep
/// guarantees that the background escaper is exterminated from the host.
#[test]
fn no_fs_only_orphan_setsid_grandchild() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
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
            "setsid sleep 9999 >/dev/null 2>&1 & sleep 0.1; echo go",
        ],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );

    // Assert honest failure / degradation: must not declare clean success (exit 0).
    // The containment gap and residual detection force exit 125 (EXIT_FAIL_CLOSED).
    assert!(
        !out.status.success(),
        "setsid grandchild in FS-ONLY must not succeed; stdout: {} stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    assert_eq!(
        out.status.code(),
        Some(125),
        "FS-ONLY setsid escape must report fail-closed exit 125; stderr: {}",
        stderr(&out)
    );

    // vetto has exited here; verify that the escaper was actually exterminated
    // and did not leak on the host.
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

/// Blind sweep fail-closed: if an escaped process clears its environment (env -i),
/// stripping VETTO_RUN_NONCE, the procfs nonce scanner detects a blind spot
/// (cannot prove extinction). Vetto must terminate fail-closed with exit code 125.
#[test]
fn fs_only_blind_sweep_fails_closed() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("blind-sweep");
    let out = run_vetto_env_in(
        proj.path(),
        &[
            "--tui=none",
            "--",
            "sh",
            "-c",
            "setsid env -i sleep 9998 >/dev/null 2>&1 & sleep 0.1; echo go",
        ],
        &[("VETTO_FORCE_TIER", "fs-only")],
    );

    assert_eq!(
        out.status.code(),
        Some(125),
        "blind sweep with stripped environment must fail-closed with exit 125; stdout: {}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );

    // Bounded cleanup verification for host safety
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        let leaks = scan_cmdlines("sleep 9998");
        if leaks.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            for leak in &leaks {
                if let Some(pid_str) = leak.split(':').next() {
                    if let Ok(pid) = pid_str.trim().parse::<i32>() {
                        unsafe { libc::kill(pid, libc::SIGKILL) };
                    }
                }
            }
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Zombie reaping: under parallel fork storm where children exit without wait(),
/// Vetto's sub-reaper loop must harvest all terminated children. No unreaped
/// zombie processes (State: Z) must remain after session exit.
#[test]
fn zombie_reaping_under_parallel_fork_storm() {
    if !have_landlock() {
        eprintln!("SKIP: no tier");
        return;
    }
    let proj = TempProject::new("fork-storm-reap");
    let script = r#"
        for i in $(seq 1 50); do
            (exit 0) &
        done
        sleep 0.2
    "#;
    let out = run_vetto_in(proj.path(), &["--tui=none", "--", "sh", "-c", script]);
    assert!(
        out.status.success(),
        "fork storm execution failed; stdout: {}, stderr: {}",
        stdout(&out),
        stderr(&out)
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "expected exit 0 for reaped fork storm; stderr: {}",
        stderr(&out)
    );

    std::thread::sleep(Duration::from_millis(300));
    let residual_zombies = scan_zombie_pids();
    assert!(
        residual_zombies.is_empty(),
        "unreaped zombies lingered after session completion: {:?}",
        residual_zombies
    );
}

/// Supervisor abrupt death: when Vetto in FS-ONLY is killed with SIGKILL (kill -9),
/// user-space cleanup cannot execute. The kernel PR_SET_PDEATHSIG must terminate
/// the sandboxed child automatically.
#[test]
fn supervisor_death_pdeathsig_linux_fs_only() {
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
    orphan_check(envs, "fsonly-pdeathsig", true);
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

/// Scan /proc for zombie processes belonging to the current test runner UID.
fn scan_zombie_pids() -> Vec<String> {
    let mut zombies = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return zombies;
    };
    let me_uid = unsafe { libc::geteuid() };
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if name.parse::<i32>().is_err() {
            continue;
        }
        let Ok(status) = std::fs::read_to_string(entry.path().join("status")) else {
            continue;
        };
        let is_my_uid = status.lines().any(|l| {
            l.starts_with("Uid:") && l.split_whitespace().nth(1) == Some(&me_uid.to_string())
        });
        if !is_my_uid {
            continue;
        }
        if status
            .lines()
            .any(|l| l.starts_with("State:") && l.contains('Z'))
        {
            zombies.push(format!("{}: {}", name, entry.path().display()));
        }
    }
    zombies
}
