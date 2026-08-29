//! DIAGNOSTIC for the macOS silent-SIGABRT hunt (remove with the fix).
//!
//! Step 1 — OUTSIDE-VETTO reproduction: does a plain `sandbox-exec`
//! deny-default profile break /bin/sleep on this machine with no vetto
//! involved? Step 2 — the in-vetto baseline for comparison.

#[cfg(target_os = "macos")]
#[test]
fn sigabrt_bisect_diagnostic() {
    let profiles: [(&str, &str); 4] = [
        (
            "sexec-minimal",
            "(version 1)(deny default)(allow process-exec)(allow process-fork)\
             (allow mach-lookup)(allow sysctl-read)(allow file-read* (subpath \"/\"))",
        ),
        ("sexec-allow-all", "(version 1)(allow default)"),
        (
            // The exact profile vetto generated when it aborted, replayed
            // through sandbox-exec: separates profile CONTENT from the
            // sandbox_init_with_parameters application path.
            "sexec-vetto-replay",
            include_str!("fixtures/macos-bisect-replay.sbpl"),
        ),
        (
            "sexec-vetto-replay-debug",
            include_str!("fixtures/macos-bisect-replay.sbpl"),
        ),
    ];
    for (label, profile) in profiles {
        let started = std::time::Instant::now();
        let profile = if label.ends_with("-debug") {
            format!("{profile}(debug deny)")
        } else {
            profile.to_string()
        };
        let out = std::process::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sleep", "1"])
            .output()
            .expect("run sandbox-exec");
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!(
            "sexec[{label}]: code={:?} secs={:.1} stderr={:?}",
            out.status.code(),
            started.elapsed().as_secs_f64(),
            stderr.trim()
        );
    }

    let proj = crate::common::TempProject::new("sigabrt-bisect");
    let started = std::time::Instant::now();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .args(["--tui=none", "--", "/bin/sleep", "1"])
        .current_dir(proj.path())
        .env("HOME", crate::common::test_home())
        .env("VETTO_CHILD_TRACE", "1")
        .output()
        .expect("run vetto for bisect");
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stages: Vec<&str> = stderr
        .lines()
        .filter_map(|l| l.strip_prefix("vetto: child stage: "))
        .collect();
    let tail: Vec<&str> = stderr.lines().rev().take(4).collect();
    eprintln!(
        "bisect[baseline]: code={:?} secs={:.1} stages={stages:?} stderr_tail={:?}",
        out.status.code(),
        started.elapsed().as_secs_f64(),
        tail.iter().rev().copied().collect::<Vec<_>>().join(" | ")
    );

    // Deliberate: cargo test only prints captured output for FAILING tests.
    panic!("DIAGNOSTIC (remove with the SIGABRT fix)");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_bisect_not_applicable_on_this_platform() {
    // Honest no-op: macOS diagnostics only run on macOS.
}
