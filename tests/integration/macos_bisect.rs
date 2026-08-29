//! DIAGNOSTIC for the macOS silent-SIGABRT hunt (remove with the fix).
//!
//! Step 1 — OUTSIDE-VETTO reproduction: does a plain `sandbox-exec`
//! deny-default profile break /bin/sleep on this machine with no vetto
//! involved? Step 2 — the in-vetto baseline for comparison.

#[cfg(target_os = "macos")]
#[test]
fn sigabrt_bisect_diagnostic() {
    // Clause-level bisect of the aborted profile. The fixture is the full
    // profile; variants slice it so one CI run narrows the poison clause.
    let full = include_str!("fixtures/macos-bisect-replay.sbpl");
    let lines: Vec<&str> = full.lines().collect();
    let join = |slice: &[&str]| slice.join("\n");
    let head = join(&lines[..30]);
    let tail = join(&[lines[..5], &lines[30..]].concat());
    let nonet = join(
        &lines
            .iter()
            .copied()
            .filter(|l| !l.contains("(deny network*)"))
            .collect::<Vec<_>>(),
    );
    let profiles: [(&str, String); 6] = [
        ("sexec-minimal", "(version 1)(deny default)(allow process-exec)(allow process-fork)(allow mach-lookup)(allow sysctl-read)(allow file-read* (subpath \"/\"))".to_string()),
        ("replay-full", full.to_string()),
        ("replay-head", head),
        ("replay-tail", tail),
        ("replay-nonet", nonet),
        ("replay-nonet-plus-mach", format!("{nonet}(allow mach-lookup)")),
    ];
    for (label, profile) in profiles {
        let started = std::time::Instant::now();
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
