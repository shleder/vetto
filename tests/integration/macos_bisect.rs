//! DIAGNOSTIC for the macOS silent-SIGABRT hunt: the same session under four
//! configurations (watchdog / limits toggled by the VETTO_NO_* kill-switches)
//! so one CI run pinpoints which pre-exec stage turns the exec'd agent into a
//! silent SIGABRT. A healthy session takes ~2s (sleep exits 0); an aborted
//! agent makes vetto exit near-instantly with code 134 (128 + SIGABRT).
//!
//! Not an assertion on purpose: the printed matrix is the result.

#[cfg(target_os = "macos")]
#[test]
fn sigabrt_bisect_diagnostic() {
    for (label, envs) in [
        ("baseline", vec![]),
        ("no-watchdog", vec![("VETTO_NO_PDEATH_WATCH", "1")]),
        ("no-limits", vec![("VETTO_NO_MAC_LIMITS", "1")]),
        (
            "no-watchdog-no-limits",
            vec![("VETTO_NO_PDEATH_WATCH", "1"), ("VETTO_NO_MAC_LIMITS", "1")],
        ),
    ] {
        let proj = crate::common::TempProject::new("sigabrt-bisect");
        let started = std::time::Instant::now();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
            .args(["--tui=none", "--", "/bin/sleep", "2"])
            .current_dir(proj.path())
            .env("HOME", crate::common::test_home())
            .env("VETTO_CHILD_TRACE", "1")
            .envs(envs.iter().copied())
            .output()
            .expect("run vetto for bisect");
        let elapsed = started.elapsed().as_secs_f64();
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stages: Vec<&str> = stderr
            .lines()
            .filter_map(|l| l.strip_prefix("vetto: child stage: "))
            .collect();
        let tail: Vec<&str> = stderr.lines().rev().take(4).collect();
        println!(
            "bisect[{label}]: code={:?} secs={elapsed:.1} stages={stages:?} stderr_tail={:?}",
            out.status.code(),
            tail.iter().rev().copied().collect::<Vec<_>>().join(" | ")
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_bisect_not_applicable_on_this_platform() {
    // Honest no-op: macOS diagnostics only run on macOS.
}
