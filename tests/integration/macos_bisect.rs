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
    let mut matrix = Vec::new();
    for (label, envs) in [
        ("baseline-unix-allow", vec![]),
        ("control-no-seatbelt", vec![("VETTO_SEATBELT_MODE", "none")]),
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
        let line = format!(
            "bisect[{label}]: code={:?} secs={elapsed:.1} stages={stages:?} stderr_tail={:?}",
            out.status.code(),
            tail.iter().rev().copied().collect::<Vec<_>>().join(" | ")
        );
        eprintln!("{line}");
        matrix.push(line);
        if label == "baseline" {
            // The full child stderr (profile dump included) and the newest
            // crash report name the exact abort reason.
            println!("bisect[baseline] FULL STDERR:\n{stderr}");
            let reports = std::env::var_os("HOME")
                .map(|h| {
                    let mut p = std::path::PathBuf::from(h);
                    p.push("Library/Logs/DiagnosticReports");
                    p
                })
                .map(|dir| {
                    let mut names: Vec<(std::time::SystemTime, std::path::PathBuf)> =
                        std::fs::read_dir(dir)
                            .into_iter()
                            .flatten()
                            .flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.to_string_lossy().contains("sleep")
                                    || p.extension().map(|x| x == "ips").unwrap_or(false)
                            })
                            .filter_map(|p| {
                                let meta = std::fs::metadata(&p).ok()?;
                                Some((meta.modified().ok()?, p))
                            })
                            .collect();
                    names.sort();
                    names
                        .into_iter()
                        .map(|(_, p)| p)
                        .collect::<Vec<std::path::PathBuf>>()
                })
                .unwrap_or_default();
            match reports.last() {
                Some(newest) => println!(
                    "bisect[baseline] newest diagnostic report {newest:?}:\n{}",
                    std::fs::read_to_string(newest).unwrap_or_default()
                ),
                None => println!("bisect[baseline] no crash reports found"),
            }
        }
    }
    // Deliberate: the matrix must reach the CI log verbatim, and cargo test
    // only prints captured output for FAILING tests. Remove this diagnostic
    // once the SIGABRT root cause is fixed.
    panic!(
        "DIAGNOSTIC MATRIX (remove with the SIGABRT fix):\n{}",
        matrix.join("\n")
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_bisect_not_applicable_on_this_platform() {
    // Honest no-op: macOS diagnostics only run on macOS.
}
