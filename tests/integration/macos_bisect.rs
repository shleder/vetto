//! DIAGNOSTIC for the macOS silent-SIGABRT hunt (remove with the fix).

#[cfg(target_os = "macos")]
#[test]
fn sigabrt_bisect_diagnostic() {
    // Clause-level bisect of the aborted profile. Variants:
    //   minimal       — proven working control
    //   replay-full   — the exact aborted profile (control, expected to fail)
    //   head / tail   — first 30 lines / line 1-5 + 31.. (narrows the half)
    //   nonet         — full profile without the network deny
    //   nonet+mach    — nonet plus an explicit mach-lookup allow
    let full = include_str!("fixtures/macos-bisect-replay.sbpl");
    let lines: Vec<&str> = full.lines().collect();
    let join = |slice: &[&str]| slice.join("\n");
    let head = join(&lines[..30]);
    let mut tail_parts: Vec<&str> = lines[..5].to_vec();
    tail_parts.extend_from_slice(&lines[30..]);
    let tail = join(&tail_parts);
    let mut nonet_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| !l.contains("(deny network*)"))
        .collect();
    nonet_lines.push("(allow mach-lookup)".into());
    let nonet_mach = nonet_lines.join("\n");

    let mut cases: Vec<(&str, String, Vec<(&str, &str)>)> = Vec::new();
    cases.push(("minimal", "(version 1)(deny default)(allow process-exec)(allow process-fork)(allow mach-lookup)(allow sysctl-read)(allow file-read* (subpath \"/\"))".to_string(), vec![]));
    cases.push(("replay-full", full.to_string(), vec![]));
    cases.push(("replay-head", head, vec![]));
    cases.push(("replay-tail", tail, vec![]));
    cases.push((
        "replay-nonet",
        join(&nonet_lines[..nonet_lines.len() - 1]),
        vec![],
    ));
    cases.push(("replay-nonet-mach", nonet_mach, vec![]));
    // Blanket read-allow candidate: if the poison is a denied startup read,
    // this configuration survives and names the class of the missing read.
    cases.push((
        "allow-all-reads",
        full.to_string(),
        vec![("VETTO_ALLOW_ALL_READS", "1")],
    ));

    for (label, profile, envs) in cases {
        let started = std::time::Instant::now();
        let out = std::process::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sleep", "1"])
            .output()
            .expect("run sandbox-exec");
        eprintln!(
            "sexec[{label}]: code={:?} secs={:.1} stderr={:?}",
            out.status.code(),
            started.elapsed().as_secs_f64(),
            String::from_utf8_lossy(&out.stderr).trim()
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
