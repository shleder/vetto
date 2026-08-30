//! DIAGNOSTIC: narrows which fragmented file-read clause kills the exec'd
//! binary under (deny default) on this runner. Pure sandbox-exec, no vetto.
//! Remove with the read-isolation fix.

#[cfg(target_os = "macos")]
#[test]
fn profile_shape_bisect() {
    let prelude = "(version 1)(deny default)(allow process-exec)(allow process-fork)\
(allow sysctl-read)(allow mach-lookup)";
    let cases: [(&str, String); 5] = [
        // Control: blanket read (proven live).
        (
            "C1-blanket-read",
            format!("{prelude}(allow file-read* (subpath \"/\"))"),
        ),
        // Fragmented without any /dev/* clauses.
        (
            "C2-no-dev",
            format!(
                "{prelude}\
(allow file-read* (subpath \"/System\"))\
(allow file-read* (subpath \"/Library\"))\
(allow file-read* (subpath \"/private/var/db/dyld\"))\
(allow file-read* (subpath \"/usr/lib\"))\
(allow file-read* (subpath \"/bin\"))\
(allow file-read* (subpath \"/usr/bin\"))\
(allow file-read* (subpath \"/usr/share\"))"
            ),
        ),
        // Bare minimum for dyld + sleep.
        (
            "C3-minimal-fragments",
            format!(
                "{prelude}\
(allow file-read* (subpath \"/System\"))\
(allow file-read* (subpath \"/usr/lib\"))\
(allow file-read* (subpath \"/bin\"))"
            ),
        ),
        // The most suspicious dev fragment alone.
        (
            "C4-dev-urandom-only",
            format!("{prelude}(allow file-read* (subpath \"/dev/urandom\"))"),
        ),
        // /System fragment alone.
        (
            "C5-system-only",
            format!("{prelude}(allow file-read* (subpath \"/System\"))"),
        ),
    ];

    for (label, profile) in cases {
        let started = std::time::Instant::now();
        let out = std::process::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sleep", "1"])
            .output()
            .expect("run sandbox-exec");
        eprintln!(
            "shape[{label}]: code={:?} secs={:.1} stderr={:?}",
            out.status.code(),
            started.elapsed().as_secs_f64(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // Deliberate: cargo test only shows captured output for FAILING tests.
    panic!("DIAGNOSTIC (remove with the read-isolation fix)");
}

#[cfg(not(target_os = "macos"))]
#[test]
fn profile_shape_bisect_not_applicable_on_this_platform() {
    // Honest no-op: macOS diagnostics only run on macOS.
}
