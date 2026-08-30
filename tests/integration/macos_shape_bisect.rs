//! DIAGNOSTIC: three hypotheses for why multi-clause seatbelt profiles abort
//! the exec'd binary on this runner while single-clause ones live:
//!   A. newlines in the profile string
//!   B. the (debug deny) directive
//!   C. fragmented per-directory file-read allows (vs one blanket subpath "/")
//! Pure sandbox-exec reproduction, no vetto involved. Remove with the fix.

#[cfg(target_os = "macos")]
#[test]
fn profile_shape_bisect() {
    let head_clauses = "(deny default)(allow process-exec)(allow process-fork)\
(allow sysctl-read)(allow mach-lookup)\
(allow file-read* (subpath \"/System\"))\
(allow file-read* (subpath \"/Library\"))\
(allow file-read* (subpath \"/private/var/db/dyld\"))\
(allow file-read* (subpath \"/usr/lib\"))\
(allow file-read* (subpath \"/bin\"))\
(allow file-read* (subpath \"/usr/bin\"))\
(allow file-read* (subpath \"/usr/share\"))\
(allow file-read* (subpath \"/dev/null\"))\
(allow file-read* (subpath \"/dev/urandom\"))";

    let cases: [(&str, String); 4] = [
        // Control: minimal, single line (proven live in earlier rounds).
        (
            "control-minimal",
            "(version 1)(deny default)(allow process-exec)(allow process-fork)\
(allow mach-lookup)(allow sysctl-read)(allow file-read* (subpath \"/\"))"
                .to_string(),
        ),
        // A: multi-line allow-default.
        (
            "A-multiline-allow-default",
            "(version 1)\n(allow default)\n".to_string(),
        ),
        // B: head clauses single line, with debug deny.
        (
            "B-singleline-debugdeny",
            format!("{head_clauses}(debug deny)"),
        ),
        // C: head clauses multi line, no debug deny.
        (
            "C-multiline-head",
            format!("(version 1)\n(deny default)\n{head_clauses}"),
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
