//! macOS seatbelt tests. On Linux these are inert placeholders so the shared
//! test binary stays green in CI; the real assertions run on macOS runners.

#[cfg(target_os = "macos")]
#[test]
fn doctor_reports_seatbelt() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .arg("doctor")
        .output()
        .expect("vetto doctor");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(text.contains("sandbox-exec"), "{text}");
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_blocks_home_secrets() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .args([
            "--tui=none",
            "--",
            "cat",
            &format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap()),
        ])
        .output()
        .expect("vetto run");
    assert!(
        !out.status.success() || out.stdout.is_empty(),
        "ssh key readable through seatbelt"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_suite_not_applicable_on_this_platform() {
    // Honest no-op: macOS tests only run on macOS (see release CI matrix).
}
