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
    let home = std::env::temp_dir().join(format!("vetto-macos-test-home-{}", std::process::id()));
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).expect("create isolated macOS test HOME");
    std::fs::write(ssh.join("id_rsa"), "FAKE-VETTO-MACOS-KEY\n").expect("write fake key");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .args([
            "--tui=none",
            "--",
            "cat",
            &format!("{}/.ssh/id_rsa", home.display()),
        ])
        .env("HOME", &home)
        .output()
        .expect("vetto run");
    let _ = std::fs::remove_dir_all(&home);
    assert!(
        !out.status.success() || out.stdout.is_empty(),
        "ssh key readable through seatbelt"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn relay_net_modes_are_rejected_loudly_before_spawn() {
    // Both relay modes must fail closed with an explicit reason on macOS —
    // never silently degrade to --net=off.
    for mode in [
        "--net=allowlist:example.com",
        "--net=strict:github.com:22",
    ] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
            .args(["--tui=none", mode, "--", "true"])
            .output()
            .expect("vetto run");
        assert!(
            !out.status.success(),
            "{mode} must be rejected on macOS"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("network-namespace relay"),
            "{mode} rejection must explain why: {stderr}"
        );
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_suite_not_applicable_on_this_platform() {
    // Honest no-op: macOS tests only run on macOS (see release CI matrix).
}
