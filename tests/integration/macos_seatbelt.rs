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
    for mode in ["--net=allowlist:example.com", "--net=strict:github.com:22"] {
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
            .args(["--tui=none", mode, "--", "true"])
            .output()
            .expect("vetto run");
        assert!(!out.status.success(), "{mode} must be rejected on macOS");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("network-namespace relay"),
            "{mode} rejection must explain why: {stderr}"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn agent_is_killed_when_vetto_is_sigkilled() {
    let mut vetto = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .args(["--tui=none", "--", "sleep", "30"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn vetto");
    let vetto_pid = vetto.id() as i32;

    // Wait for the agent (a direct child of vetto) to appear.
    let agent_pid = loop {
        let out = std::process::Command::new("/usr/bin/pgrep")
            .args(["-P", &vetto_pid.to_string()])
            .output()
            .expect("pgrep");
        if let Some(line) = String::from_utf8_lossy(&out.stdout).lines().next() {
            if let Ok(pid) = line.trim().parse::<i32>() {
                break pid;
            }
        }
        if vetto.try_wait().map(|s| s.is_some()).unwrap_or(true) {
            panic!("vetto exited before the agent spawned");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };

    // SIGKILL vetto itself; the pdeath watchdog must kill the agent shortly.
    vetto.kill().expect("SIGKILL vetto");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(6);
    loop {
        let alive = std::process::Command::new("/usr/bin/ps")
            .args(["-p", &agent_pid.to_string()])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !alive {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "agent {agent_pid} survived vetto's SIGKILL"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let _ = vetto.wait();
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_suite_not_applicable_on_this_platform() {
    // Honest no-op: macOS tests only run on macOS (see release CI matrix).
}
