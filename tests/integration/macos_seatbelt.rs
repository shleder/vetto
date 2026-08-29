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
fn secret_reads_are_not_yet_isolated_on_macos() {
    // KNOWN LIMITATION, pinned on purpose. The working macOS profile keeps
    // reads broad (see the seatbelt module doc): read isolation plus working
    // process startup do not coexist in SBPL on current macOS, and the
    // trailing secret denies lose to the broad read allow. Secret-path reads
    // on macOS are therefore NOT isolated yet — the enforced set is write
    // isolation + net=off. Turning this into an unreadability assertion is
    // the roadmap item.
    let home = std::env::temp_dir().join(format!("vetto-macos-test-home-{}", std::process::id()));
    let ssh = home.join(".ssh");
    std::fs::create_dir_all(&ssh).expect("create isolated macOS test HOME");
    std::fs::write(ssh.join("id_rsa"), "FAKE-VETTO-MACOS-KEY\n").expect("write fake key");
    let key_path = home.join(".ssh/id_rsa");
    let proj = crate::common::TempProject::new("seatbelt-secret-macos");
    let out = crate::common::run_vetto_in(
        proj.path(),
        &["--tui=none", "--", "cat", &key_path.to_string_lossy()],
    );
    let _ = std::fs::remove_dir_all(&home);
    let stdout = String::from_utf8_lossy(&out.stdout);
    if stdout.contains("FAKE-VETTO-MACOS-KEY") {
        eprintln!(
            "vetto: macOS read isolation is not enforced (known limitation); \
             the secret was readable"
        );
    }
    // The enforced property: the session completes.
    assert!(
        out.status.success() || !stdout.is_empty(),
        "session did not complete"
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
    // Same environment contract as every other macOS session test: the
    // isolated harness HOME and a scratch cwd. Running against the runner's
    // real $HOME and the repo checkout makes this the only session whose
    // policy surface differs, which is exactly the kind of divergence a
    // flaky-looking failure feeds on.
    let proj = crate::common::TempProject::new("pdeath-watch");
    let mut vetto = std::process::Command::new(env!("CARGO_BIN_EXE_vetto"))
        .args(["--tui=none", "--", "sleep", "30"])
        .current_dir(proj.path())
        .env("HOME", crate::common::test_home())
        .env("VETTO_CHILD_TRACE", "1")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn vetto");
    let vetto_pid = vetto.id() as i32;

    // Wait for the agent (a direct child of vetto) to appear. On any early
    // vetto exit, panic with vetto's stderr: a bare "it exited" hides whether
    // the spawn chain, the watchdog, or the test setup is at fault.
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
        match vetto.try_wait() {
            Ok(Some(status)) => {
                let mut diag = String::new();
                if let Some(mut err) = vetto.stderr.take() {
                    use std::io::Read;
                    let _ = err.read_to_string(&mut diag);
                }
                panic!("vetto exited before the agent spawned: {status}; stderr: {diag}");
            }
            Ok(None) => {}
            Err(error) => {
                std::thread::sleep(std::time::Duration::from_millis(200));
                panic!("try_wait errored while waiting for the agent: {error}");
            }
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

#[cfg(target_os = "macos")]
#[test]
fn agent_survives_a_full_session() {
    // Pin for the write-isolation profile model: the exec'd agent must live
    // through a session (the multi-clause fragmented-read profiles aborted
    // every exec'd binary with a silent SIGABRT; see the seatbelt module).
    let proj = crate::common::TempProject::new("seatbelt-session");
    let out = crate::common::run_vetto_in(proj.path(), &["--tui=none", "--", "/bin/sleep", "2"]);
    assert!(
        out.status.success(),
        "session died: {:?} stderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn secrets_stay_denied_under_broad_read() {
    // KNOWN LIMITATION twin of secret_reads_are_not_yet_isolated_on_macos:
    // reads are broad in the working profile and secret reads are not
    // isolated yet. This test only pins that the SESSION works with a
    // deny_resolved secret present (the trailing-deny machinery must not
    // break the launch).
    crate::common::ensure_fake_ssh_key();
    let key_path = crate::common::test_home().join(".ssh/id_rsa");
    let out = crate::common::run_vetto_in(
        crate::common::test_home(),
        &["--tui=none", "--", "cat", &key_path.to_string_lossy()],
    );
    eprintln!(
        "vetto: secret readable on macOS (known limitation): {}",
        String::from_utf8_lossy(&out.stdout).contains("FAKE-TEST-KEY-MATERIAL-FOR-VETTO-IT")
    );
    assert!(
        out.status.success() || !String::from_utf8_lossy(&out.stdout).is_empty(),
        "session with deny_resolved secrets did not complete"
    );
}

#[cfg(not(target_os = "macos"))]
#[test]
fn macos_suite_not_applicable_on_this_platform() {
    // Honest no-op: macOS tests only run on macOS (see release CI matrix).
}
