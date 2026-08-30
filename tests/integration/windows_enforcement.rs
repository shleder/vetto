//! Windows enforcement tests.  On other platforms these are inert placeholders
//! so the shared test binary stays green in CI; the real assertions run on
//! Windows runners where the experimental AppContainer backend is available.
//! Every Windows test starts with a capability gate over `vetto doctor` and
//! skips with an explicit reason instead of asserting against a run that the
//! fail-closed backend itself would refuse.

#[cfg(not(target_os = "windows"))]
#[test]
fn windows_enforcement_suite_not_applicable_on_this_platform() {
    // Honest no-op: the Windows process sandbox backend only exists on
    // Windows (see release CI matrix).
}

#[cfg(target_os = "windows")]
mod windows_only {
    use std::net::TcpListener;

    use crate::common::{doctor_output, run_vetto_in, stderr, stdout, write_file, TempProject};

    /// True only when doctor reports the full Windows process-sandbox stack:
    /// the AppContainer APIs and the experimental
    /// `Experimental_CreateProcessInSandbox` export.  Without them the backend
    /// refuses to run, so enforcement tests must skip honestly.
    fn backend_available() -> bool {
        let doctor = doctor_output();
        doctor.contains("appcontainer-api=yes")
            && doctor.contains("experimental-process-sandbox=yes")
    }

    const BACKEND_SKIP: &str = "SKIP: Windows AppContainer/experimental sandbox backend is unavailable (doctor did not report appcontainer-api=yes and experimental-process-sandbox=yes)";

    #[test]
    fn read_outside_granted_roots_fails() {
        if !backend_available() {
            eprintln!("{BACKEND_SKIP}");
            return;
        }
        // The sentinel file lives in a directory next to (not inside) the
        // sandboxed project.  The default Windows grants are the project and
        // the drive-root tmp path, so this file is outside every granted
        // root.
        let external = TempProject::new("win-read-external");
        let outside = external.path().join("outside.txt");
        write_file(&outside, "VETTO-IT-OUTSIDE-CONTENT");
        let outside_text = outside.to_string_lossy().into_owned();

        let project = TempProject::new("win-read-project");
        let output = run_vetto_in(
            project.path(),
            &[
                "--tui=none",
                "--",
                "cmd",
                "/c",
                "type",
                outside_text.as_str(),
            ],
        );
        // The honest property is content absence: the child may fail, be
        // denied by AppContainer, or print an error, but the sentinel text
        // must never reach stdout through the inherited stdio.
        let out = stdout(&output);
        assert!(
            !out.contains("VETTO-IT-OUTSIDE-CONTENT"),
            "content from outside the granted roots reached stdout: {out}"
        );
    }

    #[test]
    fn write_outside_granted_roots_fails() {
        if !backend_available() {
            eprintln!("{BACKEND_SKIP}");
            return;
        }
        let external = TempProject::new("win-write-external");
        let outside = external.path().join("outside.txt");
        // Pre-existing sentinel: the run must leave it byte-for-byte
        // unchanged, which also covers the not-created case via absence.
        write_file(&outside, "VETTO-IT-ORIGINAL-CONTENT");
        let outside_text = outside.to_string_lossy().into_owned();

        let project = TempProject::new("win-write-project");
        let output = run_vetto_in(
            project.path(),
            &[
                "--tui=none",
                "--",
                "cmd",
                "/c",
                "echo",
                "x>",
                outside_text.as_str(),
            ],
        );
        let after = std::fs::read_to_string(&outside).unwrap_or_default();
        assert_eq!(
            after,
            "VETTO-IT-ORIGINAL-CONTENT",
            "file outside the granted roots was created or modified; stderr: {}",
            stderr(&output)
        );
    }

    #[test]
    fn network_off_blocks_loopback() {
        if !backend_available() {
            eprintln!("{BACKEND_SKIP}");
            return;
        }
        // This asserts the default-deny NetworkPolicy compiled into the spec:
        // an AppContainer without a network capability cannot reach even
        // loopback, so the connection attempt must raise instead of
        // succeeding.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let port = listener.local_addr().expect("listener local addr").port();
        // Keep the listener bound for the whole run so a successful connect
        // (into the backlog) is the only way to print CONNECTED.
        let _keep_bound = &listener;

        let probe = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "exit 0"])
            .output();
        let powershell_ready = probe.map(|o| o.status.success()).unwrap_or(false);
        if !powershell_ready {
            eprintln!(
                "SKIP: powershell is unavailable on this runner; cannot exercise the default-deny network policy from inside the sandbox"
            );
            return;
        }

        let script = format!(
            "try {{ (New-Object Net.Sockets.TcpClient('127.0.0.1',{port})).Close(); 'CONNECTED' }} catch {{ 'BLOCKED' }}"
        );
        let project = TempProject::new("win-net-project");
        let output = run_vetto_in(
            project.path(),
            &[
                "--tui=none",
                "--",
                "powershell",
                "-NoProfile",
                "-Command",
                script.as_str(),
            ],
        );
        let out = stdout(&output);
        assert!(
            !out.contains("CONNECTED"),
            "loopback connect succeeded inside the sandbox; stdout: {out} stderr: {}",
            stderr(&output)
        );
    }

    #[test]
    fn job_limits_do_not_break_small_sessions() {
        if !backend_available() {
            eprintln!("{BACKEND_SKIP}");
            return;
        }
        // as=2 GiB becomes the Job memory limit and procs=256 the active
        // process limit; a successful trivial session proves those flag bits
        // construct a Job Object the experimental launcher accepts.
        let project = TempProject::new("win-limits-project");
        let output = run_vetto_in(
            project.path(),
            &[
                "--limits",
                "as=2147483648,procs=256",
                "--tui=none",
                "--",
                "cmd",
                "/c",
                "echo",
                "ok",
            ],
        );
        assert!(
            output.status.success(),
            "a small session under explicit job limits must succeed; stderr: {}",
            stderr(&output)
        );
        assert!(
            stdout(&output).contains("ok"),
            "echo output missing from stdout: {}",
            stdout(&output)
        );
    }
}
