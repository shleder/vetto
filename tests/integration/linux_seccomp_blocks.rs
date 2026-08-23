//! Negative syscall tests.  The helper makes raw calls so libc wrappers and
//! command-specific permission checks cannot hide which ABI entry was used.

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
use crate::common::*;

#[cfg(target_os = "linux")]
fn compile_probe(project: &std::path::Path) -> Option<String> {
    if !tool_available("cc") {
        eprintln!("SKIP: cc is unavailable");
        return None;
    }
    let output = project.join("seccomp_probe");
    let status = Command::new("cc")
        .args(["-O2", "-Wall", "-Wextra"])
        .arg(fixture("seccomp_probe.c"))
        .arg("-o")
        .arg(&output)
        .status()
        .expect("spawn cc");
    assert!(status.success(), "compile seccomp probe");
    // Pass the resolved path so policy loading can verify the executable is
    // inside the temporary project read scope before the sandbox starts.
    Some(output.to_string_lossy().into_owned())
}

#[test]
#[cfg(target_os = "linux")]
fn sensitive_process_mount_and_async_io_syscalls_are_blocked() {
    if !have_landlock() {
        eprintln!("SKIP: no Linux enforcement tier on this machine");
        return;
    }
    let project = TempProject::new("seccomp-negative");
    write_file(&project.path().join(".env"), "SECRET=must-not-be-visible\n");
    let policy = project.path().join("seccomp-policy.toml");
    write_file(
        &policy,
        r#"
[filesystem]
allow_write = ["/tmp"]
allow_read = ["$PROJECT", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/dev/null", "/dev/zero", "/dev/urandom"]
"#,
    );
    let Some(probe) = compile_probe(project.path()) else {
        return;
    };

    for operation in [
        "ptrace",
        "process_vm_readv",
        "process_vm_writev",
        "pidfd_getfd",
        "mount",
        "umount2",
        "pivot_root",
        "perf_event_open",
        "bpf",
        "kexec_load",
        "kexec_file_load",
        "init_module",
        "finit_module",
        "delete_module",
        "reboot",
        "swapon",
        "swapoff",
        "io_uring_setup",
        "io_uring_enter",
        "io_uring_register",
        "userfaultfd",
    ] {
        // Exercise the syscall filter even on kernels where FULL's private
        // proc mount is unavailable; the FS-ONLY tier has the same filter.
        let out = run_vetto_env_in(
            project.path(),
            &[
                "--tui=none",
                "--policy",
                policy.to_str().expect("policy path is UTF-8"),
                "--",
                &probe,
                operation,
            ],
            &[("VETTO_FORCE_TIER", "fs-only")],
        );
        if out.status.code() == Some(77) {
            eprintln!("SKIP unsupported syscall probe: {operation}");
            continue;
        }
        assert!(
            out.status.success(),
            "{operation} escaped seccomp; stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).contains(&format!("blocked:{operation}:EPERM")),
            "unexpected {operation} result: stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
    }
}

#[test]
#[cfg(not(target_os = "linux"))]
fn linux_only() {}
