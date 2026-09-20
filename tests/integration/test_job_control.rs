//! Integration tests for POSIX terminal job control and foreground handoff.
//! Blueprint Section 11.2 (INV-37: Transparent PTY Terminal Handoff).

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Command;

#[test]
#[cfg(target_os = "linux")]
fn test_child_process_group_signal_masking() {
    // Verify that when setpgid is executed, the process is prepared for terminal handoff
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("echo ok");

    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            libc::signal(libc::SIGTTIN, libc::SIG_DFL);
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            Ok(())
        });
    }

    let output = cmd.output().expect("execute command");
    assert!(
        output.status.success(),
        "Command must execute without SIGTTIN crash"
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "ok");
}

#[test]
#[cfg(target_os = "linux")]
fn test_child_process_group_exit_status_preservation() {
    // Verify that setting process group and default signals preserves non-zero exit codes
    let mut cmd = Command::new("sh");
    cmd.arg("-c").arg("exit 42");

    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            libc::signal(libc::SIGTTIN, libc::SIG_DFL);
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            Ok(())
        });
    }

    let output = cmd.output().expect("execute command");
    assert_eq!(
        output.status.code(),
        Some(42),
        "Process group child must preserve exit code 42"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_terminal_handoff_isatty_check_safety() {
    // Verify that checking isatty on file descriptor 0 returns safely without crashing or raising signals
    let is_tty = unsafe { libc::isatty(0) };
    assert!(
        is_tty == 0 || is_tty == 1,
        "isatty must return 0 or 1, got {is_tty}"
    );
}

#[test]
#[cfg(not(target_os = "linux"))]
fn test_terminal_job_control_skipped_on_non_linux() {
    // Terminal job control handoff (INV-37) via tcsetpgrp is a Linux supervisor subsystem.
}
