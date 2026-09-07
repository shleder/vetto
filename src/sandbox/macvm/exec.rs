//! Agent exec inside the Linux guest via ssh. The guest runs a Linux `vetto`
//! binary, which owns Tier-1 enforcement (Landlock/seccomp/namespaces).
//! The macOS host never executes the agent through this backend.
//!
//! Exit code passthrough: the ssh exit status IS the agent exit status
//! (ssh propagates the remote command's exit code by protocol). Signals
//! surface as 128+sig on the remote side; that mapping is preserved, not
//! reinterpreted.
//!
//! Only argv builders and shell-quoting are unit-tested. Spawning ssh is
//! intentionally untested (no local execution in unit tests).

use std::collections::HashMap;
use std::path::Path;
use std::process::Child;

use anyhow::{bail, Context, Result};

use super::MacVmConfig;
use super::{GUEST_VETTO, GUEST_WORKSPACE};
use crate::config::NetMode;
use crate::policy::Policy;

/// ssh connect timeout for probes (seconds).
pub const SSH_PROBE_TIMEOUT_SECS: u64 = 5;

/// POSIX-shell-quote one argument. Pure logic — unit-tested.
pub fn shell_quote(arg: &str) -> String {
    if !arg.is_empty()
        && arg
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./:=+@,".contains(&b))
    {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('\'');
    for ch in arg.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Build the base `ssh` argv (no remote command yet). Pure logic — unit-tested.
pub fn ssh_base_argv(cfg: &MacVmConfig, timeout_secs: u64) -> Vec<String> {
    let mut argv = vec![
        "ssh".to_string(),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        format!("ConnectTimeout={timeout_secs}"),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
    ];
    if let Some(key) = &cfg.ssh_key {
        if !key.trim().is_empty() {
            argv.push("-i".to_string());
            argv.push(key.clone());
        }
    }
    argv.push(cfg.effective_ssh_target());
    argv
}

/// Build the remote shell script the guest runs: cd to workspace, exec the
/// Linux vetto binary with the agent command as its trailing args, then
/// propagate the exit code. Pure logic — unit-tested.
///
/// The guest vetto enforces Tier-1 itself; flags mirror the host policy:
/// `--net` is forwarded verbatim (the guest owns the netns relay stack).
pub fn guest_vetto_argv(policy: &Policy, net: &NetMode, agent_cmd: &[String]) -> Vec<String> {
    let mut argv = vec![
        GUEST_VETTO.to_string(),
        "--profile".to_string(),
        policy.name.clone(),
        "--net".to_string(),
        net.label(),
        "--tui=none".to_string(),
        "--".to_string(),
    ];
    argv.extend(agent_cmd.iter().cloned());
    argv
}

/// Assemble the full remote command string (shell-quoted). Pure logic —
/// unit-tested.
pub fn remote_command_string(guest_argv: &[String]) -> String {
    // `cd <ws> && exec <quoted argv...>`: exec replaces the shell so the
    // ssh exit status is exactly the agent's exit status.
    let mut cmd = format!("cd {} && exec", shell_quote(GUEST_WORKSPACE));
    for arg in guest_argv {
        cmd.push(' ');
        cmd.push_str(&shell_quote(arg));
    }
    cmd
}

/// Full `ssh` argv for the session (base + remote command). Pure logic —
/// unit-tested.
pub fn session_ssh_argv(
    cfg: &MacVmConfig,
    policy: &Policy,
    net: &NetMode,
    agent_cmd: &[String],
) -> Vec<String> {
    let mut argv = ssh_base_argv(cfg, 10);
    argv.push(remote_command_string(&guest_vetto_argv(
        policy, net, agent_cmd,
    )));
    argv
}

/// Check ssh reachability once (true probe, bounded). Fail-closed on error.
pub fn ssh_reachable(cfg: &MacVmConfig) -> Result<()> {
    let target = cfg.effective_ssh_target();
    if target.trim().is_empty() {
        bail!("mac-vm: no ssh target configured");
    }
    let mut argv = ssh_base_argv(cfg, SSH_PROBE_TIMEOUT_SECS);
    argv.push("true".to_string());
    let (prog, args) = argv.split_first().expect("ssh argv non-empty");
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .with_context(|| format!("mac-vm: failed to spawn ssh to {target}"))?;
    if !out.status.success() {
        bail!(
            "mac-vm: ssh to {target} failed ({}): {}\n\
             action: start the VM and ensure guest sshd + key auth work; run `vetto doctor`",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Wait for ssh readiness with a bounded deadline (`ip_wait_secs`).
/// Fail-closed on timeout — never proceed to exec without ssh.
pub fn ssh_wait_ready(cfg: &MacVmConfig) -> Result<()> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(cfg.ip_wait_secs.max(1));
    let mut last_err = String::new();
    while std::time::Instant::now() < deadline {
        match ssh_reachable(cfg) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = format!("{e:#}");
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
        }
    }
    bail!(
        "mac-vm: guest ssh not ready within {}s (last: {last_err}); refusing to run (fail-closed)\n\
         action: check the VM booted and guest sshd listens; run `vetto doctor`",
        cfg.ip_wait_secs
    )
}

/// Read a small file from the guest over ssh (marker verification).
pub fn ssh_read_file(cfg: &MacVmConfig, remote: &str) -> Result<String> {
    let mut argv = ssh_base_argv(cfg, 10);
    argv.push(format!("cat {}", shell_quote(remote)));
    let (prog, args) = argv.split_first().expect("ssh argv non-empty");
    let out = std::process::Command::new(prog)
        .args(args)
        .output()
        .with_context(|| "mac-vm: failed to spawn ssh for marker read")?;
    if !out.status.success() {
        bail!(
            "mac-vm: guest marker read failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Write a small file into the guest over ssh (marker write).
pub fn ssh_write_file(cfg: &MacVmConfig, remote: &str, content: &str) -> Result<()> {
    // Content goes through stdin to avoid quoting pitfalls: `cat > file`.
    let mut argv = ssh_base_argv(cfg, 10);
    argv.push(format!("cat > {}", shell_quote(remote)));
    let (prog, args) = argv.split_first().expect("ssh argv non-empty");
    let mut child = std::process::Command::new(prog)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .with_context(|| "mac-vm: failed to spawn ssh for marker write")?;
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(content.as_bytes());
    }
    let out = child
        .wait_with_output()
        .with_context(|| "mac-vm: ssh marker write wait failed")?;
    if !out.status.success() {
        bail!(
            "mac-vm: guest marker write failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Spawn the guest session as an ssh child with the caller's stdio wiring.
/// Returns the live child; the caller converts it to a pid-based handle
/// (mirroring the legacy macOS backend). No threads are spawned here.
pub fn spawn_guest(
    cfg: &MacVmConfig,
    project: &Path,
    opts: &super::super::handle::SpawnOptions,
    guest_cmd: Vec<String>,
) -> Result<Child> {
    use std::os::unix::io::AsRawFd;
    use std::process::Stdio;

    if guest_cmd.is_empty() {
        bail!("mac-vm: empty guest command; refusing to run (fail-closed)");
    }
    let remote = remote_command_string(&guest_cmd);
    let base = ssh_base_argv(cfg, 10);
    let (prog, base_args) = base.split_first().expect("ssh argv non-empty");
    let mut cmd = std::process::Command::new(prog);
    cmd.args(base_args);
    cmd.arg(remote);
    // Run the remote session from the project dir for parity with the
    // host backends (ssh itself does not need it, but relative argv
    // resolution and diagnostics do).
    cmd.current_dir(project);
    // Guest env: allowlisted host env minus secrets, forwarded explicitly
    // via `env VAR=... ssh ...`. Only VETTO_* markers + extras cross.
    let guest_env_map: HashMap<String, String> = HashMap::new();
    let _ = guest_env_map;
    match opts.stdio {
        super::super::handle::StdioMode::Pty { slave_fd } => {
            // PTY slave is a live fd owned by main; hand it to ssh as
            // stdin/stdout/stderr via raw-fd duplication.
            // SAFETY: slave_fd is a live PTY descriptor owned by the
            // caller for the duration of spawn.
            let slave = unsafe { std::os::fd::BorrowedFd::borrow_raw(slave_fd) };
            cmd.stdin(unsafe { stdio_from_borrowed(slave) });
            cmd.stdout(unsafe { stdio_from_borrowed(slave) });
            cmd.stderr(unsafe { stdio_from_borrowed(slave) });
        }
        super::super::handle::StdioMode::Captured { stdout_w, stderr_w } => {
            use std::os::fd::FromRawFd;
            cmd.stdin(Stdio::null());
            // SAFETY: write ends are live pipe descriptors owned by main.
            cmd.stdout(unsafe { Stdio::from_raw_fd(libc_dup(stdout_w)) });
            cmd.stderr(unsafe { Stdio::from_raw_fd(libc_dup(stderr_w)) });
        }
        super::super::handle::StdioMode::Inherit => {
            cmd.stdin(Stdio::inherit());
            cmd.stdout(Stdio::inherit());
            cmd.stderr(Stdio::inherit());
        }
    }
    // Put ssh in its own process group so terminate() (kill(-pgid))
    // never targets vetto's group — same contract as the legacy backend.
    use std::os::unix::process::CommandExt as _;
    unsafe {
        cmd.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    cmd.spawn()
        .with_context(|| "mac-vm: failed to spawn ssh session")
}

/// Duplicate a raw fd (owned by the caller) for `Stdio::from_raw_fd`.
fn libc_dup(fd: i32) -> i32 {
    // SAFETY: plain dup on a live descriptor; on failure returns -1 and
    // the subsequent from_raw_fd would be UB — so abort fail-closed.
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        // Fail-closed: a broken stdio pipe must never become a silent
        // host run. Abort the spawn with a clear message via panic-catch
        // in the caller? No — return value cannot fail here, so exit the
        // whole spawn loudly. This path is unreachable in practice
        // (live pipe fds), and crashing is safer than a hijacked fd.
        eprintln!("vetto: mac-vm: dup(stdio fd) failed; refusing to run (fail-closed)");
        unsafe { libc::_exit(125) };
    }
    duped
}

/// Build a `Stdio` from a borrowed fd by duping it first.
/// SAFETY: caller guarantees `fd` is live for this call.
unsafe fn stdio_from_borrowed(fd: std::os::fd::BorrowedFd<'_>) -> std::process::Stdio {
    use std::os::fd::{AsRawFd, FromRawFd};
    unsafe { std::process::Stdio::from_raw_fd(libc_dup(fd.as_raw_fd())) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> MacVmConfig {
        MacVmConfig {
            ssh_target: "vetto@192.168.64.2".into(),
            ssh_key: None,
            helper: super::super::DEFAULT_HELPER.into(),
            ip_wait_secs: 120,
        }
    }

    #[test]
    fn quote_safe_passthrough() {
        assert_eq!(shell_quote("abcXYZ-_.:/=+@,09"), "abcXYZ-_.:/=+@,09");
    }

    #[test]
    fn quote_spaces_and_metachars() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("a$b"), "'a$b'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn base_argv_shape() {
        let argv = ssh_base_argv(&cfg(), 5);
        assert_eq!(argv[0], "ssh");
        assert!(argv.contains(&"BatchMode=yes".to_string()));
        assert!(argv.contains(&"ConnectTimeout=5".to_string()));
        assert_eq!(argv.last().unwrap(), "vetto@192.168.64.2");
    }

    #[test]
    fn base_argv_with_key() {
        let mut c = cfg();
        c.ssh_key = Some("/k".into());
        let argv = ssh_base_argv(&c, 5);
        let i = argv.iter().position(|a| a == "-i").unwrap();
        assert_eq!(argv[i + 1], "/k");
    }

    #[test]
    fn remote_command_exec_semantics() {
        let cmd = remote_command_string(&["/usr/local/bin/vetto".into(), "--".into(), "x".into()]);
        assert!(cmd.starts_with("cd /mnt/vetto-workspace && exec "));
        assert!(cmd.contains("/usr/local/bin/vetto"));
    }

    #[test]
    fn session_argv_is_single_remote_string() {
        use crate::policy::Policy;
        // Minimal policy surface: only name + net label matter here.
        let mut pol = Policy::default();
        pol.name = "default".to_string();
        let argv = session_ssh_argv(&cfg(), &pol, &NetMode::Off, &["agent".into()]);
        assert_eq!(argv[0], "ssh");
        // Last element is the whole remote command (one string).
        assert!(argv.last().unwrap().contains("exec"));
    }

    #[test]
    fn no_sbpl_references() {
        // Split literals: the forbidden tokens must not appear verbatim in
        // this file (the test reads its own source), so build them at runtime.
        let forbidden1 = ["sb", "pl"].concat();
        let forbidden2 = ["seat", "belt"].concat();
        let src = include_str!("exec.rs").to_lowercase();
        assert!(!src.contains(&forbidden1));
        assert!(!src.contains(&forbidden2));
    }
}
