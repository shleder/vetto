//! macOS backend: Native C API Seatbelt (`sandbox_init_with_parameters`).
//!
//! Applies an in-memory SBPL profile directly to the child process post-fork
//! before `execve`, eliminating temporary profile files on disk and the
//! deprecated `/usr/bin/sandbox-exec` CLI wrapper.
//!
//! HONEST LIMITS (also in SECURITY.md):
//! - Seatbelt denials are invisible to FSEvents (same enforcement-vs-
//!   visibility gap as Linux); macOS visibility is inherently delayed.
//! - A kqueue watchdog (`pdeath_watch`, forked from the parent right after
//!   the agent child exists) SIGKILLs the agent when vetto dies, closing the
//!   SIGKILLed-vetto orphan gap. Best-effort: if the fork fails the session
//!   runs without it (reported on stderr).
//! - Relay network modes (`allowlist`/`strict`) are Linux-only; macOS
//!   supports `--net=off` only and rejects the rest before forking.
//! - Policy rlimits (CPU, address space, processes, open files, file size)
//!   are applied in the child before exec, matching the Linux tier.

pub mod fsevents;
pub mod limits;
pub mod pdeath_watch;
pub mod seatbelt;

use std::ffi::CString;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{anyhow, bail, Result};

use super::handle::{KillStrategy, SandboxHandle, SpawnOptions, StdioMode};
use super::Spawned;
use crate::config::NetMode;
use crate::policy::Policy;

pub struct MacosSandbox {
    pub net: NetMode,
}

impl MacosSandbox {
    pub fn new(net: NetMode) -> Self {
        Self { net }
    }

    /// True when the native C API Seatbelt or legacy runner is present.
    pub fn seatbelt_available() -> bool {
        seatbelt::is_native_seatbelt_available()
            || std::path::Path::new("/usr/bin/sandbox-exec").exists()
    }

    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> Result<Spawned> {
        if !Self::seatbelt_available() {
            bail!("Seatbelt (sandbox_init_with_parameters / sandbox-exec) unavailable; refusing to run unsandboxed (fail-closed)");
        }
        // Relay modes require the Linux netns + broker stack. Both are
        // rejected loudly here instead of silently degrading to --net=off.
        if matches!(self.net, NetMode::Allowlist(_)) {
            bail!("--net=allowlist requires the Linux network-namespace relay and is unavailable on macOS; refusing silently-weaker enforcement (fail-closed)");
        }
        if matches!(self.net, NetMode::Strict(_)) {
            bail!("--net=strict requires the Linux network-namespace relay and is unavailable on macOS; refusing silently-weaker enforcement (fail-closed)");
        }

        let (err_r, err_w) = pipe2()?;
        let err_w_raw = err_w.as_raw_fd();

        let agent_c: Vec<CString> = opts
            .agent_cmd
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();
        let env_c = build_envp(policy, &opts);
        let opts_ref = &opts;
        let policy_ref = policy;
        let net_ref = &self.net;

        // SAFETY: fork before any worker threads exist (same iron rule as Linux).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            bail!("fork: {}", std::io::Error::last_os_error());
        }
        if pid == 0 {
            child(policy_ref, net_ref, agent_c, env_c, err_w_raw, opts_ref);
        }
        drop(err_w);

        // The parent-death watchdog must be forked HERE, from the parent —
        // never inside the child. A second fork in the child poisons
        // libSystem's fork-safety state, and the CF/ObjC calls inside
        // `sandbox_init_with_parameters` then abort the agent (silent
        // SIGABRT, no stderr). The parent has no threads yet, so a fork
        // here is safe, and the child pid is exactly what the helper needs
        // to watch. The helper closes every inherited descriptor above 2.
        // SAFETY: scalar-only getpid.
        pdeath_watch::spawn(unsafe { libc::getpid() }, pid);

        // Same readiness protocol as the Linux chains.
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(err_r.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        match (n, b[0]) {
            (1, b'R') => {}
            (1, b'E') => {
                let code = reap(pid);
                return Err(anyhow!("sandbox setup failed (child exit {code})"));
            }
            _ => {
                let code = reap(pid);
                return Err(anyhow!("sandbox child died during setup (exit {code})"));
            }
        }

        Ok(Spawned {
            handle: SandboxHandle {
                root_pid: pid as u32,
                strategy: Some(KillStrategy::ProcessGroup {
                    pid,
                    pgid: pid,
                    // No sub-reaper sweep on macOS: kill(-pgid) semantics
                    // are unchanged. setsid escapers remain the documented
                    // macOS gap (no pidns, no PR_SET_CHILD_SUBREAPER use).
                    sweep: false,
                }),
            },
            broker_ctrl_fd: None,
            relay_port: None,
            notif_listener: None,
        })
    }
}

fn reap(pid: libc::pid_t) -> i32 {
    let mut status = 0i32;
    // SAFETY: plain waitpid on our child.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

fn pipe2() -> Result<(std::os::fd::OwnedFd, std::os::fd::OwnedFd)> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; scalar flags.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        bail!("pipe: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from a successful pipe.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn child_write_all(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: raw write on the live setup pipe; EINTR is retried.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
        } else if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        } else {
            return;
        }
    }
}

fn child_fail(err_w: RawFd, code: i32, msg: &str) -> ! {
    let mut reason = String::with_capacity(msg.len() + 4);
    reason.push_str("E:");
    reason.push_str(msg);
    reason.push('\n');
    child_write_all(err_w, reason.as_bytes());
    // SAFETY: immediate child exit after reporting setup failure.
    unsafe { libc::_exit(code) }
}

fn close_all_except(keep: &[RawFd]) {
    // SAFETY: sysconf is scalar-only.
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) } as i32;
    let max = max.clamp(16, 65_536);
    for fd in 3..max {
        if !keep.contains(&fd) {
            // SAFETY: closing our own descriptor range; EBADF is harmless.
            unsafe { libc::close(fd) };
        }
    }
}

fn dup2_to(fd: RawFd, target: RawFd) -> Result<(), String> {
    loop {
        // SAFETY: dup2 onto a stdio slot.
        if unsafe { libc::dup2(fd, target) } >= 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(format!("dup2({fd}, {target}): {error}"));
    }
}

/// Pre-exec stage tracer, enabled per-session with VETTO_CHILD_TRACE=1.
/// The child cannot use logging machinery after fork; a raw stderr line is
/// the only honest breadcrumb trail when a stage dies without a message
/// (e.g. a silent SIGABRT from a platform library).
fn child_trace(stage: &str) {
    if std::env::var_os("VETTO_CHILD_TRACE").is_some() {
        eprintln!("vetto: child stage: {stage}");
    }
}

fn child(
    policy: &Policy,
    net: &NetMode,
    agent: Vec<CString>,
    env: Vec<CString>,
    err_w: RawFd,
    opts: &SpawnOptions,
) -> ! {
    child_trace("entered");
    let mut keep: Vec<RawFd> = vec![err_w];
    match opts.stdio {
        StdioMode::Pty { slave_fd } => keep.push(slave_fd),
        StdioMode::Captured { stdout_w, stderr_w } => {
            keep.push(stdout_w);
            keep.push(stderr_w);
        }
        StdioMode::Inherit => {}
    }
    close_all_except(&keep);

    // PTY mode needs a new session for TIOCSCTTY. Captured and inherited
    // modes preserve the caller's session, but still get a private process
    // group so SandboxHandle::terminate never targets the caller's group.
    match opts.stdio {
        StdioMode::Pty { .. } => {
            // SAFETY: scalar-only setsid in the freshly forked child.
            if unsafe { libc::setsid() } < 0 {
                child_fail(
                    err_w,
                    125,
                    &format!("setsid: {}", std::io::Error::last_os_error()),
                );
            }
        }
        StdioMode::Captured { .. } | StdioMode::Inherit => {
            // SAFETY: put only this child in a new process group; unlike
            // setsid(), this preserves the caller's session and ctty.
            if unsafe { libc::setpgid(0, 0) } < 0 {
                child_fail(
                    err_w,
                    125,
                    &format!("setpgid: {}", std::io::Error::last_os_error()),
                );
            }
        }
    }

    match opts.stdio {
        StdioMode::Pty { slave_fd } => {
            // SAFETY: ioctl on the live pty slave.
            if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY as libc::c_ulong, 0i32) } != 0 {
                child_fail(
                    err_w,
                    124,
                    &format!("TIOCSCTTY: {}", std::io::Error::last_os_error()),
                );
            }
            for target in [0, 1, 2] {
                if let Err(error) = dup2_to(slave_fd, target) {
                    child_fail(err_w, 124, &error);
                }
            }
        }
        StdioMode::Captured { stdout_w, stderr_w } => {
            // SAFETY: open of a static NUL-terminated path.
            let devnull = unsafe { libc::open(b"/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };
            if devnull < 0 {
                child_fail(
                    err_w,
                    124,
                    &format!("open /dev/null: {}", std::io::Error::last_os_error()),
                );
            }
            if let Err(error) = dup2_to(devnull, 0) {
                child_fail(err_w, 124, &error);
            }
            if let Err(error) = dup2_to(stdout_w, 1) {
                child_fail(err_w, 124, &error);
            }
            if let Err(error) = dup2_to(stderr_w, 2) {
                child_fail(err_w, 124, &error);
            }
            // SAFETY: plain close on the temporary /dev/null descriptor.
            unsafe { libc::close(devnull) };
        }
        StdioMode::Inherit => {}
    }

    // Policy rlimits in the child, best-effort on macOS: the kernel refuses
    // several ceilings (RLIMIT_AS, raising the NPROC hard ceiling) per host
    // configuration, and failing every session over that would make the
    // default profile unusable. Enforced values still cannot be raised back
    // by the agent after exec; refusals are surfaced, not hidden.
    child_trace("limits-about-to-apply");
    // Diagnostic kill-switch: isolates the setrlimit calls when bisecting.
    if std::env::var_os("VETTO_NO_MAC_LIMITS").is_some() {
        child_trace("limits-skipped-by-env");
    } else {
        for refused in limits::apply_before_exec(&policy.limits) {
            eprintln!("vetto: {refused}");
        }
    }
    child_trace("limits-done");

    if let Err(e) = std::env::set_current_dir(&opts.cwd) {
        let _ = e;
        // SAFETY: immediate exit; nothing else to report through.
        unsafe { libc::_exit(117) };
    }
    child_trace("cwd-set");

    // Apply native Seatbelt sandbox via dynamic C API in memory.
    // VETTO_SEATBELT_MODE is a diagnostic bisect switch (SIGABRT hunt):
    //   none           — do not sandbox at all (CI-only; never a fallback)
    //   allow-all      — "(allow default)" profile
    //   deny-net-only  — everything allowed except the network
    //   wb-tcpudp      — deny TCP/UDP outbound only (no blanket network*)
    //   wb-mach        — blanket deny network* + mach-lookup/system-socket
    //   wb-socket      — blanket deny network* + system-socket allowed
    match std::env::var_os("VETTO_SEATBELT_MODE")
        .as_deref()
        .and_then(|m| m.to_str())
    {
        Some("none") => {
            child_trace("seatbelt-skipped-by-env");
        }
        Some(mode @ ("allow-all" | "deny-net-only")) => {
            let profile = if mode == "allow-all" {
                "(version 1)\n(allow default)\n"
            } else {
                "(version 1)\n(deny network*)\n"
            };
            child_trace(&format!("seatbelt-diagnostic-mode: {mode}"));
            if let Err(err) = seatbelt::apply_seatbelt_raw(profile, &[]) {
                child_fail(err_w, 120, &format!("apply seatbelt ({mode}): {err}"));
            }
        }
        Some(mode @ ("wb-tcpudp" | "wb-mach" | "wb-socket")) => {
            let profile = match mode {
                "wb-tcpudp" => "(version 1)\n(deny network-outbound (remote tcp-port *))\n(deny network-outbound (remote udp-port *))\n",
                "wb-mach" => "(version 1)\n(deny network*)\n(allow mach-lookup)\n(allow system-socket)\n",
                _ => "(version 1)\n(deny network*)\n(allow system-socket)\n",
            };
            child_trace(&format!("seatbelt-diagnostic-mode: {mode}"));
            if let Err(err) = seatbelt::apply_seatbelt_raw(profile, &[]) {
                child_fail(err_w, 120, &format!("apply seatbelt ({mode}): {err}"));
            }
        }
        _ => {
            if let Err(err) = seatbelt::apply_seatbelt(policy, net) {
                child_fail(err_w, 120, &format!("apply seatbelt: {err}"));
            }
        }
    }
    child_trace("seatbelt-applied");
    if std::env::var_os("VETTO_CHILD_TRACE").is_some() {
        eprintln!(
            "vetto: child seatbelt profile:
{}",
            seatbelt::generate(policy, net)
        );
    }

    child_trace("ready-about-to-send");
    // Tell the parent we are ready, then execve agent binary directly.
    // SAFETY: raw write of one byte.
    let _ = unsafe { libc::write(err_w, b"R".as_ptr().cast(), 1) };
    child_trace("ready-sent");
    close_all_except(&[0, 1, 2]);

    let prog = match agent.first() {
        Some(p) => p.clone(),
        None => unsafe { libc::_exit(127) },
    };
    let mut argv: Vec<*const libc::c_char> = agent.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: execve with NUL-terminated vectors built above.
    unsafe { libc::execve(prog.as_ptr(), argv.as_ptr(), envp.as_ptr()) };
    child_trace("execve-returned");
    // SAFETY: execve failed; surface errno for post-mortem, then exit.
    let errno = std::io::Error::last_os_error();
    child_trace(&format!("execve-errno: {errno}"));
    unsafe { libc::_exit(127) }
}

fn build_envp(policy: &Policy, opts: &SpawnOptions) -> Vec<CString> {
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os()
            .filter(|(key, _)| policy.environment.allows(key))
            .collect();
    for (k, v) in &opts.env_extra {
        env.insert(
            std::ffi::OsString::from(k.as_str()),
            std::ffi::OsString::from(v.as_str()),
        );
    }
    env.iter()
        .map(|(k, v)| {
            let mut entry = k.as_encoded_bytes().to_vec();
            entry.push(b'=');
            entry.extend_from_slice(v.as_encoded_bytes());
            CString::new(entry).unwrap_or_default()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seatbelt_available_does_not_panic() {
        let _ = MacosSandbox::seatbelt_available();
    }
}
