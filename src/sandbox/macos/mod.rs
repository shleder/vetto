//! macOS backend: Seatbelt via `sandbox-exec`.
//!
//! HONEST LIMITS (also in SECURITY.md):
//! - `sandbox-exec` is deprecated and undocumented by Apple. It works today;
//!   platform risk accepted for v0.1.
//! - Seatbelt denials are invisible to FSEvents (same enforcement-vs-
//!   visibility gap as Linux); macOS visibility is inherently delayed.
//! - No PDEATHSIG on macOS: v0.1 kills the agent process group only when
//!   vetto exits normally. A SIGKILLed vetto may leave orphans (roadmap:
//!   kqueue EVFILT_PROC watchdog).
//! - `--net=allowlist` is Linux-only in v0.1.

pub mod endpoint_security;
pub mod fsevents;
pub mod seatbelt;

use std::ffi::CString;
use std::os::fd::{AsRawFd, RawFd};
use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};

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

    /// True when the seatbelt runner is present.
    pub fn seatbelt_available() -> bool {
        std::path::Path::new("/usr/bin/sandbox-exec").exists()
    }

    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> Result<Spawned> {
        if !Self::seatbelt_available() {
            bail!("sandbox-exec not found; refusing to run unsandboxed (fail-closed)");
        }
        if matches!(self.net, NetMode::Allowlist(_)) {
            bail!("--net=allowlist is Linux-only in v0.1");
        }

        let profile = seatbelt::generate(policy, &self.net);
        let sb_path: PathBuf = std::env::temp_dir().join(format!("vetto-{}.sb", std::process::id()));
        std::fs::write(&sb_path, &profile)
            .with_context(|| format!("write {}", sb_path.display()))?;

        let (err_r, err_w) = pipe2()?;
        let err_w_raw = err_w.as_raw_fd();

        let sb_c = CString::new(sb_path.to_string_lossy().as_bytes()).unwrap_or_default();
        let agent_c: Vec<CString> = opts
            .agent_cmd
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();
        let env_c = build_envp(&opts);
        let opts_ref = &opts;

        // SAFETY: fork before any worker threads exist (same iron rule as Linux).
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            bail!("fork: {}", std::io::Error::last_os_error());
        }
        if pid == 0 {
            child(sb_c, agent_c, env_c, err_w_raw, opts_ref);
        }
        drop(err_w);

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
                strategy: Some(KillStrategy::ProcessGroup { pid, pgid: pid }),
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
    if unsafe { libc::WIFEXITED(status) } {
        unsafe { libc::WEXITSTATUS(status) }
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
    Ok((
        unsafe { OwnedFd::from_raw_fd(fds[0]) },
        unsafe { OwnedFd::from_raw_fd(fds[1]) },
    ))
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

fn dup2_to(fd: RawFd, target: RawFd) {
    // SAFETY: dup2 onto a stdio slot.
    unsafe { libc::dup2(fd, target) };
}

fn child(
    sb: CString,
    agent: Vec<CString>,
    env: Vec<CString>,
    err_w: RawFd,
    opts: &SpawnOptions,
) -> ! {
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

    // Own session => own process group (kill target) + ctty possible.
    // SAFETY: scalar-only setsid.
    unsafe { libc::setsid() };

    match opts.stdio {
        StdioMode::Pty { slave_fd } => {
            // SAFETY: ioctl on the live pty slave.
            unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0i32) };
            dup2_to(slave_fd, 0);
            dup2_to(slave_fd, 1);
            dup2_to(slave_fd, 2);
        }
        StdioMode::Captured { stdout_w, stderr_w } => {
            // SAFETY: open of a static NUL-terminated path.
            let devnull = unsafe { libc::open(b"/dev/null\0".as_ptr().cast(), libc::O_RDONLY) };
            if devnull >= 0 {
                dup2_to(devnull, 0);
            }
            dup2_to(stdout_w, 1);
            dup2_to(stderr_w, 2);
        }
        StdioMode::Inherit => {}
    }
    if let Err(e) = std::env::set_current_dir(&opts.cwd) {
        let _ = e;
        // SAFETY: immediate exit; nothing else to report through.
        unsafe { libc::_exit(117) };
    }

    // Tell the parent we are ready, then hand off to sandbox-exec.
    // SAFETY: raw write of one byte.
    let _ = unsafe { libc::write(err_w, b"R".as_ptr().cast(), 1) };
    close_all_except(&[0, 1, 2]);

    let mut argv: Vec<*const libc::c_char> = vec![
        b"/usr/bin/sandbox-exec\0".as_ptr().cast(),
        b"-f\0".as_ptr().cast(),
        sb.as_ptr(),
        b"--\0".as_ptr().cast(),
    ];
    argv.extend(agent.iter().map(|a| a.as_ptr()));
    argv.push(std::ptr::null());
    let mut envp: Vec<*const libc::c_char> = env.iter().map(|e| e.as_ptr()).collect();
    envp.push(std::ptr::null());

    // SAFETY: execve with NUL-terminated vectors built above.
    unsafe {
        libc::execve(
            b"/usr/bin/sandbox-exec\0".as_ptr().cast(),
            argv.as_ptr(),
            envp.as_ptr(),
        )
    };
    // SAFETY: execve failed; nothing more to say.
    unsafe { libc::_exit(127) }
}

fn build_envp(opts: &SpawnOptions) -> Vec<CString> {
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os().collect();
    for (k, v) in &opts.env_extra {
        let key: std::ffi::OsString = k.as_ref().into();
        let val: std::ffi::OsString = v.as_ref().into();
        env.insert(key, val);
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
