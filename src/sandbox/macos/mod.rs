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
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Duration;

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
        let profile_file = SeatbeltProfile::create(&profile)?;
        let sb_path = profile_file.path.clone();

        let (err_r, err_w) = pipe2()?;
        let err_w_raw = err_w.as_raw_fd();

        let sb_c = CString::new(sb_path.to_string_lossy().as_bytes())
            .with_context(|| format!("encode {}", sb_path.display()))?;
        let agent_c: Vec<CString> = opts
            .agent_cmd
            .iter()
            .map(|s| CString::new(s.as_str()).unwrap_or_default())
            .collect();
        let env_c = build_envp(policy, &opts);
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

        // Keep the profile until sandbox-exec has exited. The cleanup watcher
        // only observes process existence; it does not reap the child, so the
        // normal SandboxHandle wait remains the sole owner of the wait status.
        if let Err(error) = spawn_profile_cleanup(pid, profile_file) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
            let _ = reap(pid);
            return Err(error);
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

/// A private, one-shot Seatbelt profile. The final path is created with
/// `O_CREAT|O_EXCL|O_NOFOLLOW` and mode 0600, then removed after the sandbox
/// process exits. A random suffix prevents an attacker from predicting the
/// target before the create operation.
struct SeatbeltProfile {
    path: PathBuf,
    file: Option<File>,
}

impl SeatbeltProfile {
    fn create(contents: &str) -> Result<Self> {
        let directory = std::env::temp_dir();
        for _ in 0..128 {
            let path = directory.join(format!("vetto-seatbelt-{}.sb", random_suffix()));
            let mut file = match open_profile_file(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("create Seatbelt profile {}", path.display()))
                }
            };
            if let Err(error) = file.write_all(contents.as_bytes()) {
                let _ = std::fs::remove_file(&path);
                return Err(error).with_context(|| format!("write {}", path.display()));
            }
            if let Err(error) = file.sync_all() {
                let _ = std::fs::remove_file(&path);
                return Err(error).with_context(|| format!("sync {}", path.display()));
            }
            return Ok(Self {
                path,
                file: Some(file),
            });
        }
        bail!("could not allocate a unique Seatbelt profile name")
    }
}

impl Drop for SeatbeltProfile {
    fn drop(&mut self) {
        // Close before unlinking so a failed write cannot leave a live handle
        // around. Ignore cleanup errors: the sandbox is already terminating,
        // and there is no safe recovery path at this point.
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}

fn open_profile_file(path: &std::path::Path) -> std::io::Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: arc4random_buf fills exactly the provided writable buffer and
    // has no fallible path or shared state to initialize in this process.
    unsafe { libc::arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

fn spawn_profile_cleanup(pid: libc::pid_t, profile: SeatbeltProfile) -> Result<()> {
    std::thread::Builder::new()
        .name("vetto-seatbelt-cleanup".to_string())
        .spawn(move || wait_for_exit_and_cleanup(pid, profile))
        .map(|_| ())
        .map_err(|error| anyhow!("start Seatbelt profile cleanup: {error}"))
}

fn wait_for_exit_and_cleanup(pid: libc::pid_t, profile: SeatbeltProfile) {
    loop {
        // The parent still owns the wait status; kill(pid, 0) only observes
        // whether the process (including a not-yet-reaped zombie) exists.
        let result = unsafe { libc::kill(pid, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(profile);
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
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_dir() -> PathBuf {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("vetto-seatbelt-test-{}-{n}", std::process::id()));
        std::fs::create_dir(&path).expect("create test directory");
        path
    }

    #[test]
    fn profile_name_is_random_and_drop_cleans_the_file() {
        let profile =
            SeatbeltProfile::create("(version 1)\n(deny default)\n").expect("create profile");
        let path = profile.path.clone();
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("vetto-seatbelt-"));
        assert_ne!(name, format!("vetto-{}.sb", std::process::id()));
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(profile);
        assert!(!path.exists(), "profile must be removed on cleanup");
    }

    #[test]
    fn profile_creation_refuses_a_final_symlink() {
        let dir = test_dir();
        let victim = dir.join("victim");
        let target = dir.join("profile.sb");
        std::fs::write(&victim, b"sentinel\n").expect("write victim");
        symlink(&victim, &target).expect("create symlink");

        assert!(open_profile_file(&target).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"sentinel\n");
        std::fs::remove_dir_all(dir).expect("remove test directory");
    }
}
