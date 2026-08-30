//! Tier selection + the sandbox fork chains (Tier FULL and Tier FS-ONLY).
//!
//! IRON RULE: `spawn()` (and every `probe_*` it calls) must run in a
//! single-threaded process — before any tokio runtime or worker thread is
//! created. Forking a multi-threaded process risks deadlocks on malloc locks.
//! The children below may allocate freely (they are single-threaded at fork
//! time) but must never spawn threads (except the dedicated relay process R,
//! which re-images itself into a fresh single-threaded process first).
//!
//! Child exit-code registry (parent reports these honestly):
//!   111  generic child failure
//!   113  parent already dead (PDEATHSIG race check)
//!   114  unshare(CLONE_NEWUSER) failed
//!   115  unshare(MOUNT/IPC/NET/PID) or root-private failed
//!   116  fork of the relay process R failed
//!   117  chdir(project) failed
//!   118  fork of the agent failed (reported by B)
//!   119  uid/gid map handshake failed
//!   120  landlock::apply_policy failed
//!   121  secret mount-overlay failed
//!   122  fork of the inner supervisor B failed
//!   123  seccomp network block failed (FS-ONLY)
//!   124  stdio (pty/pipe) setup failed
//!   125  session/pgroup setup failed
//!   126  seccomp hardening failed (FULL)
//!   127  execve of the agent failed
//!   97/98  relay: loopback bring-up / bind failed

pub mod audit_reader;
pub mod debug_guard;
pub mod landlock;
pub mod limits;
pub mod mounts;
pub mod namespaces;
pub mod net_relay;
pub mod observe_seccomp;
pub mod proctrack;
pub mod seccomp_netblock;
pub mod visibility;

use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use anyhow::{anyhow, bail, Result};

use super::handle::{KillStrategy, SandboxHandle, SpawnOptions, StdioMode};
use super::Spawned;
use crate::config::NetMode;
use crate::policy::{Policy, Tier};

const SETUP_TIMEOUT_MS: i32 = 30_000;

// ---------------------------------------------------------------------------
// Probe + tier selection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Probe {
    pub kernel: String,
    pub landlock_abi: Option<u32>,
    pub userns_available: bool,
    /// The complete FULL setup path, including private procfs, succeeded.
    pub full_tier_available: bool,
    pub seccomp_filter_available: bool,
    pub seccomp_notify_available: bool,
    pub audit_feed_readable: bool,
}

/// Collect platform capabilities. Forks probe children — single-threaded
/// callers only.
pub fn probe() -> Probe {
    let kernel = kernel_release();
    let userns_available = namespaces::probe_unprivileged_userns();
    Probe {
        kernel,
        landlock_abi: landlock::abi_version(),
        userns_available,
        full_tier_available: userns_available && namespaces::probe_full_tier(),
        seccomp_filter_available: seccomp_netblock::probe_available(),
        seccomp_notify_available: observe_seccomp::probe_available(),
        audit_feed_readable: audit_reader::open_audit_feed().is_ok(),
    }
}

fn kernel_release() -> String {
    // SAFETY: utsname out-pointer is properly sized by the libc binding.
    let mut uts = std::mem::MaybeUninit::<libc::utsname>::uninit();
    if unsafe { libc::uname(uts.as_mut_ptr()) } != 0 {
        return "unknown".into();
    }
    // SAFETY: uname initialized the struct.
    let u = unsafe { uts.assume_init() };
    let bytes: Vec<u8> = u
        .release
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).to_string()
}

/// Fail-closed tier selection. `Err` means: the agent does NOT run.
///
/// `VETTO_FORCE_TIER=full|fs-only` (testing override) can only select a tier
/// whose primitives are actually available — it can never bypass fail-closed.
pub fn pick_tier(probe: &Probe) -> Result<Tier> {
    match std::env::var("VETTO_FORCE_TIER").as_deref() {
        Ok("fs-only") if probe.seccomp_filter_available => return Ok(Tier::FsOnly),
        Ok("full") if probe.full_tier_available => return Ok(Tier::Full),
        _ => {}
    }
    if probe.landlock_abi.is_none() {
        bail!(
            "Landlock is unavailable on this kernel (needs >= 5.13 with landlock enabled); \
             refusing to run the agent unsandboxed (fail-closed)"
        );
    }
    if probe.full_tier_available {
        return Ok(Tier::Full);
    }
    if probe.seccomp_filter_available {
        return Ok(Tier::FsOnly);
    }
    bail!(
        "no enforcement tier possible: unprivileged user namespaces are disabled AND \
         seccomp filters are unavailable; refusing to run unsandboxed (fail-closed)"
    );
}

pub struct LinuxSandbox {
    pub probe: Probe,
    pub tier: Tier,
    pub net: NetMode,
    pub observe_seccomp: bool,
}

impl LinuxSandbox {
    /// Build the sandbox and fork the agent into it. Single-threaded callers
    /// only (see module docs). The caller owns the stdio fds passed via
    /// `opts.stdio` and must close its own duplicates after this returns.
    pub fn spawn(self, policy: &Policy, opts: SpawnOptions) -> Result<Spawned> {
        if self.tier == Tier::FsOnly && self.net.uses_relay() {
            bail!(
                "--net relay modes require Tier FULL (unprivileged user namespaces), \
                 which is unavailable on this machine; refusing to run (fail-closed)"
            );
        }
        let relay_port = match self.net {
            NetMode::Allowlist(_) | NetMode::Strict(_) => Some(net_relay::RELAY_PORT_BASE),
            NetMode::Off => None,
        };
        match self.tier {
            Tier::Full => spawn_full(policy, opts, self.observe_seccomp, relay_port),
            Tier::FsOnly => spawn_fs_only(policy, opts, self.observe_seccomp),
        }
    }
}

// ---------------------------------------------------------------------------
// fd plumbing helpers
// ---------------------------------------------------------------------------

fn errno_val() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn pipe2_cloexec() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; flags are scalar.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        bail!("pipe2: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from a successful pipe2.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

fn socketpair_cloexec() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: valid out-array; flags are scalar.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    } != 0
    {
        bail!("socketpair: {}", std::io::Error::last_os_error());
    }
    // SAFETY: fresh descriptors from a successful socketpair.
    Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
        OwnedFd::from_raw_fd(fds[1])
    }))
}

/// close_range(2) — available on every kernel that also has Landlock (5.9+).
fn close_range(first: u32, last: u32) {
    if first > last {
        return;
    }
    const SYS_CLOSE_RANGE: libc::c_long = 436;
    // SAFETY: scalar-only syscall.
    unsafe { libc::syscall(SYS_CLOSE_RANGE, first, last, 0u32) };
}

/// Close every descriptor >= 3 except the listed ones. Child-side helper.
fn close_all_except(keep: &[RawFd]) {
    let mut keep: Vec<u32> = keep.iter().map(|&f| f as u32).collect();
    keep.sort_unstable();
    keep.dedup();
    let mut cur = 3u32;
    for &fd in &keep {
        if fd > cur {
            close_range(cur, fd - 1);
        }
        cur = fd + 1;
    }
    close_range(cur, u32::MAX);
}

fn child_write_all(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: raw write on a live descriptor; EINTR retried.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
        } else if n < 0 && errno_val() == libc::EINTR {
            continue;
        } else {
            return;
        }
    }
}

/// Report a setup failure to the parent over the err pipe and die.
fn child_fail(err_w: RawFd, code: i32, msg: &str) -> ! {
    let mut m = String::with_capacity(msg.len() + 4);
    m.push('E');
    m.push(':');
    m.push_str(msg);
    m.push('\n');
    child_write_all(err_w, m.as_bytes());
    // SAFETY: immediate child exit; no cleanup is possible or needed.
    unsafe { libc::_exit(code) }
}

fn child_exit(code: i32) -> ! {
    // SAFETY: immediate child exit.
    unsafe { libc::_exit(code) }
}

/// PDEATHSIG + the classic fork race check: if the parent died between fork
/// and prctl, we are already orphaned and must not continue.
fn child_pdeathsig(parent_pid: libc::pid_t) {
    // SAFETY: scalar-only prctl.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        child_exit(113);
    }
    // SAFETY: scalar getpid/getppid.
    if unsafe { libc::getppid() } != parent_pid {
        child_exit(113);
    }
}

/// Permanently remove the user-namespace root capability set before exec.
/// Mount setup is complete by the time this runs, so the agent never needs
/// CAP_SYS_ADMIN, CAP_DAC_OVERRIDE, CAP_SYS_PTRACE, or any other capability.
fn drop_agent_capabilities() -> Result<(), String> {
    // Disable the special uid-0 capability regain rules across execve and
    // lock that choice before clearing the current sets.
    const SECURE_NOROOT_AND_NO_SETUID_FIXUP_LOCKED: libc::c_ulong = 0x0f;
    if unsafe {
        libc::prctl(
            libc::PR_SET_SECUREBITS,
            SECURE_NOROOT_AND_NO_SETUID_FIXUP_LOCKED,
            0,
            0,
            0,
        )
    } != 0
    {
        return Err(format!(
            "lock securebits: {}",
            std::io::Error::last_os_error()
        ));
    }

    // Remove every known/possible capability from the bounding set while
    // CAP_SETPCAP is still effective. EINVAL simply means the kernel has a
    // smaller capability table.
    for capability in 0..64 {
        let result = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) };
        if result != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
            return Err(format!(
                "drop capability {capability} from bounding set: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    // Clear ambient capabilities (the operation is harmless when none exist).
    const PR_CAP_AMBIENT_CLEAR_ALL: libc::c_ulong = 4;
    if unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0) } != 0 {
        return Err(format!(
            "clear ambient capabilities: {}",
            std::io::Error::last_os_error()
        ));
    }

    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let data = [
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
        CapData {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        },
    ];
    if unsafe {
        libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "clear capability sets: {}",
            std::io::Error::last_os_error()
        ));
    }
    // capset/securebits transitions may clear dumpability. Re-enable it so
    // the ancestor vetto process can read syscall arguments for the optional
    // seccomp user-notify observer. Outgoing ptrace/process_vm/pidfd_getfd
    // syscalls remain blocked by the agent's own seccomp filter.
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) } != 0 {
        return Err(format!(
            "restore parent observability: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

fn decode_status(status: i32) -> i32 {
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        -libc::WTERMSIG(status)
    } else {
        -1
    }
}

fn exit_byte(code: i32) -> i32 {
    if code < 0 {
        128 - code // signal death -> conventional 128+n
    } else {
        code
    }
}

// ---------------------------------------------------------------------------
// Parent-side read helpers (with timeout, so a stuck child cannot hang vetto)
// ---------------------------------------------------------------------------

enum ByteRead {
    Byte(u8),
    Eof,
    Timeout,
}

fn read_byte(fd: RawFd, timeout_ms: i32) -> ByteRead {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    loop {
        let now = std::time::Instant::now();
        if now >= deadline {
            return ByteRead::Timeout;
        }
        let remain = (deadline - now).as_millis() as i32 + 1;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one valid descriptor.
        let pr = unsafe { libc::poll(&mut pfd, 1, remain) };
        if pr <= 0 {
            if pr < 0 && errno_val() == libc::EINTR {
                continue;
            }
            if std::time::Instant::now() >= deadline {
                return ByteRead::Timeout;
            }
            continue;
        }
        let mut b = [0u8; 1];
        // SAFETY: raw read on a readable descriptor.
        let n = unsafe { libc::read(fd, b.as_mut_ptr().cast(), 1) };
        return if n == 1 {
            ByteRead::Byte(b[0])
        } else if n == 0 {
            ByteRead::Eof
        } else if errno_val() == libc::EINTR {
            continue;
        } else {
            ByteRead::Eof
        };
    }
}

fn read_exact_timeout(fd: RawFd, buf: &mut [u8], timeout_ms: i32) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms as u64);
    let mut filled = 0usize;
    while filled < buf.len() {
        let now = std::time::Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "read timeout",
            ));
        }
        let remain = (deadline - now).as_millis() as i32 + 1;
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one valid descriptor.
        if unsafe { libc::poll(&mut pfd, 1, remain) } <= 0 {
            continue;
        }
        // SAFETY: raw read into the unfilled tail of the buffer.
        let n = unsafe { libc::read(fd, buf[filled..].as_mut_ptr().cast(), buf.len() - filled) };
        if n > 0 {
            filled += n as usize;
        } else if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof",
            ));
        } else if errno_val() != libc::EINTR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Drain the err pipe to EOF after an 'E' byte (the child is dying, EOF is
/// imminent). Best-effort with a short timeout.
fn drain_err_reason(err_r: RawFd) -> String {
    let mut out = Vec::new();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: err_r,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one valid descriptor.
        if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
            break;
        }
        let mut chunk = [0u8; 512];
        // SAFETY: raw read into a local buffer.
        let n = unsafe { libc::read(err_r, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n <= 0 {
            break;
        }
        out.extend_from_slice(&chunk[..n as usize]);
        if out.len() > 8192 {
            break;
        }
    }
    String::from_utf8_lossy(&out).trim().to_string()
}

fn reap_child(pid: libc::pid_t) -> i32 {
    loop {
        let mut status = 0i32;
        // SAFETY: plain waitpid on our child.
        let r = unsafe { libc::waitpid(pid, &mut status, 0) };
        if r == pid {
            return decode_status(status);
        }
        if r < 0 && errno_val() != libc::EINTR {
            return -1;
        }
    }
}

fn kill_and_reap(pid: libc::pid_t) -> i32 {
    // SAFETY: scalar-only kill.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    reap_child(pid)
}

/// Parse the setup result from the err pipe once the child has died or
/// signalled failure.
fn err_from_dead_child(pid: libc::pid_t, err_r: RawFd) -> anyhow::Error {
    let reason = drain_err_reason(err_r);
    let code = reap_child(pid);
    if reason.is_empty() {
        anyhow!("sandbox child died during setup (exit {code})")
    } else {
        anyhow!(
            "sandbox setup failed (child exit {code}): {}",
            reason.trim_start_matches("E:")
        )
    }
}

// ---------------------------------------------------------------------------
// Shared child pieces
// ---------------------------------------------------------------------------

/// Route the agent's stdio according to the mode. PTY callers perform
/// setsid()/session setup beforehand; captured and inherited modes do not
/// alter the caller's session.
fn child_stdio_setup(stdio: &StdioMode) -> Result<(), String> {
    match *stdio {
        StdioMode::Pty { slave_fd } => {
            // Make the pty slave our controlling terminal (session leader
            // required — the caller did setsid()).
            // SAFETY: ioctl on a live pty slave descriptor.
            if unsafe { libc::ioctl(slave_fd, libc::TIOCSCTTY, 0i32) } != 0 {
                return Err(format!("TIOCSCTTY: {}", errno_val()));
            }
            dup2_all(slave_fd)
        }
        StdioMode::Captured { stdout_w, stderr_w } => {
            // SAFETY: open of a static NUL-terminated path.
            let devnull = unsafe {
                libc::open(
                    b"/dev/null\0".as_ptr().cast(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                )
            };
            if devnull < 0 {
                return Err(format!("open /dev/null: {}", errno_val()));
            }
            dup2_all(devnull)?;
            dup2_to(stdout_w, 1)?;
            dup2_to(stderr_w, 2)?;
            // SAFETY: plain close on our temporary descriptor.
            unsafe { libc::close(devnull) };
            Ok(())
        }
        StdioMode::Inherit => Ok(()),
    }
}

fn dup2_to(fd: RawFd, target: RawFd) -> Result<(), String> {
    loop {
        // SAFETY: dup2 onto a stdio slot; EINTR retried.
        if unsafe { libc::dup2(fd, target) } >= 0 {
            return Ok(());
        }
        if errno_val() != libc::EINTR {
            return Err(format!(
                "dup2({fd}, {target}): {}",
                std::io::Error::last_os_error()
            ));
        }
    }
}

fn dup2_all(fd: RawFd) -> Result<(), String> {
    dup2_to(fd, 0)?;
    dup2_to(fd, 1)?;
    dup2_to(fd, 2)
}

/// Keep the agent's stdio descriptors alive across the supervisor fork.
fn append_stdio_fds(keep: &mut Vec<RawFd>, stdio: StdioMode) {
    match stdio {
        StdioMode::Pty { slave_fd } => keep.push(slave_fd),
        StdioMode::Captured { stdout_w, stderr_w } => {
            keep.push(stdout_w);
            keep.push(stderr_w);
        }
        StdioMode::Inherit => {}
    }
}

/// Close the supervisor's copies after C has inherited the descriptors.
fn close_stdio_fds(stdio: StdioMode) {
    let mut fds = [None, None];
    match stdio {
        StdioMode::Pty { slave_fd } => fds[0] = Some(slave_fd),
        StdioMode::Captured { stdout_w, stderr_w } => {
            fds[0] = Some(stdout_w);
            fds[1] = Some(stderr_w);
        }
        StdioMode::Inherit => {}
    }
    for fd in fds.into_iter().flatten().filter(|fd| *fd > 2) {
        // SAFETY: these are supervisor-owned inherited descriptors.
        unsafe { libc::close(fd) };
    }
}

/// execve the agent. Only returns on failure (exit 127).
fn child_exec(policy: &Policy, opts: &SpawnOptions) -> ! {
    let mut argv = Vec::with_capacity(opts.agent_cmd.len() + 1);
    for a in &opts.agent_cmd {
        match CString::new(a.as_str()) {
            Ok(c) => argv.push(c),
            Err(_) => child_exit(127),
        }
    }

    // Only explicitly allowed parent variables reach the agent. Internal
    // overrides (currently the network relay's proxy variables) are added
    // separately below; arbitrary parent credentials never reach execve.
    let mut env: std::collections::BTreeMap<std::ffi::OsString, std::ffi::OsString> =
        std::env::vars_os()
            .filter(|(key, _)| policy.environment.allows(key))
            .collect();
    crate::cred_broker::filter_proxy_secrets(&mut env, &policy.secret_proxies);
    for (k, v) in &opts.env_extra {
        env.insert(
            std::ffi::OsString::from(k.as_str()),
            std::ffi::OsString::from(v.as_str()),
        );
    }
    let mut envp = Vec::with_capacity(env.len());
    for (k, v) in &env {
        let mut entry = k.as_encoded_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(v.as_encoded_bytes());
        if let Ok(c) = CString::new(entry) {
            envp.push(c);
        }
    }

    let prog = match argv.first() {
        Some(p) => p.clone(),
        None => child_exit(127),
    };
    let mut argv_ptr: Vec<*const libc::c_char> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptr.push(std::ptr::null());
    let mut envp_ptr: Vec<*const libc::c_char> = envp.iter().map(|e| e.as_ptr()).collect();
    envp_ptr.push(std::ptr::null());

    if !opts.cwd.as_os_str().is_empty() {
        if let Err(e) = std::env::set_current_dir(&opts.cwd) {
            let _ = e;
            child_exit(117);
        }
    }

    // SAFETY: execve with NUL-terminated argv/envp vectors built above.
    if let Err(error) = limits::apply_before_exec(&policy.limits) {
        let message = format!("[vetto-child] resource limits failed: {error}\n");
        // SAFETY: raw write to stderr for diagnostics before dying.
        unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
        child_exit(126);
    }
    let r = unsafe { libc::execve(prog.as_ptr(), argv_ptr.as_ptr(), envp_ptr.as_ptr()) };
    let msg = format!(
        "[vetto-child] execve failed r={r} errno={}\n",
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    );
    // SAFETY: raw write to stderr for diagnostics before dying.
    unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
    child_exit(127)
}

/// Relay process R: lives in the netns (forked before the pidns unshare),
/// outside the landlock ruleset, outside the inner pidns.
fn child_relay(relay_end: RawFd, s_pid: libc::pid_t, port: u16) -> ! {
    child_pdeathsig(s_pid);
    close_all_except(&[relay_end]);
    // SAFETY: open of a static NUL-terminated path (fd will be dup2'd).
    let devnull = unsafe {
        libc::open(
            b"/dev/null\0".as_ptr().cast(),
            libc::O_RDWR | libc::O_CLOEXEC,
        )
    };
    if devnull < 0 || dup2_all(devnull).is_err() {
        // The relay has no setup error pipe; terminate rather than run with
        // inherited or partially redirected descriptors.
        child_exit(111);
    }
    // SAFETY: plain close on the temporary descriptor.
    unsafe { libc::close(devnull) };
    net_relay::serve_relay(relay_end, port)
}

/// Inner supervisor B: PID 1 of the sandbox pidns. Reaps zombies, watches the
/// alive pipe, and kills the whole namespace when the agent (or vetto) dies.
fn child_b(
    alive_r: RawFd,
    err_w: RawFd,
    notif_child: Option<RawFd>,
    observe: bool,
    policy: &Policy,
    opts: &SpawnOptions,
    socket_policy: seccomp_netblock::SocketPolicy,
) -> ! {
    // PDEATHSIG still works across the pid boundary; the getppid() identity
    // check is impossible here (our parent lives in an ancestor pidns and
    // getppid() returns 0), so the alive-pipe poll below covers that race.
    // SAFETY: scalar-only prctl.
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        child_exit(113);
    }
    match mounts::mount_restricted_proc() {
        Ok(mounts::ProcVisibility::HidePid) => {}
        Ok(mounts::ProcVisibility::Fallback) => {
            // Keep setup honest without claiming hidepid enforcement when a
            // kernel lacks it. The proc mount remains private to this PID ns.
            let message = b"[vetto-child] /proc hidepid unsupported; private proc fallback\n";
            // SAFETY: inherited stderr remains open until C is forked.
            unsafe { libc::write(2, message.as_ptr().cast(), message.len()) };
        }
        Err(error) => child_fail(err_w, 115, &format!("restricted /proc: {error}")),
    }
    // Install Landlock only after the private procfs is mounted. Mounting
    // `/proc` after applying a policy that intentionally omits the host proc
    // tree can fail with EACCES/EPERM even though the namespace stack itself
    // is available. B and every descendant inherit this ruleset, while the
    // relay (forked earlier and outside the PID namespace) remains outside it.
    if let Err(error) = landlock::apply_policy(&policy.allow_write, &policy.allow_read, false) {
        child_fail(err_w, 120, &format!("{error}"));
    }
    // B does not use the agent's stdio, but must keep the descriptors alive
    // until C has inherited them. Closing them before the fork makes PTY and
    // captured modes fail during C's stdio setup.
    // Keep inherited stdio for StdioMode::Inherit; C uses it unchanged.
    let mut keep = vec![0, 1, 2, alive_r, err_w];
    if let Some(fd) = notif_child {
        keep.push(fd);
    }
    append_stdio_fds(&mut keep, opts.stdio);
    close_all_except(&keep);
    // SAFETY: scalar getpid (returns 1 inside the fresh pidns).
    let b_pid = unsafe { libc::getpid() };

    // SAFETY: fork of the single-threaded supervisor.
    let c_pid = unsafe { libc::fork() };
    if c_pid < 0 {
        child_fail(err_w, 118, "fork agent failed");
    }
    if c_pid == 0 {
        // Agent process C.
        child_pdeathsig(b_pid);
        let mut keep = vec![0, 1, 2, err_w];
        if let Some(fd) = notif_child {
            keep.push(fd);
        }
        append_stdio_fds(&mut keep, opts.stdio);
        close_all_except(&keep);
        // Become a session leader only for PTY mode: TIOCSCTTY requires it.
        // Captured and inherited stdio must keep their caller's session.
        if matches!(opts.stdio, StdioMode::Pty { .. }) && unsafe { libc::setsid() } < 0 {
            child_fail(err_w, 125, "setsid failed");
        }
        if let Err(msg) = child_stdio_setup(&opts.stdio) {
            child_fail(err_w, 124, &format!("stdio: {msg}"));
        }
        if let Err(error) = drop_agent_capabilities() {
            child_fail(err_w, 126, &format!("drop capabilities: {error}"));
        }
        // Install user-notify only in the final agent process. Installing it
        // in S or B would trap their own Landlock path opens or fork and
        // deadlock setup before the parent owns the listener.
        if observe {
            if let Some(nc) = notif_child {
                let mut ok = false;
                if let Ok(listener) = observe_seccomp::install_tap() {
                    child_write_all(nc, b"T");
                    if net_relay::send_fd(nc, listener).is_ok() {
                        ok = true;
                    }
                    unsafe { libc::close(listener) };
                }
                if !ok {
                    child_write_all(nc, b"N");
                }
                unsafe { libc::close(nc) };
            }
        }
        // The actual NetMode selects the socket policy: FULL/off is
        // AF_UNIX-only, while FULL/allowlist additionally permits IPv4/IPv6
        // for the loopback proxy. Both variants retain syscall hardening.
        if let Err(e) = seccomp_netblock::install_for(socket_policy) {
            child_fail(err_w, 126, &format!("seccomp hardening: {e}"));
        }
        // Readiness belongs to C, not the outer namespace helper: by this
        // point private procfs, Landlock, stdio and seccomp are all active.
        // Reporting ready earlier can return a handle for a child that is
        // already failing its final sandbox setup.
        child_write_all(err_w, b"R");
        close_all_except(&[0, 1, 2]);
        child_exec(policy, opts)
    }

    if let Some(fd) = notif_child {
        unsafe { libc::close(fd) };
    }

    // B must not retain a PTY slave or captured pipe writers: those copies
    // would keep the outer stream open after C exits and hide EOF from vetto.
    close_stdio_fds(opts.stdio);

    // Supervisor loop.
    let mut c_code: i32 = 0;
    loop {
        // Reap whatever is done.
        loop {
            let mut status = 0i32;
            // SAFETY: waitpid on children of this pidns init.
            let r = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if r == c_pid {
                c_code = decode_status(status);
                // SAFETY: scalar-only kill; PID 1 in a pidns kills the ns.
                unsafe { libc::kill(-1, libc::SIGKILL) };
            } else if r > 0 {
                continue; // some other child reaped
            } else if r < 0 && errno_val() == libc::ECHILD {
                child_exit(exit_byte(c_code));
            } else {
                break; // nothing ready
            }
        }

        // Watch for parent death: EOF on the alive pipe.
        let mut pfd = libc::pollfd {
            fd: alive_r,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll on one valid descriptor.
        let pr = unsafe { libc::poll(&mut pfd, 1, 50) };
        if pr > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
            let mut b = [0u8; 1];
            // SAFETY: raw read to distinguish EOF (0) from spurious POLLIN.
            let n = unsafe { libc::read(alive_r, b.as_mut_ptr().cast(), 1) };
            if n == 0 {
                // vetto is gone: kill the namespace and follow.
                // SAFETY: scalar-only kill.
                unsafe { libc::kill(-1, libc::SIGKILL) };
                loop {
                    let mut status = 0i32;
                    // SAFETY: blocking reap of the whole namespace.
                    let r = unsafe { libc::waitpid(-1, &mut status, 0) };
                    if r < 0 {
                        break;
                    }
                }
                child_exit(exit_byte(c_code));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tier FULL chain
// ---------------------------------------------------------------------------

struct FullChildArgs<'a> {
    parent_pid: libc::pid_t,
    err_w: RawFd,
    map_w: RawFd,
    ack_r: RawFd,
    alive_r: RawFd,
    relay_end: Option<RawFd>,
    notif_child: Option<RawFd>,
    relay_port: Option<u16>,
    observe: bool,
    policy: &'a Policy,
    opts: &'a SpawnOptions,
}

/// Process S: enters the namespaces, masks secrets, applies Landlock, forks
/// the relay (R) and the inner supervisor (B). Never returns.
///
/// SAFETY: must only be called in a freshly forked single-threaded child.
unsafe fn child_full(a: FullChildArgs<'_>) -> ! {
    let FullChildArgs {
        parent_pid,
        err_w,
        map_w,
        ack_r,
        alive_r,
        relay_end,
        notif_child,
        relay_port,
        observe,
        policy,
        opts,
    } = a;

    // NOTE: the parent's alive_w copy must NOT survive this fork — the whole
    // orphan-kill design depends on the write end living ONLY in vetto.
    // Preserve inherited stdio for StdioMode::Inherit; the eventual agent C
    // uses these descriptors unchanged.
    let mut keep: Vec<RawFd> = vec![0, 1, 2, err_w, map_w, ack_r, alive_r];
    if let Some(fd) = relay_end {
        keep.push(fd);
    }
    if let Some(fd) = notif_child {
        keep.push(fd);
    }
    if let StdioMode::Pty { slave_fd } = opts.stdio {
        keep.push(slave_fd);
    }
    if let StdioMode::Captured { stdout_w, stderr_w } = opts.stdio {
        keep.push(stdout_w);
        keep.push(stderr_w);
    }
    close_all_except(&keep);

    child_pdeathsig(parent_pid);

    // User namespace + id-maps handshake with the real parent.
    if let Err(e) = namespaces::unshare(namespaces::CLONE_NEWUSER) {
        child_fail(err_w, 114, &format!("unshare user: {e}"));
    }
    // SAFETY: scalar getpid.
    let my_pid = unsafe { libc::getpid() };
    child_write_all(map_w, &my_pid.to_le_bytes());
    let mut ack = [0u8; 1];
    // SAFETY: raw blocking read of the single ack byte.
    let n = unsafe { libc::read(ack_r, ack.as_mut_ptr().cast(), 1) };
    if n != 1 || ack[0] != 0 {
        child_exit(119);
    }
    // SAFETY: plain closes on descriptors we are done with.
    unsafe {
        libc::close(map_w);
        libc::close(ack_r);
    }

    if let Err(e) = namespaces::unshare(namespaces::CLONE_NEWNS) {
        child_fail(err_w, 115, &format!("unshare mount: {e}"));
    }
    if let Err(e) = mounts::make_root_private() {
        child_fail(err_w, 115, &format!("make root private: {e}"));
    }
    if let Err(e) = mounts::isolate_dev_shm() {
        child_fail(err_w, 115, &format!("isolate /dev/shm: {e}"));
    }
    if policy.tmpfs_tmp {
        if let Err(e) = mounts::isolate_tmp() {
            child_fail(err_w, 115, &format!("isolate /tmp: {e}"));
        }
    }
    if let Err(e) = mounts::remount_sys_readonly() {
        child_fail(err_w, 115, &format!("remount /sys read-only: {e}"));
    }
    let _ = mounts::mask_sensitive_proc_paths();
    let _ = mounts::mount_ro_caches(&policy.ro_mounts);
    if let Err(e) = namespaces::unshare(namespaces::CLONE_NEWIPC) {
        child_fail(err_w, 115, &format!("unshare ipc: {e}"));
    }
    if let Err(e) = namespaces::unshare(namespaces::CLONE_NEWNET) {
        child_fail(err_w, 115, &format!("unshare net: {e}"));
    }

    if let Some(port) = relay_port {
        let relay_fd = relay_end.expect("relay fd wired for allowlist mode");
        if let Err(e) = mounts::blackhole_resolv_conf() {
            child_fail(err_w, 121, &format!("blackhole resolv.conf: {e}"));
        }
        // SAFETY: scalar getpid (still the outer pid here).
        let s_pid = unsafe { libc::getpid() };
        // SAFETY: fork of a single-threaded child.
        let r = unsafe { libc::fork() };
        if r < 0 {
            child_fail(err_w, 116, "fork relay failed");
        }
        if r == 0 {
            child_relay(relay_fd, s_pid, port);
        }
        // SAFETY: plain close; the relay owns the only other copy now.
        unsafe { libc::close(relay_fd) };
    }

    if let Err(e) = namespaces::unshare(namespaces::CLONE_NEWPID) {
        child_fail(err_w, 115, &format!("unshare pidns: {e}"));
    }

    // Secret overlays: the ONLY way to carve deny paths out of allowed trees.
    for entry in &policy.deny_resolved {
        match mounts::mask_path(&entry.path, entry.is_dir) {
            Ok(true) => {}
            Ok(false) => {} // path absent on this machine — nothing to mask
            Err(e) => child_fail(
                err_w,
                121,
                &format!("mask overlay {}: {e}", entry.path.display()),
            ),
        }
    }

    let socket_policy = match relay_port {
        Some(_) => seccomp_netblock::SocketPolicy::UnixAndIp,
        None => seccomp_netblock::SocketPolicy::UnixOnly,
    };

    // Inner supervisor B (PID 1 of the new pidns) forks the agent C.
    // SAFETY: fork of a single-threaded child.
    let b = unsafe { libc::fork() };
    if b < 0 {
        child_fail(err_w, 122, "fork supervisor failed");
    }
    if b == 0 {
        child_b(
            alive_r,
            err_w,
            notif_child,
            observe,
            policy,
            opts,
            socket_policy,
        );
    }

    // C reports readiness only after the complete sandbox stack is active.
    // S only ferries B's exit code.
    close_all_except(&[]);
    // SAFETY: blocking waitpid on B.
    let mut status = 0i32;
    let code = loop {
        // SAFETY: plain waitpid.
        let r = unsafe { libc::waitpid(b, &mut status, 0) };
        if r == b {
            break decode_status(status);
        }
        if r < 0 && errno_val() != libc::EINTR {
            break -1;
        }
    };
    child_exit(exit_byte(code))
}

fn spawn_full(
    policy: &Policy,
    opts: SpawnOptions,
    observe: bool,
    relay_port: Option<u16>,
) -> Result<Spawned> {
    // SAFETY: scalar getpid.
    let parent_pid = unsafe { libc::getpid() };

    let (err_r, err_w) = pipe2_cloexec()?;
    let (map_r, map_w) = pipe2_cloexec()?;
    let (ack_r, ack_w) = pipe2_cloexec()?;
    let (alive_r, alive_w) = pipe2_cloexec()?;
    let relay_pair = if relay_port.is_some() {
        Some(socketpair_cloexec()?)
    } else {
        None
    };
    let (broker_end, relay_end) = match relay_pair {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    let (notif_parent, notif_child) = if observe {
        let (a, b) = socketpair_cloexec()?;
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    let args = FullChildArgs {
        parent_pid,
        err_w: err_w.as_raw_fd(),
        map_w: map_w.as_raw_fd(),
        ack_r: ack_r.as_raw_fd(),
        alive_r: alive_r.as_raw_fd(),
        relay_end: relay_end.as_ref().map(|f| f.as_raw_fd()),
        notif_child: notif_child.as_ref().map(|f| f.as_raw_fd()),
        relay_port,
        observe,
        policy,
        opts: &opts,
    };

    // SAFETY: single-threaded fork — spawn() runs before any threads exist.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { child_full(args) }
    }

    // Parent: drop every child-side duplicate (alive_w stays HERE — dropping
    // it later is the Tier FULL kill switch).
    drop(err_w);
    drop(map_w);
    drop(ack_r);
    drop(alive_r);
    drop(relay_end);
    drop(notif_child);

    // 1. uid/gid map handshake.
    let mut pid_buf = [0u8; 4];
    if let Err(e) = read_exact_timeout(map_r.as_raw_fd(), &mut pid_buf, SETUP_TIMEOUT_MS) {
        let code = kill_and_reap(pid);
        let reason = drain_err_reason(err_r.as_raw_fd());
        return Err(anyhow!(
            "userns handshake failed ({e}, child exit {code}): {}",
            reason.trim_start_matches("E:")
        ));
    }
    let child_pid = u32::from_le_bytes(pid_buf) as libc::pid_t;
    let maps_ok = namespaces::write_id_maps(child_pid).is_ok();
    // SAFETY: raw write of one ack byte (0 ok / 1 fail).
    let ack: &[u8] = if maps_ok { &[0] } else { &[1] };
    let _ = unsafe { libc::write(ack_w.as_raw_fd(), ack.as_ptr().cast(), ack.len()) };
    if !maps_ok {
        let code = reap_child(pid);
        return Err(anyhow!(
            "writing uid_map/gid_map failed (child exit {code}); \
             unprivileged userns may be restricted here"
        ));
    }
    drop(map_r);
    drop(ack_w);

    // 2. Setup result: 'R' ready / 'E:<reason>' failure / EOF died.
    match read_byte(err_r.as_raw_fd(), SETUP_TIMEOUT_MS) {
        ByteRead::Byte(b'R') => {}
        ByteRead::Byte(b'E') | ByteRead::Eof => {
            return Err(err_from_dead_child(pid, err_r.as_raw_fd()));
        }
        ByteRead::Byte(other) => {
            let code = reap_child(pid);
            return Err(anyhow!(
                "unexpected setup byte {other:#x} from sandbox child (exit {code})"
            ));
        }
        ByteRead::Timeout => {
            let code = kill_and_reap(pid);
            return Err(anyhow!("sandbox setup timed out (child exit {code})"));
        }
    }

    // 3. Optional observation listener fd.
    let notif_listener = match notif_parent {
        Some(np) => match read_byte(np.as_raw_fd(), SETUP_TIMEOUT_MS) {
            ByteRead::Byte(b'T') => net_relay::recv_fd(np.as_raw_fd()).ok(),
            _ => None,
        },
        None => None,
    };

    Ok(Spawned {
        handle: SandboxHandle {
            root_pid: pid as u32,
            strategy: Some(KillStrategy::PidNsPipe(alive_w)),
        },
        broker_ctrl_fd: broker_end,
        relay_port,
        notif_listener,
    })
}

// ---------------------------------------------------------------------------
// Tier FS-ONLY chain (single fork)
// ---------------------------------------------------------------------------

struct FsChildArgs<'a> {
    parent_pid: libc::pid_t,
    err_w: RawFd,
    notif_child: Option<RawFd>,
    observe: bool,
    net_off: bool,
    policy: &'a Policy,
    opts: &'a SpawnOptions,
}

/// FS-ONLY: the child IS the agent. Landlock + seccomp netblock, no
/// namespaces.
///
/// setsid()-detached grandchildren escape `kill(-pgid)`. The gap is closed
/// best-effort, not by the kernel: before the fork vetto registers as a
/// child sub-reaper, so descendants that outlive the agent child — including
/// setsid escapers — are reparented to vetto, where teardown runs a bounded
/// sweep ([`proctrack::sweep_reparented`]) that reaps and SIGKILLs them.
/// Residual risk: escapers survive when the sub-reaper prctl failed, when
/// they sit in uninterruptible sleep past the sweep budget, or when a
/// reparenting cascade outlives it. The FULL tier kills in the kernel and
/// has no such window.
///
/// SAFETY: must only be called in a freshly forked single-threaded child.
unsafe fn child_fs_only(a: FsChildArgs<'_>) -> ! {
    let FsChildArgs {
        parent_pid,
        err_w,
        notif_child,
        observe,
        net_off,
        policy,
        opts,
    } = a;

    // Preserve inherited stdio for StdioMode::Inherit; child_exec must not
    // receive closed standard streams merely because FS-ONLY has one fork.
    let mut keep: Vec<RawFd> = vec![0, 1, 2, err_w];
    if let Some(fd) = notif_child {
        keep.push(fd);
    }
    if let StdioMode::Pty { slave_fd } = opts.stdio {
        keep.push(slave_fd);
    }
    if let StdioMode::Captured { stdout_w, stderr_w } = opts.stdio {
        keep.push(stdout_w);
        keep.push(stderr_w);
    }
    close_all_except(&keep);

    child_pdeathsig(parent_pid);

    // PTY mode needs a new session for TIOCSCTTY. Captured and inherited
    // modes preserve the caller's session, but still get a private process
    // group so kill(-pgid) never targets the caller's group.
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

    if net_off {
        if let Err(e) = seccomp_netblock::install() {
            child_fail(err_w, 123, &format!("network block: {e}"));
        }
    }

    // FS-ONLY has no mount ns: intra-project secrets were carved out by the
    // loader's tree enumeration; READ is stripped from write roots so the
    // whole-tree write rule cannot re-expose them (see landlock.rs).
    if let Err(e) = landlock::apply_policy(&policy.allow_write, &policy.allow_read, true) {
        child_fail(err_w, 120, &format!("{e}"));
    }

    if observe {
        if let Some(nc) = notif_child {
            let mut ok = false;
            if let Ok(listener) = observe_seccomp::install_tap() {
                child_write_all(nc, b"T");
                if net_relay::send_fd(nc, listener).is_ok() {
                    ok = true;
                }
                // SAFETY: plain close; the parent owns the listener now.
                unsafe { libc::close(listener) };
            }
            if !ok {
                child_write_all(nc, b"N");
            }
            // SAFETY: plain close on the spent socket end.
            unsafe { libc::close(nc) };
        }
    }

    if let Err(msg) = child_stdio_setup(&opts.stdio) {
        child_fail(err_w, 124, &format!("stdio: {msg}"));
    }
    if !opts.cwd.as_os_str().is_empty() {
        if let Err(e) = std::env::set_current_dir(&opts.cwd) {
            child_fail(err_w, 117, &format!("chdir {}: {e}", opts.cwd.display()));
        }
    }

    child_write_all(err_w, b"R");
    close_all_except(&[0, 1, 2]);
    child_exec(policy, opts)
}

fn spawn_fs_only(policy: &Policy, opts: SpawnOptions, observe: bool) -> Result<Spawned> {
    // SAFETY: scalar getpid.
    let parent_pid = unsafe { libc::getpid() };
    // allowlist was rejected in LinuxSandbox::spawn: FS-ONLY always netblocks.
    let net_off = true;

    // Close the setsid escape hatch (best-effort): as a child sub-reaper,
    // vetto adopts every descendant that outlives the agent child, so the
    // teardown sweep can reach escapers kill(-pgid) cannot. If the prctl
    // fails the historical gap remains; say so loudly instead of silently.
    if let Err(error) = crate::multi::isolation::set_subreaper() {
        tracing::warn!(
            "fs-only: PR_SET_CHILD_SUBREAPER failed ({error}); setsid-detached \
             grandchildren may survive teardown"
        );
    }

    let (err_r, err_w) = pipe2_cloexec()?;
    let (notif_parent, notif_child) = if observe {
        let (a, b) = socketpair_cloexec()?;
        (Some(a), Some(b))
    } else {
        (None, None)
    };

    let args = FsChildArgs {
        parent_pid,
        err_w: err_w.as_raw_fd(),
        notif_child: notif_child.as_ref().map(|f| f.as_raw_fd()),
        observe,
        net_off,
        policy,
        opts: &opts,
    };

    // SAFETY: single-threaded fork — spawn() runs before any threads exist.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        bail!("fork: {}", std::io::Error::last_os_error());
    }
    if pid == 0 {
        unsafe { child_fs_only(args) }
    }

    drop(err_w);
    drop(notif_child);

    match read_byte(err_r.as_raw_fd(), SETUP_TIMEOUT_MS) {
        ByteRead::Byte(b'R') => {}
        ByteRead::Byte(b'E') | ByteRead::Eof => {
            return Err(err_from_dead_child(pid, err_r.as_raw_fd()));
        }
        ByteRead::Byte(other) => {
            let code = reap_child(pid);
            return Err(anyhow!(
                "unexpected setup byte {other:#x} from sandbox child (exit {code})"
            ));
        }
        ByteRead::Timeout => {
            let code = kill_and_reap(pid);
            return Err(anyhow!("sandbox setup timed out (child exit {code})"));
        }
    }

    let notif_listener = match notif_parent {
        Some(np) => match read_byte(np.as_raw_fd(), SETUP_TIMEOUT_MS) {
            ByteRead::Byte(b'T') => net_relay::recv_fd(np.as_raw_fd()).ok(),
            _ => None,
        },
        None => None,
    };

    // Arm the process-exit safety net AFTER the last fork in this process:
    // supervise exits via std::process::exit (no Drop), so without this
    // handler a normally-exiting FS-ONLY session would never kill(-pgid) nor
    // sweep its reparented setsid escapers.
    proctrack::arm_exit_sweep(pid, pid);

    Ok(Spawned {
        handle: SandboxHandle {
            root_pid: pid as u32,
            strategy: Some(KillStrategy::ProcessGroup {
                pid,
                pgid: pid,
                sweep: true,
            }),
        },
        broker_ctrl_fd: None,
        relay_port: None,
        notif_listener,
    })
}
