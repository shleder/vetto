//! OPTIONAL blocked-attempt observability tap (`--observe-seccomp`).
//!
//! seccomp user-notify used PURELY for observation of filesystem, process,
//! and network attempts. The default listener answers every notification with
//! SECCOMP_USER_NOTIF_FLAG_CONTINUE so the kernel re-enters the syscall
//! normally and LANDLOCK REMAINS THE SOLE FILESYSTEM ENFORCER. This tap can
//! never enforce anything and never blocks the child from running: if setup
//! fails, vetto continues without a blocked-attempt feed. A separately named,
//! explicit ADDFD API exists only for exact `/dev/null` substitutions of a
//! documented non-critical system-file set and is disabled by default.
//!
//! Documented limits: reported paths are racy (TOCTOU in observation only);
//! path strings are read best-effort from /proc/<pid>/mem.

use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::{VettoError, VettoResult};
use crate::events::{bus::EventBus, Event};

// Keep syscall numbers architecture-aware. In particular, seccomp is 317 on
// x86_64 but 277 on aarch64; hard-coding the former disables observation on
// ARM while still looking superficially healthy.
const SYS_SECCOMP: libc::c_long = libc::SYS_seccomp;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000; // NOT 0x7ff00000 (= RET_TRACE!)
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

// ioctl numbers for seccomp notify (_IOWR('!', ...)).
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;
const SECCOMP_IOCTL_NOTIF_ADDFD: libc::c_ulong = 0x4018_2103;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
struct SockFProg {
    len: u16,
    filter: *const SockFilter,
}

#[repr(C)]
struct SeccompNotif {
    id: u64,
    pid: u32,
    flags: u32,
    data: SeccompData,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SeccompData {
    nr: i32,
    arch: u32,
    instruction_pointer: u64,
    args: [u64; 6],
}

#[repr(C)]
struct SeccompNotifResp {
    id: u64,
    val: i64,
    error: i32,
    flags: u32,
}

#[repr(C)]
struct SeccompNotifAddfd {
    id: u64,
    flags: u32,
    srcfd: u32,
    newfd: u32,
    newfd_flags: u32,
}

const BPF_LD_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET: u16 = 0x06;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
#[cfg(target_arch = "x86")]
const AUDIT_ARCH_I386: u32 = 0x4000_0003;
#[cfg(target_arch = "arm")]
const AUDIT_ARCH_ARM: u32 = 0x4000_0028;
#[cfg(target_arch = "riscv64")]
const AUDIT_ARCH_RISCV64: u32 = 0xC000_00F3;

fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
    #[cfg(target_arch = "x86")]
    {
        AUDIT_ARCH_I386
    }
    #[cfg(target_arch = "arm")]
    {
        AUDIT_ARCH_ARM
    }
    #[cfg(target_arch = "riscv64")]
    {
        AUDIT_ARCH_RISCV64
    }
    #[cfg(not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "x86",
        target_arch = "arm",
        target_arch = "riscv64"
    )))]
    {
        0
    }
}

// libc exposes the target ABI's syscall table; do not copy x86_64 numbers
// into this observability filter.
#[cfg(not(target_arch = "aarch64"))]
const NR_OPEN: i32 = libc::SYS_open as i32;
const NR_EXECVE: i32 = libc::SYS_execve as i32;
const NR_OPENAT: i32 = libc::SYS_openat as i32;
const NR_OPENAT2: i32 = libc::SYS_openat2 as i32;
const NR_EXECVEAT: i32 = libc::SYS_execveat as i32;
const NR_CONNECT: i32 = libc::SYS_connect as i32;
const NR_BIND: i32 = libc::SYS_bind as i32;
#[cfg(not(target_arch = "aarch64"))]
const NR_UNLINK: i32 = libc::SYS_unlink as i32;
const NR_UNLINKAT: i32 = libc::SYS_unlinkat as i32;
#[cfg(not(target_arch = "aarch64"))]
const NR_RENAME: i32 = libc::SYS_rename as i32;
const NR_RENAMEAT: i32 = libc::SYS_renameat as i32;
const NR_RENAMEAT2: i32 = libc::SYS_renameat2 as i32;
#[cfg(not(target_arch = "aarch64"))]
const NR_CHMOD: i32 = libc::SYS_chmod as i32;
const NR_FCHMODAT: i32 = libc::SYS_fchmodat as i32;
#[cfg(not(target_arch = "aarch64"))]
const NR_FORK: i32 = libc::SYS_fork as i32;
const NR_CLONE: i32 = libc::SYS_clone as i32;
const NR_CLONE3: i32 = libc::SYS_clone3 as i32;

/// Syscalls observed by the optional tap. The filter only returns
/// `USER_NOTIF`; it never turns these observations into enforcement.
const OBSERVED_SYSCALLS: &[i32] = &[
    #[cfg(not(target_arch = "aarch64"))]
    NR_OPEN,
    NR_OPENAT,
    NR_OPENAT2,
    NR_EXECVE,
    NR_EXECVEAT,
    NR_CONNECT,
    NR_BIND,
    #[cfg(not(target_arch = "aarch64"))]
    NR_UNLINK,
    NR_UNLINKAT,
    #[cfg(not(target_arch = "aarch64"))]
    NR_RENAME,
    NR_RENAMEAT,
    NR_RENAMEAT2,
    #[cfg(not(target_arch = "aarch64"))]
    NR_CHMOD,
    NR_FCHMODAT,
    #[cfg(not(target_arch = "aarch64"))]
    NR_FORK,
    NR_CLONE,
    NR_CLONE3,
];

/// Build the observation filter without installing it.
///
/// The returned instructions are safe to inspect or benchmark as data. The
/// kernel is not touched; installation remains explicit through
/// [`install_tap`].
pub fn build_tap_program() -> Vec<SockFilter> {
    // Trap the observed syscalls; everything else passes through untouched.
    // The true jump for each comparison points at the one shared
    // USER_NOTIF return at the end of the comparison chain.
    let mut program = vec![
        stmt(BPF_LD_ABS, 4),                        // 0: arch
        jump(BPF_JEQ_K, native_audit_arch(), 1, 0), // 1: native -> 3
        stmt(BPF_RET, SECCOMP_RET_KILL_PROCESS),    // 2: foreign ABI
        stmt(BPF_LD_ABS, 0),                        // 3: syscall number
    ];
    let first_comparison = program.len();
    for (index, syscall) in OBSERVED_SYSCALLS.iter().enumerate() {
        let remaining = OBSERVED_SYSCALLS.len() - index;
        program.push(jump(BPF_JEQ_K, *syscall as u32, remaining as u8, 0));
    }
    program.push(stmt(BPF_RET, SECCOMP_RET_ALLOW));
    let notify_index = program.len();
    program.push(stmt(BPF_RET, SECCOMP_RET_USER_NOTIF));
    debug_assert_eq!(notify_index - first_comparison, OBSERVED_SYSCALLS.len() + 1);
    program
}

/// Classification used by the notification observer. `Unclassified` covers
/// notifications without a path argument and keeps the distinction explicit
/// instead of treating missing evidence as denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotificationClass {
    Allowed,
    Blocked,
    Unclassified,
}

/// Classify an optional syscall path against the effective read/write policy.
///
/// This is an observation label only. It does not make a kernel decision and
/// must not be used as an enforcement substitute for Landlock.
pub fn classify_notification_path(
    path: Option<&str>,
    sandbox_cwd: &Path,
    policy: &crate::policy::Policy,
) -> NotificationClass {
    let Some(path) = path else {
        return NotificationClass::Unclassified;
    };
    // Abstract UNIX socket path (indicated by @ prefix)
    if path.starts_with('@') {
        return NotificationClass::Blocked;
    }
    let absolute = absolutize(path, sandbox_cwd);
    // Overlay-carved secrets can sit below a broad writable root such as
    // `/tmp` or `$PROJECT`. They must be classified before the additive allow
    // roots or observation would label a kernel-denied attempt as allowed.
    if policy
        .deny_resolved
        .iter()
        .any(|denied| absolute.starts_with(&denied.path))
    {
        return NotificationClass::Blocked;
    }
    if policy.in_read_scope(&absolute) {
        NotificationClass::Allowed
    } else {
        NotificationClass::Blocked
    }
}

/// Install the tap on the calling process and return the listener fd.
/// Requires PR_SET_NO_NEW_PRIVS (set beforehand by landlock/netblock setup).
pub fn install_tap() -> VettoResult<RawFd> {
    Ok(install_tap_owned()?.into_raw_fd())
}

fn install_tap_owned() -> VettoResult<OwnedFd> {
    let prog = build_tap_program();
    let fprog = SockFProg {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    // SAFETY: syscall with scalar + valid filter pointer.
    let ret = unsafe {
        libc::syscall(
            SYS_SECCOMP,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &fprog as *const SockFProg,
        )
    };
    if ret < 0 {
        return Err(VettoError::Seccomp(format!(
            "user-notify filter install failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: a successful seccomp NEW_LISTENER return is a fresh owned fd.
    Ok(unsafe { OwnedFd::from_raw_fd(ret as RawFd) })
}

/// Fork-probe whether user-notify is available on this kernel.
///
/// SAFETY: fork before worker threads exist; the child only installs a
/// trivial allow-all listener and _exit()s.
pub fn probe_available() -> bool {
    let probe_prog = [stmt(BPF_RET, SECCOMP_RET_ALLOW)];
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            // NEW_LISTENER requires no_new_privs (or CAP_SYS_ADMIN).
            // SAFETY: scalar-only prctl.
            if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
                unsafe { libc::_exit(1) };
            }
            let fprog = SockFProg {
                len: 1,
                filter: probe_prog.as_ptr(),
            };
            // SAFETY: scalar + valid pointer.
            let r = unsafe {
                libc::syscall(
                    SYS_SECCOMP,
                    SECCOMP_SET_MODE_FILTER,
                    SECCOMP_FILTER_FLAG_NEW_LISTENER,
                    &fprog as *const SockFProg,
                )
            };
            unsafe { libc::_exit(if r >= 0 { 0 } else { 1 }) };
        }
        pid => {
            let mut status = 0;
            loop {
                // SAFETY: plain waitpid.
                let r = unsafe { libc::waitpid(pid, &mut status, 0) };
                if r != -1 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
                    break;
                }
            }
            libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
        }
    }
}

// ---------------------------------------------------------------------------
// Parent side: the notifier watchdog.
// ---------------------------------------------------------------------------

/// Spawn the notification watchdog answering CONTINUE promptly. A stalled
/// responder would stall the child, so this runs on a dedicated thread.
///
/// `policy` is used to classify notifications: the notifier cannot see
/// syscall RESULTS (the kernel answers with CONTINUE and Landlock decides),
/// so an attempt is reported as BlockedAttempt only when the path is OUTSIDE
/// the policy allowlist — those are exactly the paths Landlock will deny.
/// Attempts inside the allowlist are allowed ops (covered by the /proc
/// poller) and are not re-reported here.
pub fn spawn_notifier(
    listener_fd: OwnedFd,
    bus: EventBus,
    policy: std::sync::Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    spawn_notifier_with_workers(listener_fd, bus, policy, sandbox_cwd, 4);
}

/// Spawn a bounded number of workers over one seccomp listener. Each worker
/// receives a distinct notification; sharing the listener is the kernel's
/// supported way to prevent one slow path read from stalling all children.
/// The default remains CONTINUE-only and Landlock remains the sole enforcer.
pub fn spawn_notifier_with_workers(
    listener_fd: OwnedFd,
    bus: EventBus,
    policy: std::sync::Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
    workers: usize,
) {
    let listener = Arc::new(listener_fd);
    let workers = workers.clamp(1, 8);
    for worker in 0..workers {
        let listener = Arc::clone(&listener);
        let bus = bus.clone();
        let policy = Arc::clone(&policy);
        let sandbox_cwd = sandbox_cwd.clone();
        std::thread::Builder::new()
            .name(format!("vetto-notifier-{worker}"))
            .spawn(move || notifier_loop(listener, bus, policy, sandbox_cwd))
            .expect("spawn notifier thread");
    }
}

fn notifier_loop(
    listener: Arc<OwnedFd>,
    bus: EventBus,
    policy: std::sync::Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    let fd = listener.as_raw_fd();
    loop {
        let mut notif = zeroed_notif();
        // SAFETY: valid fd + properly initialized struct.
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) } != 0 {
            break; // session over / fd closed
        }

        let maybe_path = extract_path(fd, &notif);
        if let Some(path) = maybe_path {
            if classify_notification_path(Some(&path), &sandbox_cwd, &policy)
                == NotificationClass::Blocked
            {
                let comm = read_comm(notif.pid).unwrap_or_else(|| "?".into());
                bus.publish(Event::BlockedAttempt {
                    ts: crate::events::types::now(),
                    pid: notif.pid,
                    comm,
                    path,
                    source: "observe-seccomp".into(),
                });
            }
        }

        // A notification can become stale while `/proc/<pid>/mem` is being
        // read. ID_VALID is mandatory immediately before every response;
        // stale notifications are simply discarded and never terminate the
        // other workers.
        if !send_continue_response(fd, notif.id) {
            break;
        }
    }
}

fn notif_id_valid(fd: libc::c_int, id: u64) -> bool {
    let mut id = id;
    // SAFETY: valid listener fd and pointer to the notification id.
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id as *mut u64) == 0 }
}

/// Send the default non-enforcing response. A stale id is not an I/O error:
/// the target already completed or exited, so the worker can receive again.
fn send_continue_response(fd: libc::c_int, id: u64) -> bool {
    if !notif_id_valid(fd, id) {
        return true;
    }
    let resp = SeccompNotifResp {
        id,
        val: 0,
        error: 0,
        flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
    };
    // SAFETY: valid fd + initialized response struct.
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0 }
}

fn send_fd_response(fd: libc::c_int, id: u64, value: i64) -> bool {
    if !notif_id_valid(fd, id) {
        return true;
    }
    let resp = SeccompNotifResp {
        id,
        val: value,
        error: 0,
        flags: 0,
    };
    // SAFETY: valid fd + initialized response struct.
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0 }
}

/// Resolve syscall path arguments (often relative) against the sandbox cwd.
fn absolutize(path: &str, sandbox_cwd: &std::path::Path) -> std::path::PathBuf {
    let p = std::path::Path::new(path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        sandbox_cwd.join(p)
    }
}

fn zeroed_notif() -> SeccompNotif {
    // SAFETY: all-zero bytes are a valid initial state for POD structs.
    unsafe { std::mem::zeroed() }
}

/// Path argument position per syscall number.
fn path_arg_index(nr: i32) -> Option<usize> {
    match nr {
        #[cfg(not(target_arch = "aarch64"))]
        NR_OPEN | NR_EXECVE => Some(0),
        #[cfg(target_arch = "aarch64")]
        NR_EXECVE => Some(0),
        NR_OPENAT | NR_OPENAT2 | NR_EXECVEAT => Some(1),
        NR_CONNECT | NR_BIND => Some(1),
        #[cfg(not(target_arch = "aarch64"))]
        NR_UNLINK | NR_RENAME | NR_CHMOD => Some(0),
        NR_UNLINKAT | NR_RENAMEAT | NR_RENAMEAT2 | NR_FCHMODAT => Some(1),
        _ => None,
    }
}

/// Exact, intentionally narrow ADDFD substitution. This is a compatibility
/// hook for harmless system files only; it is not a general path broker and
/// cannot substitute project files, credentials, sockets, or arbitrary fds.
#[derive(Debug)]
pub struct ExactSystemFileSubstitution {
    target: PathBuf,
    source: OwnedFd,
}

impl ExactSystemFileSubstitution {
    /// Construct the only supported substitution shape: an exact path from
    /// the documented non-security-critical system-file set, backed by the
    /// caller's `/dev/null` fd. Rejecting every other source keeps ADDFD
    /// visibly distinct from ordinary CONTINUE-only observation.
    pub fn new(target: impl AsRef<Path>, source: OwnedFd) -> VettoResult<Self> {
        let target = target.as_ref().to_path_buf();
        if !is_supported_system_path(&target) {
            return Err(VettoError::Seccomp(format!(
                "ADDFD target is not an approved exact system path: {}",
                target.display()
            )));
        }
        let source_path = std::fs::read_link(format!("/proc/self/fd/{}", source.as_raw_fd()))
            .map_err(|e| VettoError::Seccomp(format!("inspect ADDFD source fd: {e}")))?;
        if source_path != Path::new("/dev/null") {
            return Err(VettoError::Seccomp(format!(
                "ADDFD source must be /dev/null, got {}",
                source_path.display()
            )));
        }
        Ok(Self { target, source })
    }

    pub fn target(&self) -> &Path {
        &self.target
    }
}

fn is_supported_system_path(path: &Path) -> bool {
    matches!(
        path,
        p if p == Path::new("/etc/hostname")
            || p == Path::new("/etc/issue")
            || p == Path::new("/etc/os-release")
            || p == Path::new("/proc/kcore")
            || p == Path::new("/proc/kallsyms")
            || p == Path::new("/proc/sys/kernel/core_pattern")
            || p == Path::new("/proc/version_signature")
    )
}

/// A listener configured for the explicit, opt-in ADDFD compatibility path.
/// It cannot be passed to `spawn_notifier`; callers must choose the separately
/// named `spawn_addfd_notifier` API.
#[derive(Debug)]
pub struct AddFdListener {
    listener: OwnedFd,
    substitution: ExactSystemFileSubstitution,
}

impl AddFdListener {
    pub fn as_raw_fd(&self) -> RawFd {
        self.listener.as_raw_fd()
    }
}

/// Install a tap with the explicit ADDFD option. The ordinary `install_tap`
/// path never enables ADDFD and always uses CONTINUE responses.
pub fn install_tap_with_addfd(
    substitution: ExactSystemFileSubstitution,
) -> VettoResult<AddFdListener> {
    Ok(AddFdListener {
        listener: install_tap_owned()?,
        substitution,
    })
}

/// Spawn the opt-in exact-system-file substituter. No caller in the normal
/// sandbox path uses this API; it exists for a deliberate compatibility
/// integration and remains disabled by default.
pub fn spawn_addfd_notifier(
    listener: AddFdListener,
    bus: EventBus,
    policy: Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    std::thread::Builder::new()
        .name("vetto-addfd-notifier".into())
        .spawn(move || addfd_notifier_loop(listener, bus, policy, sandbox_cwd))
        .expect("spawn addfd notifier thread");
}

fn addfd_notifier_loop(
    listener: AddFdListener,
    bus: EventBus,
    policy: Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    let fd = listener.as_raw_fd();
    loop {
        let mut notif = zeroed_notif();
        // SAFETY: valid listener fd + initialized notification struct.
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) } != 0 {
            break;
        }

        let maybe_path = extract_path(fd, &notif);
        let exact_target = maybe_path
            .as_deref()
            .map(|path| absolutize(path, &sandbox_cwd) == listener.substitution.target);
        // ADDFD can replace only an open-family result. Applying an injected
        // fd to execve, unlink, chmod, rename, or connect would change the
        // syscall's return type/semantics and could turn this compatibility
        // hook into an unintended policy bypass.
        if addfd_allowed_syscall(notif.data.nr) && exact_target == Some(true) {
            if let Some(injected) = inject_exact_fd(fd, &notif, &listener.substitution) {
                if !send_fd_response(fd, notif.id, injected as i64) {
                    break;
                }
                continue;
            }
        }

        if let Some(path) = maybe_path {
            if classify_notification_path(Some(&path), &sandbox_cwd, &policy)
                == NotificationClass::Blocked
            {
                let comm = read_comm(notif.pid).unwrap_or_else(|| "?".into());
                bus.publish(Event::BlockedAttempt {
                    ts: crate::events::types::now(),
                    pid: notif.pid,
                    comm,
                    path,
                    source: "observe-seccomp".into(),
                });
            }
        }
        if !send_continue_response(fd, notif.id) {
            break;
        }
    }
}

/// Spawn the user-notify enforcement supervisor.
/// Evaluates policy decisions for intercepted syscalls (default deny).
pub fn spawn_enforcement_supervisor(
    listener_fd: OwnedFd,
    bus: EventBus,
    config: crate::policy::SeccompNotifyConfig,
    policy: Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    std::thread::Builder::new()
        .name("vetto-enforce-notifier".into())
        .spawn(move || enforcement_supervisor_loop(listener_fd, bus, config, policy, sandbox_cwd))
        .expect("spawn enforcement notifier thread");
}

fn enforcement_supervisor_loop(
    listener: OwnedFd,
    bus: EventBus,
    config: crate::policy::SeccompNotifyConfig,
    policy: Arc<crate::policy::Policy>,
    sandbox_cwd: PathBuf,
) {
    let fd = listener.as_raw_fd();
    loop {
        let mut notif = zeroed_notif();
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) } != 0 {
            break;
        }

        let is_default_allow = config.default_action.as_deref() == Some("allow");
        let allowed = is_default_allow || is_syscall_allowed(notif.data.nr, &config.allow_syscalls);

        if allowed {
            if !send_continue_response(fd, notif.id) {
                break;
            }
        } else {
            let comm = read_comm(notif.pid).unwrap_or_else(|| "?".into());
            let path =
                extract_path(fd, &notif).unwrap_or_else(|| format!("syscall:{}", notif.data.nr));
            bus.publish(Event::BlockedAttempt {
                ts: crate::events::types::now(),
                pid: notif.pid,
                comm,
                path,
                source: "seccomp-user-notify-enforce".into(),
            });

            if !send_error_response(fd, notif.id, libc::EPERM) {
                break;
            }
        }
    }
}

fn send_error_response(fd: libc::c_int, id: u64, error_code: i32) -> bool {
    if !notif_id_valid(fd, id) {
        return true;
    }
    let resp = SeccompNotifResp {
        id,
        val: -1,
        error: error_code,
        flags: 0,
    };
    unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) == 0 }
}

fn is_syscall_allowed(nr: i32, allow_list: &[String]) -> bool {
    for allowed in allow_list {
        if let Ok(num) = allowed.parse::<i32>() {
            if num == nr {
                return true;
            }
        }
        if match_syscall_name(nr, allowed) {
            return true;
        }
    }
    false
}

fn match_syscall_name(nr: i32, name: &str) -> bool {
    match name {
        "mount" => nr == libc::SYS_mount as i32,
        "umount" | "umount2" => nr == libc::SYS_umount2 as i32,
        "pivot_root" => nr == libc::SYS_pivot_root as i32,
        "chroot" => nr == libc::SYS_chroot as i32,
        "syslog" => nr == libc::SYS_syslog as i32,
        _ => false,
    }
}

fn inject_exact_fd(
    listener_fd: libc::c_int,
    notif: &SeccompNotif,
    substitution: &ExactSystemFileSubstitution,
) -> Option<i32> {
    if !notif_id_valid(listener_fd, notif.id) {
        return None;
    }
    let mut addfd = SeccompNotifAddfd {
        id: notif.id,
        flags: 0,
        srcfd: substitution.source.as_raw_fd() as u32,
        newfd: 0,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    // SAFETY: valid listener fd and initialized ADDFD request.
    let result = unsafe {
        libc::ioctl(
            listener_fd,
            SECCOMP_IOCTL_NOTIF_ADDFD,
            &mut addfd as *mut SeccompNotifAddfd,
        )
    };
    (result >= 0).then_some(result as i32)
}

fn addfd_allowed_syscall(nr: i32) -> bool {
    #[cfg(not(target_arch = "aarch64"))]
    {
        matches!(nr, NR_OPEN | NR_OPENAT | NR_OPENAT2)
    }
    #[cfg(target_arch = "aarch64")]
    {
        matches!(nr, NR_OPENAT | NR_OPENAT2)
    }
}

fn extract_path(fd: libc::c_int, notif: &SeccompNotif) -> Option<String> {
    let idx = path_arg_index(notif.data.nr)?;
    let ptr = notif.data.args[idx];
    if ptr == 0 {
        return None;
    }
    // Guard against reading a stale notification.
    let mut id = notif.id;
    // SAFETY: ioctl with valid fd + u64 out-pointer.
    if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id as *mut u64) } != 0 {
        return None;
    }

    let mem_path = format!("/proc/{}/mem", notif.pid);
    let Ok(file) = std::fs::File::open(&mem_path) else {
        return None;
    };
    use std::io::{Read, Seek, SeekFrom};
    let mut file = file;
    file.seek(SeekFrom::Start(ptr)).ok()?;

    // Handle connect and bind: args[1] points to struct sockaddr
    if notif.data.nr == NR_CONNECT || notif.data.nr == NR_BIND {
        let mut sa_buf = [0u8; 128];
        let n = file.read(&mut sa_buf).ok()?;
        if n >= 2 {
            let family = u16::from_ne_bytes([sa_buf[0], sa_buf[1]]);
            if family == libc::AF_UNIX as u16 {
                let path_bytes = &sa_buf[2..n.min(110)];
                if !path_bytes.is_empty() {
                    if path_bytes[0] == 0 {
                        let name_bytes = &path_bytes[1..];
                        let end = name_bytes
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(name_bytes.len());
                        if end > 0 {
                            return Some(format!(
                                "@{}",
                                String::from_utf8_lossy(&name_bytes[..end])
                            ));
                        }
                    } else {
                        let end = path_bytes
                            .iter()
                            .position(|&b| b == 0)
                            .unwrap_or(path_bytes.len());
                        if end > 0 {
                            return Some(String::from_utf8_lossy(&path_bytes[..end]).to_string());
                        }
                    }
                }
            }
        }
        return None;
    }

    let mut buf = [0u8; 4096];
    let mut n = file.read(&mut buf).ok()?;
    n = n.min(buf.len());

    // Re-validate AFTER the read to shrink (not eliminate) the race window.
    // SAFETY: same ioctl as above.
    if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_ID_VALID, &mut id as *mut u64) } != 0 {
        return None;
    }

    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..end]).to_string())
}

fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbers_come_from_target_libc_table() {
        assert_eq!(SYS_SECCOMP, libc::SYS_seccomp);
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(NR_OPEN, libc::SYS_open as i32);
        assert_eq!(NR_EXECVE, libc::SYS_execve as i32);
        assert_eq!(NR_OPENAT, libc::SYS_openat as i32);
        assert_eq!(NR_OPENAT2, libc::SYS_openat2 as i32);
        assert_eq!(NR_EXECVEAT, libc::SYS_execveat as i32);
        assert_eq!(NR_CONNECT, libc::SYS_connect as i32);
        assert_eq!(NR_BIND, libc::SYS_bind as i32);
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(NR_UNLINK, libc::SYS_unlink as i32);
        assert_eq!(NR_UNLINKAT, libc::SYS_unlinkat as i32);
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(NR_RENAME, libc::SYS_rename as i32);
        assert_eq!(NR_RENAMEAT, libc::SYS_renameat as i32);
        assert_eq!(NR_RENAMEAT2, libc::SYS_renameat2 as i32);
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(NR_CHMOD, libc::SYS_chmod as i32);
        assert_eq!(NR_FCHMODAT, libc::SYS_fchmodat as i32);
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(NR_FORK, libc::SYS_fork as i32);
        assert_eq!(NR_CLONE, libc::SYS_clone as i32);
        assert_eq!(NR_CLONE3, libc::SYS_clone3 as i32);
    }

    #[test]
    fn tap_filter_checks_native_arch_before_syscall_numbers() {
        let program = build_tap_program();
        assert_eq!(program.len(), OBSERVED_SYSCALLS.len() + 6);
        assert_eq!(program[0].code, BPF_LD_ABS);
        assert_eq!(program[0].k, 4);
        assert_eq!(program[1].k, native_audit_arch());
        assert_eq!(program[2].k, SECCOMP_RET_KILL_PROCESS);
        for syscall in OBSERVED_SYSCALLS {
            assert_eq!(
                eval(&program, native_audit_arch(), *syscall),
                SECCOMP_RET_USER_NOTIF,
                "syscall {syscall} must be observed"
            );
        }
        assert_eq!(
            eval(&program, native_audit_arch(), libc::SYS_read as i32),
            SECCOMP_RET_ALLOW
        );
        assert_eq!(
            eval(&program, native_audit_arch() ^ 1, NR_OPENAT),
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_audit_arch_is_native_little_endian() {
        assert_eq!(native_audit_arch(), 0xC000_00B7);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x86_64_audit_arch_is_native_little_endian() {
        assert_eq!(native_audit_arch(), 0xC000_003E);
    }

    #[cfg(target_arch = "arm")]
    #[test]
    fn arm_audit_arch_is_native_little_endian() {
        assert_eq!(native_audit_arch(), 0x4000_0028);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn i386_audit_arch_is_native_little_endian() {
        assert_eq!(native_audit_arch(), 0x4000_0003);
    }

    #[cfg(target_arch = "riscv64")]
    #[test]
    fn riscv64_audit_arch_is_native_little_endian() {
        assert_eq!(native_audit_arch(), 0xC000_00F3);
    }

    #[test]
    fn filesystem_path_arguments_cover_requested_mutations() {
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(path_arg_index(NR_OPEN), Some(0));
        assert_eq!(path_arg_index(NR_OPENAT), Some(1));
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(path_arg_index(NR_UNLINK), Some(0));
        assert_eq!(path_arg_index(NR_UNLINKAT), Some(1));
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(path_arg_index(NR_RENAME), Some(0));
        assert_eq!(path_arg_index(NR_RENAMEAT), Some(1));
        assert_eq!(path_arg_index(NR_RENAMEAT2), Some(1));
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(path_arg_index(NR_CHMOD), Some(0));
        assert_eq!(path_arg_index(NR_FCHMODAT), Some(1));
        assert_eq!(path_arg_index(NR_CONNECT), Some(1));
        assert_eq!(path_arg_index(NR_BIND), Some(1));
        assert_eq!(path_arg_index(NR_CLONE3), None);
    }

    #[test]
    fn addfd_substitution_is_limited_to_open_family_results() {
        #[cfg(not(target_arch = "aarch64"))]
        assert!(addfd_allowed_syscall(NR_OPEN));
        assert!(addfd_allowed_syscall(NR_OPENAT));
        assert!(addfd_allowed_syscall(NR_OPENAT2));
        assert!(!addfd_allowed_syscall(NR_EXECVE));
        #[cfg(not(target_arch = "aarch64"))]
        assert!(!addfd_allowed_syscall(NR_UNLINK));
        assert!(!addfd_allowed_syscall(NR_CONNECT));
    }

    #[test]
    fn addfd_accepts_only_devnull_for_exact_noncritical_system_paths() {
        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        let source = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let accepted = ExactSystemFileSubstitution::new("/etc/hostname", source)
            .expect("approved exact system path");
        assert_eq!(accepted.target(), Path::new("/etc/hostname"));

        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        let source = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        assert!(ExactSystemFileSubstitution::new("/tmp/project-secret", source).is_err());

        let file = std::fs::File::open("/dev/null").expect("/dev/null");
        let source = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        let accepted_kcore = ExactSystemFileSubstitution::new("/proc/kcore", source)
            .expect("/proc/kcore is supported");
        assert_eq!(accepted_kcore.target(), Path::new("/proc/kcore"));
    }

    fn eval(program: &[SockFilter], arch: u32, syscall: i32) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;
        loop {
            let instruction = &program[pc];
            match instruction.code {
                BPF_LD_ABS => {
                    accumulator = match instruction.k {
                        0 => syscall as u32,
                        4 => arch,
                        offset => panic!("unexpected load offset {offset}"),
                    };
                    pc += 1;
                }
                BPF_JEQ_K => {
                    pc += if accumulator == instruction.k {
                        instruction.jt as usize + 1
                    } else {
                        instruction.jf as usize + 1
                    };
                }
                BPF_RET => return instruction.k,
                code => panic!("unexpected BPF opcode {code:#x}"),
            }
        }
    }
}
