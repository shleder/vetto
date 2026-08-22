//! OPTIONAL blocked-attempt observability tap (`--observe-seccomp`).
//!
//! seccomp user-notify used PURELY for observation of open/openat/openat2/
//! execve/execveat attempts. Every notification is answered with
//! SECCOMP_USER_NOTIF_FLAG_CONTINUE so the kernel re-enters the syscall
//! normally and LANDLOCK REMAINS THE SOLE ENFORCER. This tap can never
//! enforce anything and never blocks the child from running: if anything in
//! its setup fails, vetto continues without a blocked-attempt feed.
//!
//! Documented limits: reported paths are racy (TOCTOU in observation only);
//! path strings are read best-effort from /proc/<pid>/mem.

use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::events::{bus::EventBus, Event};
use crate::error::{VettoError, VettoResult};

const SYS_SECCOMP: libc::c_long = 317;
const SECCOMP_SET_MODE_FILTER: libc::c_uint = 1;
const SECCOMP_FILTER_FLAG_NEW_LISTENER: libc::c_uint = 1 << 3;

const SECCOMP_RET_USER_NOTIF: u32 = 0x7fc0_0000; // NOT 0x7ff00000 (= RET_TRACE!)
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1 << 0;

// ioctl numbers for seccomp notify (_IOWR('!', ...)).
const SECCOMP_IOCTL_NOTIF_RECV: libc::c_ulong = 0xc050_2100;
const SECCOMP_IOCTL_NOTIF_SEND: libc::c_ulong = 0xc018_2101;
const SECCOMP_IOCTL_NOTIF_ID_VALID: libc::c_ulong = 0x4008_2102;

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
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

const BPF_LD_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET: u16 = 0x06;

fn stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

/// x86_64 syscall numbers for the observed set.
const NR_OPEN: i32 = 2;
const NR_EXECVE: i32 = 59;
const NR_OPENAT: i32 = 257;
const NR_OPENAT2: i32 = 437;
const NR_EXECVEAT: i32 = 322;

fn build_tap_program() -> Vec<SockFilter> {
    // Trap the observed syscalls; everything else passes through untouched.
    //
    // idx: instruction
    // 0  LD nr
    // 1  JEQ open      -> trap (jt=5)
    // 2  JEQ openat    -> trap (jt=4)
    // 3  JEQ openat2   -> trap (jt=3)
    // 4  JEQ execve    -> trap (jt=2)
    // 5  JEQ execveat  -> trap (jt=1)
    // 6  RET ALLOW
    // 7  RET USER_NOTIF
    vec![
        stmt(BPF_LD_ABS, 0),                      // 0
        jump(BPF_JEQ_K, NR_OPEN as u32, 5, 0),    // 1
        jump(BPF_JEQ_K, NR_OPENAT as u32, 4, 0),  // 2
        jump(BPF_JEQ_K, NR_OPENAT2 as u32, 3, 0), // 3
        jump(BPF_JEQ_K, NR_EXECVE as u32, 2, 0),  // 4
        jump(BPF_JEQ_K, NR_EXECVEAT as u32, 1, 0),// 5
        stmt(BPF_RET, SECCOMP_RET_ALLOW),         // 6
        stmt(BPF_RET, SECCOMP_RET_USER_NOTIF),    // 7
    ]
}

/// Install the tap on the calling process and return the listener fd.
/// Requires PR_SET_NO_NEW_PRIVS (set beforehand by landlock/netblock setup).
pub fn install_tap() -> VettoResult<RawFd> {
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
    Ok(ret as RawFd)
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
/// responder would stall the child, so this runs on a dedicated thread that
/// never allocates heavily per notification.
pub fn spawn_notifier(listener_fd: OwnedFd, bus: EventBus) {
    std::thread::Builder::new()
        .name("vetto-notifier".into())
        .spawn(move || notifier_loop(listener_fd, bus))
        .expect("spawn notifier thread");
}

fn notifier_loop(listener: OwnedFd, bus: EventBus) {
    let fd = listener.as_raw_fd();
    loop {
        let mut notif = zeroed_notif();
        // SAFETY: valid fd + properly initialized struct.
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_RECV, &mut notif) } != 0 {
            eprintln!(
                "[notifier] RECV failed errno={}",
                std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
            );
            break; // session over / fd closed
        }

        let comm = read_comm(notif.pid).unwrap_or_else(|| "?".into());
        let maybe_path = extract_path(fd, &notif);

        if let Some(path) = maybe_path {
            bus.publish(Event::BlockedAttempt {
                ts: crate::events::types::now(),
                pid: notif.pid,
                comm,
                path,
                source: "observe-seccomp".into(),
            });
        }

        let resp = SeccompNotifResp {
            id: notif.id,
            val: 0,
            error: 0,
            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
        };
        // SAFETY: valid fd + struct.
        if unsafe { libc::ioctl(fd, SECCOMP_IOCTL_NOTIF_SEND, &resp) } != 0 {
            break;
        }
    }
}

fn zeroed_notif() -> SeccompNotif {
    // SAFETY: all-zero bytes are a valid initial state for POD structs.
    unsafe { std::mem::zeroed() }
}

/// Path argument position per syscall number.
fn path_arg_index(nr: i32) -> Option<usize> {
    match nr {
        NR_OPEN | NR_EXECVE => Some(0),
        NR_OPENAT | NR_OPENAT2 | NR_EXECVEAT => Some(1),
        _ => None,
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
