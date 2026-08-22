//! Coarse NETWORK kill-switch for Tier FS-ONLY (no namespaces available).
//!
//! Installs an unprivileged seccomp-BPF filter (PR_SET_NO_NEW_PRIVS +
//! SECCOMP_MODE_FILTER) returning EAFNOSUPPORT for socket()/socketpair() on
//! AF_INET/AF_INET6. Coarse but real: no network exfiltration without a
//! userns. seccomp NEVER enforces filesystem paths anywhere in vetto.

use crate::error::{VettoError, VettoResult};

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0x8000_00B7;

const NR_SOCKET: i32 = 41; // x86_64 + aarch64
const NR_SOCKETPAIR: i32 = 53;

const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EAFNOSUPPORT: u32 = 97;

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

const fn bpf_stmt(code: u16, k: u32) -> SockFilter {
    SockFilter { code, jt: 0, jf: 0, k }
}
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// BPF class/mode constants (linux/filter.h)
const BPF_LD_BPF_W_BPF_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET: u16 = 0x06;

fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
}

fn build_program() -> Vec<SockFilter> {
    use BPF_JMP_JEQ_K as JEQ;
    use BPF_LD_BPF_W_BPF_ABS as LD_ABS;
    use BPF_RET as RET;

    // Layout notes: seccomp_data.nr @0, .arch @4, .args[0] @16 (all LE words).
    //
    // idx: instruction
    // 0    LD arch
    // 1    JEQ native -> 2 : ret ERRNO(EPERM)
    // 2    LD nr
    // 3    JEQ socket     -> 6 (domain check)
    // 4    JEQ socketpair -> 6
    // 5    ret ALLOW
    // 6    LD args[0] (address family)
    // 7    JEQ AF_INET  -> ret EAFNOSUPPORT
    // 8    JEQ AF_INET6 -> ret EAFNOSUPPORT
    // 9    ret ALLOW
    // 10   ret ERRNO(EAFNOSUPPORT)
    vec![
        bpf_stmt(LD_ABS, 4),                              // 0
        bpf_jump(JEQ, native_audit_arch(), 0, 1),         // 1 -> 2 / 3(err)
        bpf_stmt(RET, SECCOMP_RET_ERRNO | libc::EPERM as u32), // fallback for foreign ABIs
        bpf_stmt(LD_ABS, 0),                              // 3
        bpf_jump(JEQ, NR_SOCKET as u32, 2, 0),            // 4 -> 7(domain)
        bpf_jump(JEQ, NR_SOCKETPAIR as u32, 1, 0),        // 5 -> 7
        bpf_stmt(RET, SECCOMP_RET_ALLOW),                 // 6
        bpf_stmt(LD_ABS, 16),                             // 7 args[0]
        bpf_jump(JEQ, AF_INET, 0, 1),                     // 8
        bpf_stmt(RET, SECCOMP_RET_ERRNO | EAFNOSUPPORT),  // 9
        bpf_jump(JEQ, AF_INET6, 0, 1),                    // 10
        bpf_stmt(RET, SECCOMP_RET_ERRNO | EAFNOSUPPORT),  // 11
        bpf_stmt(RET, SECCOMP_RET_ALLOW),                 // 12
    ]
}

/// Install the network block on the calling process. Irreversible and
/// inherited by every descendant. Must run before exec.
pub fn install() -> VettoResult<()> {
    // SAFETY: scalar-only prctl.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(VettoError::Seccomp(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }
    let prog = build_program();
    let fprog = SockFProg {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    // SAFETY: fprog points to a valid filter array for the duration of the call.
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &fprog) } != 0 {
        return Err(VettoError::Seccomp(format!(
            "SECCOMP_MODE_FILTER: {} (CONFIG_SECCOMP_FILTER disabled?)",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Fork-probe whether seccomp filters can be installed unprivileged here.
///
/// SAFETY: fork before any worker threads exist; child performs syscalls
/// only and _exit()s.
pub fn probe_available() -> bool {
    match unsafe { libc::fork() } {
        -1 => false,
        0 => {
            let res = install();
            unsafe { libc::_exit(if res.is_ok() { 0 } else { 1 }) };
        }
        pid => {
            let mut status = 0i32;
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
