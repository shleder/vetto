//! Coarse NETWORK kill-switch for Tier FS-ONLY (no namespaces available).
//!
//! Installs an unprivileged seccomp-BPF filter (PR_SET_NO_NEW_PRIVS +
//! SECCOMP_MODE_FILTER) returning EAFNOSUPPORT for every non-AF_UNIX
//! socket()/socketpair() in FS-ONLY. AF_UNIX remains available for local IPC;
//! no network family can be created without a userns. FULL selects either the
//! same AF_UNIX-only policy for `--net=off`, or AF_UNIX+AF_INET+AF_INET6 for
//! the allowlist relay. Every policy also blocks mount teardown and the
//! kernel interfaces most useful for escaping a filesystem sandbox. seccomp
//! NEVER enforces filesystem paths anywhere in vetto.

use crate::error::{VettoError, VettoResult};

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

// Keep syscall numbers architecture-aware. In particular, socket/socketpair
// are 41/53 on x86_64 but 198/199 on aarch64. libc exposes the right values
// for the target ABI; hard-coded x86_64 numbers would silently disable the
// network kill-switch on ARM.
const NR_SOCKET: u32 = libc::SYS_socket as u32;
const NR_SOCKETPAIR: u32 = libc::SYS_socketpair as u32;

// Linux exposes both umount(2) and umount2(2) through the umount2 syscall
// entry point on the supported ABIs. libc::umount(path) is the flags=0
// wrapper, so denying SYS_umount2 covers both spellings.
const NR_UMOUNT2: u32 = libc::SYS_umount2 as u32;
const NR_MOUNT: u32 = libc::SYS_mount as u32;
const NR_PIVOT_ROOT: u32 = libc::SYS_pivot_root as u32;
const NR_MOVE_MOUNT: u32 = libc::SYS_move_mount as u32;
const NR_OPEN_TREE: u32 = libc::SYS_open_tree as u32;
const NR_FSOPEN: u32 = libc::SYS_fsopen as u32;
const NR_FSCONFIG: u32 = libc::SYS_fsconfig as u32;
const NR_FSMOUNT: u32 = libc::SYS_fsmount as u32;
const NR_FSPICK: u32 = libc::SYS_fspick as u32;
const NR_MOUNT_SETATTR: u32 = libc::SYS_mount_setattr as u32;
const NR_IO_URING_SETUP: u32 = libc::SYS_io_uring_setup as u32;
const NR_IO_URING_ENTER: u32 = libc::SYS_io_uring_enter as u32;
const NR_IO_URING_REGISTER: u32 = libc::SYS_io_uring_register as u32;
const NR_USERFAULTFD: u32 = libc::SYS_userfaultfd as u32;
const NR_PTRACE: u32 = libc::SYS_ptrace as u32;
const NR_PROCESS_VM_READV: u32 = libc::SYS_process_vm_readv as u32;
const NR_PROCESS_VM_WRITEV: u32 = libc::SYS_process_vm_writev as u32;
const NR_PIDFD_GETFD: u32 = libc::SYS_pidfd_getfd as u32;
const NR_KEXEC_LOAD: u32 = libc::SYS_kexec_load as u32;
const NR_KEXEC_FILE_LOAD: u32 = libc::SYS_kexec_file_load as u32;
const NR_INIT_MODULE: u32 = libc::SYS_init_module as u32;
const NR_FINIT_MODULE: u32 = libc::SYS_finit_module as u32;
const NR_DELETE_MODULE: u32 = libc::SYS_delete_module as u32;
const NR_PERF_EVENT_OPEN: u32 = libc::SYS_perf_event_open as u32;
const NR_BPF: u32 = libc::SYS_bpf as u32;
const NR_REBOOT: u32 = libc::SYS_reboot as u32;
const NR_SWAPON: u32 = libc::SYS_swapon as u32;
const NR_SWAPOFF: u32 = libc::SYS_swapoff as u32;

// Keep this list evidence-based. These interfaces tear down or replace the
// namespace/filesystem setup, expose another process, open kernel tracing and
// loading attack surfaces, or are follow-up io_uring operations. Ordinary
// compilation, package management, file, process and IPC syscalls remain
// available. docs/threat-model.md records the compatibility decision for the
// less universally malicious perf/BPF interfaces.
const HARDENING_SYSCALLS: &[u32] = &[
    NR_UMOUNT2,
    NR_MOUNT,
    NR_PIVOT_ROOT,
    NR_MOVE_MOUNT,
    NR_OPEN_TREE,
    NR_FSOPEN,
    NR_FSCONFIG,
    NR_FSMOUNT,
    NR_FSPICK,
    NR_MOUNT_SETATTR,
    NR_IO_URING_SETUP,
    NR_IO_URING_ENTER,
    NR_IO_URING_REGISTER,
    NR_USERFAULTFD,
    NR_PTRACE,
    NR_PROCESS_VM_READV,
    NR_PROCESS_VM_WRITEV,
    NR_PIDFD_GETFD,
    NR_KEXEC_LOAD,
    NR_KEXEC_FILE_LOAD,
    NR_INIT_MODULE,
    NR_FINIT_MODULE,
    NR_DELETE_MODULE,
    NR_PERF_EVENT_OPEN,
    NR_BPF,
    NR_REBOOT,
    NR_SWAPON,
    NR_SWAPOFF,
];

const AF_UNIX: u32 = libc::AF_UNIX as u32;
const AF_INET: u32 = libc::AF_INET as u32;
const AF_INET6: u32 = libc::AF_INET6 as u32;

const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const EAFNOSUPPORT: u32 = 97;

/// Socket families available to the agent after the seccomp filter is
/// installed.  Both variants always permit local AF_UNIX IPC; the allowlist
/// relay additionally needs ordinary IPv4/IPv6 sockets for its loopback
/// proxy.  All other families (including AF_VSOCK, AF_PACKET and AF_NETLINK)
/// are rejected before the kernel creates a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketPolicy {
    UnixOnly,
    UnixAndIp,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    SockFilter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}
const fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> SockFilter {
    SockFilter { code, jt, jf, k }
}

// BPF class/mode constants (linux/filter.h)
const BPF_LD_BPF_W_BPF_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET: u16 = 0x06;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

fn native_audit_arch() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        AUDIT_ARCH_X86_64
    }
    #[cfg(target_arch = "aarch64")]
    {
        AUDIT_ARCH_AARCH64
    }
    // No supported Linux target reaches here today. Returning an impossible
    // arch keeps the filter fail-closed if the module is ever compiled for a
    // new target: the first syscall is killed instead of being allowed.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        0
    }
}

fn build_program(socket_policy: SocketPolicy) -> Vec<SockFilter> {
    use BPF_JMP_JEQ_K as JEQ;
    use BPF_JMP_JSET_K as JSET;
    use BPF_LD_BPF_W_BPF_ABS as LD_ABS;
    use BPF_RET as RET;

    // Layout notes: seccomp_data.nr @0, .arch @4, .args[0] @16 (all LE
    // words).  The two syscall branches and every hardening branch are
    // patched after the vector is assembled, so adding one narrowly justified
    // denial cannot silently leave a stale BPF jump offset behind.
    let (inet_jt, inet_jf, inet6_jt, inet6_jf) = match socket_policy {
        SocketPolicy::UnixOnly => (1, 1, 0, 0),
        SocketPolicy::UnixAndIp => (2, 0, 1, 0),
    };
    let mut program = vec![
        bpf_stmt(LD_ABS, 4),                      // 0: arch
        bpf_jump(JEQ, native_audit_arch(), 1, 0), // 1: native -> 3
        bpf_stmt(RET, SECCOMP_RET_KILL_PROCESS),  // 2: foreign ABI
        bpf_stmt(LD_ABS, 0),                      // 3: syscall number
        bpf_jump(JSET, X32_SYSCALL_BIT, 0, 1),    // 4: x32 -> 5
        bpf_stmt(RET, SECCOMP_RET_KILL_PROCESS),  // 5: x32 ABI
    ];

    let socket_index = program.len();
    program.push(bpf_jump(JEQ, NR_SOCKET, 0, 0));
    let socketpair_index = program.len();
    program.push(bpf_jump(JEQ, NR_SOCKETPAIR, 0, 0));

    let hardening_start = program.len();
    for syscall in HARDENING_SYSCALLS {
        program.push(bpf_jump(JEQ, *syscall, 0, 0));
    }
    let allow_index = program.len();
    program.push(bpf_stmt(RET, SECCOMP_RET_ALLOW));
    let hardening_deny_index = program.len();
    program.push(bpf_stmt(RET, SECCOMP_RET_ERRNO | libc::EPERM as u32));

    let domain_index = program.len();
    program.extend([
        bpf_stmt(LD_ABS, 16),
        bpf_jump(JEQ, AF_UNIX, 0, 0),
        bpf_jump(JEQ, AF_INET, inet_jt, inet_jf),
        bpf_jump(JEQ, AF_INET6, inet6_jt, inet6_jf),
        bpf_stmt(RET, SECCOMP_RET_ERRNO | EAFNOSUPPORT),
        bpf_stmt(RET, SECCOMP_RET_ALLOW),
    ]);
    let permitted_family_index = program.len() - 1;

    // The socket and socketpair branches jump directly to the argument
    // inspection. Every hardening syscall branch jumps to one shared EPERM
    // return. All offsets are guaranteed to fit in u8 for this compact filter.
    program[socket_index].jt = jump_offset(socket_index, domain_index);
    program[socketpair_index].jt = jump_offset(socketpair_index, domain_index);
    for (index, instruction) in program
        .iter_mut()
        .enumerate()
        .take(allow_index)
        .skip(hardening_start)
    {
        instruction.jt = jump_offset(index, hardening_deny_index);
    }
    // AF_UNIX is always permitted; its branch target is the final allow.
    let unix_index = domain_index + 1;
    program[unix_index].jt = jump_offset(unix_index, permitted_family_index);

    program
}

fn jump_offset(from: usize, to: usize) -> u8 {
    to.checked_sub(from + 1)
        .expect("BPF jump target must be after its branch")
        .try_into()
        .expect("seccomp BPF jump offset must fit in u8")
}

/// Install the network block plus syscall hardening on the calling process.
/// Irreversible and inherited by every descendant. Must run before exec.
pub fn install() -> VettoResult<()> {
    install_for(SocketPolicy::UnixOnly)
}

/// Install syscall hardening and the explicitly selected socket-family
/// policy. Irreversible and inherited by every descendant; callers must
/// treat an error as a fail-closed setup failure.
pub fn install_for(socket_policy: SocketPolicy) -> VettoResult<()> {
    // SAFETY: scalar-only prctl.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(VettoError::Seccomp(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }
    let prog = build_program(socket_policy);
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
            if let Err(e) = &res {
                eprintln!("[netblock-probe] install failed: {e}");
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscall_numbers_come_from_libc() {
        assert_eq!(NR_SOCKET, libc::SYS_socket as u32);
        assert_eq!(NR_SOCKETPAIR, libc::SYS_socketpair as u32);
        assert_eq!(NR_UMOUNT2, libc::SYS_umount2 as u32);
        assert_eq!(NR_MOUNT, libc::SYS_mount as u32);
        assert_eq!(NR_PIVOT_ROOT, libc::SYS_pivot_root as u32);
        assert_eq!(NR_MOVE_MOUNT, libc::SYS_move_mount as u32);
        assert_eq!(NR_OPEN_TREE, libc::SYS_open_tree as u32);
        assert_eq!(NR_FSOPEN, libc::SYS_fsopen as u32);
        assert_eq!(NR_FSCONFIG, libc::SYS_fsconfig as u32);
        assert_eq!(NR_FSMOUNT, libc::SYS_fsmount as u32);
        assert_eq!(NR_FSPICK, libc::SYS_fspick as u32);
        assert_eq!(NR_MOUNT_SETATTR, libc::SYS_mount_setattr as u32);
        assert_eq!(NR_IO_URING_SETUP, libc::SYS_io_uring_setup as u32);
        assert_eq!(NR_IO_URING_ENTER, libc::SYS_io_uring_enter as u32);
        assert_eq!(NR_IO_URING_REGISTER, libc::SYS_io_uring_register as u32);
        assert_eq!(NR_USERFAULTFD, libc::SYS_userfaultfd as u32);
        assert_eq!(NR_PTRACE, libc::SYS_ptrace as u32);
        assert_eq!(NR_PROCESS_VM_READV, libc::SYS_process_vm_readv as u32);
        assert_eq!(NR_PROCESS_VM_WRITEV, libc::SYS_process_vm_writev as u32);
        assert_eq!(NR_PIDFD_GETFD, libc::SYS_pidfd_getfd as u32);
        assert_eq!(NR_KEXEC_LOAD, libc::SYS_kexec_load as u32);
        assert_eq!(NR_KEXEC_FILE_LOAD, libc::SYS_kexec_file_load as u32);
        assert_eq!(NR_INIT_MODULE, libc::SYS_init_module as u32);
        assert_eq!(NR_FINIT_MODULE, libc::SYS_finit_module as u32);
        assert_eq!(NR_DELETE_MODULE, libc::SYS_delete_module as u32);
        assert_eq!(NR_PERF_EVENT_OPEN, libc::SYS_perf_event_open as u32);
        assert_eq!(NR_BPF, libc::SYS_bpf as u32);
        assert_eq!(NR_REBOOT, libc::SYS_reboot as u32);
        assert_eq!(NR_SWAPON, libc::SYS_swapon as u32);
        assert_eq!(NR_SWAPOFF, libc::SYS_swapoff as u32);
    }

    #[test]
    fn socket_policy_keeps_socket_targets_and_changes_family_jumps() {
        for program in [
            build_program(SocketPolicy::UnixOnly),
            build_program(SocketPolicy::UnixAndIp),
        ] {
            assert_eq!(program.len(), 6 + 2 + HARDENING_SYSCALLS.len() + 2 + 6);
            for syscall in [NR_SOCKET, NR_SOCKETPAIR] {
                let (index, branch) = program
                    .iter()
                    .enumerate()
                    .find(|(_, instruction)| {
                        instruction.code == BPF_JMP_JEQ_K && instruction.k == syscall
                    })
                    .expect("socket syscall branch");
                let target = index + 1 + branch.jt as usize;
                assert_eq!(program[target].code, BPF_LD_BPF_W_BPF_ABS);
                assert_eq!(program[target].k, 16, "socket branch must inspect args[0]");
            }
        }
    }

    fn eval(program: &[SockFilter], syscall: u32, family: u32) -> u32 {
        let mut pc = 0usize;
        let mut accumulator = 0u32;
        loop {
            let instruction = &program[pc];
            match instruction.code {
                BPF_LD_BPF_W_BPF_ABS => {
                    accumulator = match instruction.k {
                        0 => syscall,
                        4 => native_audit_arch(),
                        16 => family,
                        offset => panic!("unexpected load offset {offset}"),
                    };
                    pc += 1;
                }
                BPF_JMP_JEQ_K => {
                    pc += if accumulator == instruction.k {
                        instruction.jt as usize + 1
                    } else {
                        instruction.jf as usize + 1
                    };
                }
                BPF_JMP_JSET_K => {
                    pc += if accumulator & instruction.k != 0 {
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

    #[test]
    fn hardening_syscalls_return_eperm_in_all_socket_policies() {
        let denied = SECCOMP_RET_ERRNO | libc::EPERM as u32;
        for program in [
            build_program(SocketPolicy::UnixOnly),
            build_program(SocketPolicy::UnixAndIp),
        ] {
            for syscall in HARDENING_SYSCALLS {
                assert_eq!(eval(&program, *syscall, AF_UNIX), denied);
            }
        }
    }

    #[test]
    fn unix_only_policy_allows_only_af_unix() {
        let program = build_program(SocketPolicy::UnixOnly);
        let denied = SECCOMP_RET_ERRNO | EAFNOSUPPORT;
        let network_families = [
            libc::AF_UNSPEC as u32,
            AF_INET,
            AF_INET6,
            libc::AF_NETLINK as u32,
            libc::AF_VSOCK as u32,
            libc::AF_PACKET as u32,
        ];

        assert_eq!(eval(&program, NR_SOCKET, AF_UNIX), SECCOMP_RET_ALLOW);
        assert_eq!(eval(&program, NR_SOCKETPAIR, AF_UNIX), SECCOMP_RET_ALLOW);
        for family in network_families {
            assert_eq!(eval(&program, NR_SOCKET, family), denied);
            assert_eq!(eval(&program, NR_SOCKETPAIR, family), denied);
        }
    }

    #[test]
    fn unix_and_ip_policy_allows_only_unix_and_ip() {
        let program = build_program(SocketPolicy::UnixAndIp);
        let denied = SECCOMP_RET_ERRNO | EAFNOSUPPORT;

        for family in [AF_UNIX, AF_INET, AF_INET6] {
            assert_eq!(eval(&program, NR_SOCKET, family), SECCOMP_RET_ALLOW);
            assert_eq!(eval(&program, NR_SOCKETPAIR, family), SECCOMP_RET_ALLOW);
        }
        for family in [
            libc::AF_UNSPEC as u32,
            libc::AF_NETLINK as u32,
            libc::AF_VSOCK as u32,
            libc::AF_PACKET as u32,
            38, // AF_ALG
            44, // AF_XDP
        ] {
            assert_eq!(eval(&program, NR_SOCKET, family), denied);
            assert_eq!(eval(&program, NR_SOCKETPAIR, family), denied);
        }

        // The allowlist relay needs ordinary IP sockets, but host-facing and
        // kernel-control families remain fail-closed.
    }

    #[test]
    fn x32_abi_is_killed_before_syscall_comparisons() {
        for program in [
            build_program(SocketPolicy::UnixOnly),
            build_program(SocketPolicy::UnixAndIp),
        ] {
            assert_eq!(program[4].code, BPF_JMP_JSET_K);
            assert_eq!(program[4].k, X32_SYSCALL_BIT);
            assert_eq!(program[4].jt, 0);
            assert_eq!(program[4].jf, 1);
            assert_eq!(program[5].k, SECCOMP_RET_KILL_PROCESS);
            assert_eq!(
                eval(&program, NR_SOCKET | X32_SYSCALL_BIT, AF_UNIX),
                SECCOMP_RET_KILL_PROCESS
            );
        }
    }

    #[test]
    fn all_conditional_jump_offsets_stay_in_program() {
        for program in [
            build_program(SocketPolicy::UnixOnly),
            build_program(SocketPolicy::UnixAndIp),
        ] {
            let denied = SECCOMP_RET_ERRNO | libc::EPERM as u32;
            for syscall in HARDENING_SYSCALLS {
                let (idx, instruction) = program
                    .iter()
                    .enumerate()
                    .find(|(_, instruction)| {
                        instruction.code == BPF_JMP_JEQ_K && instruction.k == *syscall
                    })
                    .expect("every hardening syscall must have a filter branch");
                let target = idx + 1 + instruction.jt as usize;
                assert_eq!(program[target].k, denied);
            }
            for (idx, instruction) in program.iter().enumerate() {
                if instruction.code != BPF_JMP_JEQ_K && instruction.code != BPF_JMP_JSET_K {
                    continue;
                }
                let true_target = idx + 1 + instruction.jt as usize;
                let false_target = idx + 1 + instruction.jf as usize;
                assert!(true_target < program.len());
                assert!(false_target < program.len());
            }
        }
    }

    #[test]
    fn foreign_arch_is_fail_closed() {
        assert_eq!(
            build_program(SocketPolicy::UnixOnly)[2].k,
            SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn aarch64_audit_arch_is_little_endian() {
        assert_eq!(native_audit_arch(), 0xC000_00B7);
    }
}
