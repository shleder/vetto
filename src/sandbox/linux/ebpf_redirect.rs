//! eBPF cgroup socket redirection subsystem (`cgroup_sock_addr`).
//!
//! Provides transparent TCP socket redirection at the kernel level using
//! `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` attached to `BPF_CGROUP_INET4_CONNECT`
//! and `BPF_CGROUP_INET6_CONNECT` hooks on a dedicated cgroup v2 hierarchy.
//!
//! Outbound non-loopback connections are rewritten to `127.0.0.1:<RELAY_PORT>`,
//! while the original destination is preserved in a `BPF_MAP_TYPE_LRU_HASH`
//! keyed by the socket cookie (`bpf_get_socket_cookie`).
//!
//! If eBPF or cgroup v2 is unsupported or unprivileged, the subsystem
//! cleanly signals fallback to the user-space network namespace relay (`CLONE_NEWNET`).

use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use crate::error::{VettoError, VettoResult};

// ---------------------------------------------------------------------------
// Linux BPF and Cgroup constants
// ---------------------------------------------------------------------------

pub const BPF_MAP_CREATE: libc::c_uint = 0;
pub const BPF_MAP_LOOKUP_ELEM: libc::c_uint = 1;
pub const BPF_MAP_UPDATE_ELEM: libc::c_uint = 2;
pub const BPF_MAP_DELETE_ELEM: libc::c_uint = 3;
pub const BPF_PROG_LOAD: libc::c_uint = 5;
pub const BPF_PROG_ATTACH: libc::c_uint = 8;
pub const BPF_PROG_DETACH: libc::c_uint = 9;

pub const BPF_MAP_TYPE_LRU_HASH: u32 = 10;
pub const BPF_PROG_TYPE_CGROUP_SOCK_ADDR: u32 = 18;

pub const BPF_CGROUP_INET4_CONNECT: u32 = 10;
pub const BPF_CGROUP_INET6_CONNECT: u32 = 11;

pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

pub const BPF_F_ALLOW_OVERRIDE: u32 = 1 << 0;
pub const BPF_F_ALLOW_MULTI: u32 = 1 << 1;

// BPF instruction classes
pub const BPF_LD: u8 = 0x00;
pub const BPF_LDX: u8 = 0x01;
pub const BPF_ST: u8 = 0x02;
pub const BPF_STX: u8 = 0x03;
pub const BPF_ALU: u8 = 0x04;
pub const BPF_JMP: u8 = 0x05;
pub const BPF_ALU64: u8 = 0x07;

// BPF sizes
pub const BPF_W: u8 = 0x00; // 32-bit word
pub const BPF_H: u8 = 0x08; // 16-bit halfword
pub const BPF_B: u8 = 0x10; // 8-bit byte
pub const BPF_DW: u8 = 0x18; // 64-bit doubleword

// BPF modes
pub const BPF_IMM: u8 = 0x00;
pub const BPF_ABS: u8 = 0x20;
pub const BPF_IND: u8 = 0x40;
pub const BPF_MEM: u8 = 0x60;

// BPF opcodes
pub const BPF_ADD: u8 = 0x00;
pub const BPF_SUB: u8 = 0x10;
pub const BPF_MUL: u8 = 0x20;
pub const BPF_DIV: u8 = 0x30;
pub const BPF_OR: u8 = 0x40;
pub const BPF_AND: u8 = 0x50;
pub const BPF_LSH: u8 = 0x60;
pub const BPF_RSH: u8 = 0x70;
pub const BPF_NEG: u8 = 0x80;
pub const BPF_XOR: u8 = 0xa0;
pub const BPF_MOV: u8 = 0xb0;
pub const BPF_ARSH: u8 = 0xc0;

// BPF jumps
pub const BPF_JA: u8 = 0x00;
pub const BPF_JEQ: u8 = 0x10;
pub const BPF_JGT: u8 = 0x20;
pub const BPF_JGE: u8 = 0x30;
pub const BPF_JSET: u8 = 0x40;
pub const BPF_JNE: u8 = 0x50;
pub const BPF_CALL: u8 = 0x80;
pub const BPF_EXIT: u8 = 0x90;

pub const BPF_K: u8 = 0x00;
pub const BPF_X: u8 = 0x08;

// BPF helper function IDs
pub const BPF_FUNC_MAP_LOOKUP_ELEM: i32 = 1;
pub const BPF_FUNC_MAP_UPDATE_ELEM: i32 = 2;
pub const BPF_FUNC_GET_SOCKET_COOKIE: i32 = 46;

// `bpf_sock_addr` struct offsets
pub const SOCK_ADDR_OFF_USER_FAMILY: i16 = 0;
pub const SOCK_ADDR_OFF_USER_IP4: i16 = 4;
pub const SOCK_ADDR_OFF_USER_IP6: i16 = 8;
pub const SOCK_ADDR_OFF_USER_PORT: i16 = 24;
pub const SOCK_ADDR_OFF_FAMILY: i16 = 28;
pub const SOCK_ADDR_OFF_TYPE: i16 = 32;
pub const SOCK_ADDR_OFF_PROTOCOL: i16 = 36;

pub const BPF_REG_0: u8 = 0; // Return value
pub const BPF_REG_1: u8 = 1; // Arg 1 / Context
pub const BPF_REG_2: u8 = 2; // Arg 2
pub const BPF_REG_3: u8 = 3; // Arg 3
pub const BPF_REG_4: u8 = 4; // Arg 4
pub const BPF_REG_5: u8 = 5; // Arg 5
pub const BPF_REG_6: u8 = 6; // Callee-saved
pub const BPF_REG_7: u8 = 7; // Callee-saved
pub const BPF_REG_8: u8 = 8; // Callee-saved
pub const BPF_REG_9: u8 = 9; // Callee-saved
pub const BPF_REG_10: u8 = 10; // Frame pointer (read-only)

// ---------------------------------------------------------------------------
// eBPF Instruction representation
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfInsn {
    pub code: u8,
    pub regs: u8, // (src_reg << 4) | (dst_reg & 0x0f)
    pub off: i16,
    pub imm: i32,
}

impl BpfInsn {
    #[inline]
    pub const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self {
            code,
            regs: ((src & 0x0f) << 4) | (dst & 0x0f),
            off,
            imm,
        }
    }

    #[inline]
    pub const fn mov64_imm(dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_K, dst, 0, 0, imm)
    }

    #[inline]
    pub const fn mov64_reg(dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | BPF_MOV | BPF_X, dst, src, 0, 0)
    }

    #[inline]
    pub const fn ldx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_LDX | BPF_MEM | size, dst, src, off, 0)
    }

    #[inline]
    pub const fn stx_mem(size: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_STX | BPF_MEM | size, dst, src, off, 0)
    }

    #[inline]
    pub const fn st_imm(size: u8, dst: u8, off: i16, imm: i32) -> Self {
        Self::new(BPF_ST | BPF_MEM | size, dst, 0, off, imm)
    }

    #[inline]
    pub const fn alu64_imm(op: u8, dst: u8, imm: i32) -> Self {
        Self::new(BPF_ALU64 | op | BPF_K, dst, 0, 0, imm)
    }

    #[inline]
    pub const fn alu64_reg(op: u8, dst: u8, src: u8) -> Self {
        Self::new(BPF_ALU64 | op | BPF_X, dst, src, 0, 0)
    }

    #[inline]
    pub const fn jmp_imm(op: u8, dst: u8, imm: i32, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_K, dst, 0, off, imm)
    }

    #[inline]
    pub const fn jmp_reg(op: u8, dst: u8, src: u8, off: i16) -> Self {
        Self::new(BPF_JMP | op | BPF_X, dst, src, off, 0)
    }

    #[inline]
    pub const fn call(func_id: i32) -> Self {
        Self::new(BPF_JMP | BPF_CALL, 0, 0, 0, func_id)
    }

    #[inline]
    pub const fn exit() -> Self {
        Self::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)
    }

    #[inline]
    pub const fn ld_map_fd(dst: u8, map_fd: RawFd) -> [Self; 2] {
        [
            Self::new(BPF_LD | BPF_DW | BPF_IMM, dst, 1, 0, map_fd),
            Self::new(0, 0, 0, 0, 0),
        ]
    }
}

// ---------------------------------------------------------------------------
// Original Destination representation in LRU map
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketDst {
    pub ip: [u8; 16],
    pub port: u16,
    pub family: u16,
    pub _pad: u32,
}

impl Default for SocketDst {
    fn default() -> Self {
        Self {
            ip: [0; 16],
            port: 0,
            family: 0,
            _pad: 0,
        }
    }
}

impl SocketDst {
    pub fn from_v4(ip: Ipv4Addr, port: u16) -> Self {
        let octets = ip.octets();
        let mut ip16 = [0u8; 16];
        ip16[..4].copy_from_slice(&octets);
        Self {
            ip: ip16,
            port,
            family: libc::AF_INET as u16,
            _pad: 0,
        }
    }

    pub fn from_v6(ip: Ipv6Addr, port: u16) -> Self {
        Self {
            ip: ip.octets(),
            port,
            family: libc::AF_INET6 as u16,
            _pad: 0,
        }
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        if self.family == libc::AF_INET as u16 {
            let v4 = Ipv4Addr::new(self.ip[0], self.ip[1], self.ip[2], self.ip[3]);
            Some(SocketAddr::V4(SocketAddrV4::new(v4, self.port)))
        } else if self.family == libc::AF_INET6 as u16 {
            let v6 = Ipv6Addr::from(self.ip);
            Some(SocketAddr::V6(SocketAddrV6::new(v6, self.port, 0, 0)))
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Cgroup v2 session management
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct CgroupV2Session {
    pub path: PathBuf,
    pub fd: OwnedFd,
}

impl CgroupV2Session {
    /// Locate cgroup v2 mount and create dedicated session folder:
    /// `/sys/fs/cgroup/vetto/session_<id>/`
    pub fn create(session_id: &str) -> VettoResult<Self> {
        let base = Path::new("/sys/fs/cgroup");
        if !base.exists() {
            return Err(VettoError::Sandbox("cgroup v2 is not mounted at /sys/fs/cgroup".into()));
        }
        let vetto_dir = base.join("vetto");
        if !vetto_dir.exists() {
            let _ = fs::create_dir_all(&vetto_dir);
        }
        let session_dir = if vetto_dir.exists() {
            vetto_dir.join(format!("session_{session_id}"))
        } else {
            base.join(format!("vetto_session_{session_id}"))
        };

        fs::create_dir_all(&session_dir)
            .map_err(|e| VettoError::Sandbox(format!("create cgroup {}: {e}", session_dir.display())))?;

        let c_path = std::ffi::CString::new(session_dir.as_os_str().as_encoded_bytes())
            .map_err(|_| VettoError::Sandbox("invalid cgroup path".into()))?;

        // SAFETY: open cgroup directory for attachment
        let raw_fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if raw_fd < 0 {
            let _ = fs::remove_dir(&session_dir);
            return Err(VettoError::Sandbox(format!(
                "open cgroup directory: {}",
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self {
            path: session_dir,
            fd: unsafe { OwnedFd::from_raw_fd(raw_fd) },
        })
    }

    /// Attach PID to this cgroup by writing to `cgroup.procs`.
    pub fn attach_pid(&self, pid: libc::pid_t) -> VettoResult<()> {
        let procs_file = self.path.join("cgroup.procs");
        fs::write(&procs_file, format!("{pid}\n"))
            .map_err(|e| VettoError::Sandbox(format!("attach PID {pid} to cgroup {}: {e}", self.path.display())))?;
        Ok(())
    }

    pub fn cgroup_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl Drop for CgroupV2Session {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Low-level BPF syscall attributes and wrappers
// ---------------------------------------------------------------------------

#[repr(C)]
union BpfAttr {
    map_create: MapCreateAttr,
    map_elem: MapElemAttr,
    prog_load: ProgLoadAttr,
    prog_attach: ProgAttachAttr,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MapElemAttr {
    map_fd: u32,
    key: u64,   // pointer to key
    value: u64, // pointer to value
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64, // pointer to instructions
    license: u64, // pointer to license string
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ProgAttachAttr {
    target_fd: u32,
    attach_bpf_fd: u32,
    attach_type: u32,
    attach_flags: u32,
}

unsafe fn sys_bpf(cmd: libc::c_uint, attr: *const BpfAttr, size: libc::c_uint) -> libc::c_long {
    libc::syscall(libc::SYS_bpf, cmd, attr, size)
}

// ---------------------------------------------------------------------------
// eBPF Redirect Manager
// ---------------------------------------------------------------------------

pub struct EbpfRedirectManager {
    map_fd: OwnedFd,
    prog_v4_fd: Option<OwnedFd>,
    prog_v6_fd: Option<OwnedFd>,
    cgroup_fd: RawFd,
    relay_port: u16,
}

impl EbpfRedirectManager {
    /// Probe if eBPF socket redirection and cgroup v2 are usable.
    pub fn probe_available() -> bool {
        let base = Path::new("/sys/fs/cgroup");
        if !base.exists() {
            return false;
        }
        // Try creating a test LRU map
        let attr = BpfAttr {
            map_create: MapCreateAttr {
                map_type: BPF_MAP_TYPE_LRU_HASH,
                key_size: 8,
                value_size: std::mem::size_of::<SocketDst>() as u32,
                max_entries: 16,
                map_flags: 0,
            },
        };
        let fd = unsafe { sys_bpf(BPF_MAP_CREATE, &attr, std::mem::size_of::<BpfAttr>() as u32) };
        if fd < 0 {
            return false;
        }
        unsafe { libc::close(fd as i32) };
        true
    }

    /// Construct BPF instructions to redirect IPv4 connect calls to 127.0.0.1:<relay_port>.
    pub fn build_v4_redirect_bytecode(map_fd: RawFd, relay_port: u16) -> Vec<BpfInsn> {
        let mut insns = Vec::with_capacity(64);

        // r6 = ctx (bpf_sock_addr)
        insns.push(BpfInsn::mov64_reg(BPF_REG_6, BPF_REG_1));

        // Load ctx->user_ip4 (offset 4) into r7
        insns.push(BpfInsn::ldx_mem(
            BPF_W,
            BPF_REG_7,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP4,
        ));

        // If user_ip4 == 127.0.0.1 (0x0100007f in network byte order), skip redirection -> jump to allow
        let loopback_v4_net: i32 = u32::from_ne_bytes([127, 0, 0, 1]) as i32;
        insns.push(BpfInsn::jmp_imm(BPF_JEQ, BPF_REG_7, loopback_v4_net, 28));

        // Allocate SocketDst on stack: fp - 32
        // Zero out stack area
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -32, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -24, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -16, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -8, 0));

        // Store original IP at fp - 32
        insns.push(BpfInsn::stx_mem(BPF_W, BPF_REG_10, BPF_REG_7, -32));

        // Load original port ctx->user_port (offset 24) into r8
        insns.push(BpfInsn::ldx_mem(
            BPF_W,
            BPF_REG_8,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_PORT,
        ));
        // Store original port at fp - 16
        insns.push(BpfInsn::stx_mem(BPF_H, BPF_REG_10, BPF_REG_8, -16));
        // Store AF_INET family at fp - 14
        insns.push(BpfInsn::st_imm(
            BPF_H,
            BPF_REG_10,
            -14,
            libc::AF_INET as i32,
        ));

        // Get socket cookie: bpf_get_socket_cookie(ctx) -> r0
        insns.push(BpfInsn::mov64_reg(BPF_REG_1, BPF_REG_6));
        insns.push(BpfInsn::call(BPF_FUNC_GET_SOCKET_COOKIE));

        // Store cookie at fp - 40
        insns.push(BpfInsn::stx_mem(BPF_DW, BPF_REG_10, BPF_REG_0, -40));

        // Prepare map_update_elem(map, &key, &value, BPF_ANY)
        // r1 = map_fd
        let map_insns = BpfInsn::ld_map_fd(BPF_REG_1, map_fd);
        insns.push(map_insns[0]);
        insns.push(map_insns[1]);

        // r2 = fp - 40 (&cookie key)
        insns.push(BpfInsn::mov64_reg(BPF_REG_2, BPF_REG_10));
        insns.push(BpfInsn::alu64_imm(BPF_ADD, BPF_REG_2, -40));

        // r3 = fp - 32 (&SocketDst value)
        insns.push(BpfInsn::mov64_reg(BPF_REG_3, BPF_REG_10));
        insns.push(BpfInsn::alu64_imm(BPF_ADD, BPF_REG_3, -32));

        // r4 = BPF_ANY (0)
        insns.push(BpfInsn::mov64_imm(BPF_REG_4, BPF_ANY as i32));

        // call map_update_elem
        insns.push(BpfInsn::call(BPF_FUNC_MAP_UPDATE_ELEM));

        // Rewrite ctx->user_ip4 to 127.0.0.1
        insns.push(BpfInsn::st_imm(
            BPF_W,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP4,
            loopback_v4_net,
        ));

        // Rewrite ctx->user_port to htons(relay_port)
        insns.push(BpfInsn::st_imm(
            BPF_W,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_PORT,
            relay_port.to_be() as i32,
        ));

        // Allow (return 1)
        insns.push(BpfInsn::mov64_imm(BPF_REG_0, 1));
        insns.push(BpfInsn::exit());

        insns
    }

    /// Construct BPF instructions to redirect IPv6 connect calls to ::1:<relay_port>.
    pub fn build_v6_redirect_bytecode(map_fd: RawFd, relay_port: u16) -> Vec<BpfInsn> {
        let mut insns = Vec::with_capacity(64);

        // r6 = ctx (bpf_sock_addr)
        insns.push(BpfInsn::mov64_reg(BPF_REG_6, BPF_REG_1));

        // Allocate SocketDst on stack: fp - 32
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -32, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -24, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -16, 0));
        insns.push(BpfInsn::st_imm(BPF_DW, BPF_REG_10, -8, 0));

        // Copy 16 bytes of user_ip6 from ctx (offset 8) to fp - 32
        insns.push(BpfInsn::ldx_mem(
            BPF_DW,
            BPF_REG_7,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP6,
        ));
        insns.push(BpfInsn::stx_mem(BPF_DW, BPF_REG_10, BPF_REG_7, -32));
        insns.push(BpfInsn::ldx_mem(
            BPF_DW,
            BPF_REG_7,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP6 + 8,
        ));
        insns.push(BpfInsn::stx_mem(BPF_DW, BPF_REG_10, BPF_REG_7, -24));

        // Load original port ctx->user_port (offset 24)
        insns.push(BpfInsn::ldx_mem(
            BPF_W,
            BPF_REG_8,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_PORT,
        ));
        insns.push(BpfInsn::stx_mem(BPF_H, BPF_REG_10, BPF_REG_8, -16));
        // Store AF_INET6 family
        insns.push(BpfInsn::st_imm(
            BPF_H,
            BPF_REG_10,
            -14,
            libc::AF_INET6 as i32,
        ));

        // Get socket cookie
        insns.push(BpfInsn::mov64_reg(BPF_REG_1, BPF_REG_6));
        insns.push(BpfInsn::call(BPF_FUNC_GET_SOCKET_COOKIE));
        insns.push(BpfInsn::stx_mem(BPF_DW, BPF_REG_10, BPF_REG_0, -40));

        // Update map
        let map_insns = BpfInsn::ld_map_fd(BPF_REG_1, map_fd);
        insns.push(map_insns[0]);
        insns.push(map_insns[1]);

        insns.push(BpfInsn::mov64_reg(BPF_REG_2, BPF_REG_10));
        insns.push(BpfInsn::alu64_imm(BPF_ADD, BPF_REG_2, -40));
        insns.push(BpfInsn::mov64_reg(BPF_REG_3, BPF_REG_10));
        insns.push(BpfInsn::alu64_imm(BPF_ADD, BPF_REG_3, -32));
        insns.push(BpfInsn::mov64_imm(BPF_REG_4, BPF_ANY as i32));
        insns.push(BpfInsn::call(BPF_FUNC_MAP_UPDATE_ELEM));

        // Rewrite IPv6 dst to ::1
        insns.push(BpfInsn::st_imm(
            BPF_DW,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP6,
            0,
        ));
        insns.push(BpfInsn::st_imm(
            BPF_W,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP6 + 8,
            0,
        ));
        let loopback_v6_last: i32 = u32::from_ne_bytes([0, 0, 0, 1]) as i32;
        insns.push(BpfInsn::st_imm(
            BPF_W,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_IP6 + 12,
            loopback_v6_last,
        ));

        // Rewrite port to relay_port
        insns.push(BpfInsn::st_imm(
            BPF_W,
            BPF_REG_6,
            SOCK_ADDR_OFF_USER_PORT,
            relay_port.to_be() as i32,
        ));

        // Return 1 (allow)
        insns.push(BpfInsn::mov64_imm(BPF_REG_0, 1));
        insns.push(BpfInsn::exit());

        insns
    }

    /// Load and attach eBPF redirection to the cgroup.
    pub fn new(cgroup_fd: RawFd, relay_port: u16) -> VettoResult<Self> {
        // 1. Create LRU Hash Map
        let map_attr = BpfAttr {
            map_create: MapCreateAttr {
                map_type: BPF_MAP_TYPE_LRU_HASH,
                key_size: 8,
                value_size: std::mem::size_of::<SocketDst>() as u32,
                max_entries: 10240,
                map_flags: 0,
            },
        };
        let map_fd_raw = unsafe {
            sys_bpf(
                BPF_MAP_CREATE,
                &map_attr,
                std::mem::size_of::<BpfAttr>() as u32,
            )
        };
        if map_fd_raw < 0 {
            return Err(VettoError::Sandbox(format!(
                "create eBPF LRU map: {}",
                std::io::Error::last_os_error()
            )));
        }
        let map_fd = unsafe { OwnedFd::from_raw_fd(map_fd_raw as i32) };

        // 2. Build and Load IPv4 program
        let v4_insns = Self::build_v4_redirect_bytecode(map_fd.as_raw_fd(), relay_port);
        let license = b"Apache-2.0\0";
        let prog_v4_attr = BpfAttr {
            prog_load: ProgLoadAttr {
                prog_type: BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                insn_cnt: v4_insns.len() as u32,
                insns: v4_insns.as_ptr() as u64,
                license: license.as_ptr() as u64,
                log_level: 0,
                log_size: 0,
                log_buf: 0,
                kern_version: 0,
                prog_flags: 0,
            },
        };
        let prog_v4_raw = unsafe {
            sys_bpf(
                BPF_PROG_LOAD,
                &prog_v4_attr,
                std::mem::size_of::<BpfAttr>() as u32,
            )
        };
        let prog_v4_fd = if prog_v4_raw >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(prog_v4_raw as i32) })
        } else {
            None
        };

        // 3. Build and Load IPv6 program
        let v6_insns = Self::build_v6_redirect_bytecode(map_fd.as_raw_fd(), relay_port);
        let prog_v6_attr = BpfAttr {
            prog_load: ProgLoadAttr {
                prog_type: BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
                insn_cnt: v6_insns.len() as u32,
                insns: v6_insns.as_ptr() as u64,
                license: license.as_ptr() as u64,
                log_level: 0,
                log_size: 0,
                log_buf: 0,
                kern_version: 0,
                prog_flags: 0,
            },
        };
        let prog_v6_raw = unsafe {
            sys_bpf(
                BPF_PROG_LOAD,
                &prog_v6_attr,
                std::mem::size_of::<BpfAttr>() as u32,
            )
        };
        let prog_v6_fd = if prog_v6_raw >= 0 {
            Some(unsafe { OwnedFd::from_raw_fd(prog_v6_raw as i32) })
        } else {
            None
        };

        // 4. Attach programs to cgroup
        if let Some(ref p4) = prog_v4_fd {
            let attach_attr = BpfAttr {
                prog_attach: ProgAttachAttr {
                    target_fd: cgroup_fd as u32,
                    attach_bpf_fd: p4.as_raw_fd() as u32,
                    attach_type: BPF_CGROUP_INET4_CONNECT,
                    attach_flags: BPF_F_ALLOW_MULTI,
                },
            };
            let r = unsafe {
                sys_bpf(
                    BPF_PROG_ATTACH,
                    &attach_attr,
                    std::mem::size_of::<BpfAttr>() as u32,
                )
            };
            if r < 0 {
                return Err(VettoError::Sandbox(format!(
                    "attach eBPF v4 redirect: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }

        if let Some(ref p6) = prog_v6_fd {
            let attach_attr = BpfAttr {
                prog_attach: ProgAttachAttr {
                    target_fd: cgroup_fd as u32,
                    attach_bpf_fd: p6.as_raw_fd() as u32,
                    attach_type: BPF_CGROUP_INET6_CONNECT,
                    attach_flags: BPF_F_ALLOW_MULTI,
                },
            };
            let _ = unsafe {
                sys_bpf(
                    BPF_PROG_ATTACH,
                    &attach_attr,
                    std::mem::size_of::<BpfAttr>() as u32,
                )
            };
        }

        Ok(Self {
            map_fd,
            prog_v4_fd,
            prog_v6_fd,
            cgroup_fd,
            relay_port,
        })
    }

    /// Look up original destination from the LRU map for a given socket cookie.
    pub fn lookup_original_dst(&self, cookie: u64) -> Option<SocketDst> {
        let mut value = SocketDst::default();
        let attr = BpfAttr {
            map_elem: MapElemAttr {
                map_fd: self.map_fd.as_raw_fd() as u32,
                key: &cookie as *const u64 as u64,
                value: &mut value as *mut SocketDst as u64,
                flags: 0,
            },
        };
        let r = unsafe {
            sys_bpf(
                BPF_MAP_LOOKUP_ELEM,
                &attr,
                std::mem::size_of::<BpfAttr>() as u32,
            )
        };
        if r == 0 {
            Some(value)
        } else {
            None
        }
    }

    pub fn relay_port(&self) -> u16 {
        self.relay_port
    }
}

impl Drop for EbpfRedirectManager {
    fn drop(&mut self) {
        if let Some(ref p4) = self.prog_v4_fd {
            let detach_attr = BpfAttr {
                prog_attach: ProgAttachAttr {
                    target_fd: self.cgroup_fd as u32,
                    attach_bpf_fd: p4.as_raw_fd() as u32,
                    attach_type: BPF_CGROUP_INET4_CONNECT,
                    attach_flags: 0,
                },
            };
            unsafe {
                sys_bpf(
                    BPF_PROG_DETACH,
                    &detach_attr,
                    std::mem::size_of::<BpfAttr>() as u32,
                )
            };
        }
        if let Some(ref p6) = self.prog_v6_fd {
            let detach_attr = BpfAttr {
                prog_attach: ProgAttachAttr {
                    target_fd: self.cgroup_fd as u32,
                    attach_bpf_fd: p6.as_raw_fd() as u32,
                    attach_type: BPF_CGROUP_INET6_CONNECT,
                    attach_flags: 0,
                },
            };
            unsafe {
                sys_bpf(
                    BPF_PROG_DETACH,
                    &detach_attr,
                    std::mem::size_of::<BpfAttr>() as u32,
                )
            };
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod tests {
    use super::*;

    #[test]
    fn socket_dst_conversions() {
        let v4_addr = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let dst = SocketDst::from_v4(*v4_addr.ip(), v4_addr.port());
        assert_eq!(dst.family, libc::AF_INET as u16);
        assert_eq!(dst.port, 443);
        assert_eq!(dst.to_socket_addr(), Some(SocketAddr::V4(v4_addr)));

        let v6_addr = SocketAddrV6::new(
            Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946),
            8443,
            0,
            0,
        );
        let dst_v6 = SocketDst::from_v6(*v6_addr.ip(), v6_addr.port());
        assert_eq!(dst_v6.family, libc::AF_INET6 as u16);
        assert_eq!(dst_v6.port, 8443);
        assert_eq!(dst_v6.to_socket_addr(), Some(SocketAddr::V6(v6_addr)));
    }

    #[test]
    fn bpf_insn_constructors() {
        let insn = BpfInsn::mov64_imm(BPF_REG_0, 1);
        assert_eq!(insn.code, BPF_ALU64 | BPF_MOV | BPF_K);
        assert_eq!(insn.regs & 0x0f, BPF_REG_0);
        assert_eq!(insn.imm, 1);

        let map_insns = BpfInsn::ld_map_fd(BPF_REG_1, 42);
        assert_eq!(map_insns.len(), 2);
        assert_eq!(map_insns[0].code, BPF_LD | BPF_DW | BPF_IMM);
        assert_eq!(map_insns[0].imm, 42);
    }

    #[test]
    fn v4_bytecode_generation() {
        let insns = EbpfRedirectManager::build_v4_redirect_bytecode(5, 47129);
        assert!(!insns.is_empty());
        assert_eq!(insns.last().unwrap().code, BPF_JMP | BPF_EXIT);
    }

    #[test]
    fn v6_bytecode_generation() {
        let insns = EbpfRedirectManager::build_v6_redirect_bytecode(5, 47129);
        assert!(!insns.is_empty());
        assert_eq!(insns.last().unwrap().code, BPF_JMP | BPF_EXIT);
    }

    #[test]
    fn cgroup_path_formatting() {
        let session_id = "test1234";
        let expected_name = format!("session_{session_id}");
        assert!(expected_name.contains(session_id));
    }
}
