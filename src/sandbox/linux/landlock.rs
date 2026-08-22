//! Landlock LSM enforcement via raw syscalls.
//!
//! Landlock decisions happen in the VFS on the resolved inode, so TOCTOU is
//! structurally impossible. Rules are purely additive: anything not covered
//! by an allow rule is denied once `restrict_self` runs.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::error::{VettoError, VettoResult};

// x86_64 and aarch64 share these syscall numbers.
const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;

// fs access rights (ABI 1 unless noted)
pub const EXECUTE: u64 = 1 << 0;
pub const WRITE_FILE: u64 = 1 << 1;
pub const READ_FILE: u64 = 1 << 2;
pub const READ_DIR: u64 = 1 << 3;
pub const REMOVE_DIR: u64 = 1 << 4;
pub const REMOVE_FILE: u64 = 1 << 5;
pub const MAKE_CHAR: u64 = 1 << 6;
pub const MAKE_DIR: u64 = 1 << 7;
pub const MAKE_REG: u64 = 1 << 8;
pub const MAKE_SOCK: u64 = 1 << 9;
pub const MAKE_FIFO: u64 = 1 << 10;
pub const MAKE_BLOCK: u64 = 1 << 11;
pub const MAKE_SYM: u64 = 1 << 12;
pub const REFER: u64 = 1 << 13; // ABI 2
pub const TRUNCATE: u64 = 1 << 14; // ABI 3

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

/// Probe the highest Landlock ABI supported by the running kernel.
/// None => Landlock unavailable (kernel < 5.13 or disabled).
///
/// SAFETY: direct syscall; the NULL ruleset_attr pointer is the documented
/// version-probe form when LANDLOCK_CREATE_RULESET_VERSION is set.
pub fn abi_version() -> Option<u32> {
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if r <= 0 {
        None
    } else {
        Some(r as u32)
    }
}

fn handled_fs_mask(abi: u32) -> u64 {
    let mut mask =
        EXECUTE | WRITE_FILE | READ_FILE | READ_DIR | REMOVE_DIR | REMOVE_FILE | MAKE_CHAR
            | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;
    if abi >= 2 {
        mask |= REFER;
    }
    if abi >= 3 {
        mask |= TRUNCATE;
    }
    // IOCTL_DEV (ABI 4+) intentionally omitted from v0.1 handling to keep the
    // compat matrix small; kernels >=6.10 still enforce everything else.
    mask
}

/// Read-only rights for toolchains/caches/system trees.
fn read_only_rights(is_dir: bool, abi: u32) -> u64 {
    let mut r = READ_FILE | EXECUTE;
    if is_dir {
        r |= READ_DIR;
    }
    let _ = abi;
    r
}

/// Rights for trees the agent must be able to mutate.
fn write_rights(abi: u32) -> u64 {
    let mut r = read_only_rights(true, abi)
        | WRITE_FILE
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SYM
        | MAKE_FIFO
        | MAKE_SOCK
        | MAKE_CHAR
        | MAKE_BLOCK;
    if abi >= 2 {
        r |= REFER;
    }
    if abi >= 3 {
        r |= TRUNCATE;
    }
    r
}

struct OpenPath {
    _fd: OwnedFd,
    is_dir: bool,
}

fn open_path_fd(path: &Path) -> VettoResult<OpenPath> {
    let c = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|_| VettoError::Landlock(format!("NUL in path {}", path.display())))?;
    // SAFETY: c is a valid NUL-terminated string.
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(VettoError::Landlock(format!(
            "open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd + valid out-pointer.
    if unsafe { libc::fstat(owned.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(VettoError::Landlock(format!(
            "fstat {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: fstat initialized the value.
    let is_dir = unsafe { stat.assume_init() }.st_mode & libc::S_IFMT == libc::S_IFDIR;
    Ok(OpenPath { _fd: owned, is_dir })
}

/// Apply the policy's filesystem allowlist to the current thread/process and
/// restrict. Irreversible; inherited by all future children.
pub fn apply_policy(
    allow_write: &[std::path::PathBuf],
    allow_read: &[std::path::PathBuf],
) -> VettoResult<()> {
    let Some(abi) = abi_version() else {
        return Err(VettoError::Landlock(
            "kernel does not support Landlock (needs >= 5.13)".into(),
        ));
    };

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs_mask(abi),
    };
    // SAFETY: valid reference to a repr(C) struct of documented layout.
    let ruleset_fd = unsafe {
        libc::syscall(
            SYS_LANDLOCK_CREATE_RULESET,
            &attr as *const LandlockRulesetAttr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if ruleset_fd < 0 {
        return Err(VettoError::Landlock(format!(
            "create_ruleset: {}",
            std::io::Error::last_os_error()
        )));
    }
    let ruleset = unsafe { OwnedFd::from_raw_fd(ruleset_fd as i32) };

    // Dedup paths by canonical target to bound rule count.
    let mut seen: HashMap<String, bool> = HashMap::new();

    let mut add_rule = |path: &Path, rights: u64| -> VettoResult<()> {
        let key = format!("{}", path.display());
        let opened = open_path_fd(path)?;
        let is_dir = opened.is_dir;
        if seen.insert(key, is_dir).is_some() {
            return Ok(());
        }
        let rule = LandlockPathBeneathAttr {
            allowed_access: rights,
            parent_fd: opened._fd.as_raw_fd(),
        };
        // SAFETY: valid rule pointer referencing a live fd.
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_PATH_BENEATH,
                &rule as *const LandlockPathBeneathAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(VettoError::Landlock(format!(
                "add_rule {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    };

    // Profiles list paths that vary per machine; absent paths simply have
    // nothing to allow and are skipped (write roots were already validated
    // by the policy checker, so missing WRITE targets stay loud there).
    for p in allow_read.iter().filter(|p| p.exists()) {
        let is_dir = p.is_dir();
        add_rule(p, read_only_rights(is_dir, abi))?;
    }
    for p in allow_write.iter().filter(|p| p.exists()) {
        add_rule(p, write_rights(abi))?;
    }

    // SAFETY: prctl with scalar args only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(VettoError::Landlock(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: syscall with fd + null pointers.
    let r = unsafe {
        libc::syscall(
            SYS_LANDLOCK_RESTRICT_SELF,
            ruleset.as_raw_fd(),
            0u32,
        )
    };
    if r < 0 {
        return Err(VettoError::Landlock(format!(
            "restrict_self: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}
