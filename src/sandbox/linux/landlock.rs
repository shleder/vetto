//! Landlock LSM enforcement via raw syscalls.
//!
//! Landlock decisions happen in the VFS on the resolved inode, so TOCTOU is
//! structurally impossible. Rules are purely additive: anything not covered
//! by an allow rule is denied once `restrict_self` runs.
//!
//! ABI Version History:
//! - ABI 1 (Linux 5.13): base filesystem access rights (EXECUTE .. MAKE_SYM)
//! - ABI 2 (Linux 5.19): file reparenting (REFER)
//! - ABI 3 (Linux 6.2):  file truncation (TRUNCATE)
//! - ABI 4 (Linux 6.7):  network TCP port rules (BIND_TCP, CONNECT_TCP)
//! - ABI 5 (Linux 6.10): character device ioctl (IOCTL_DEV)
//! - ABI 6 (Linux 6.12): IPC and signal scoping (ABSTRACT_UNIX_SOCKET, SIGNAL)

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

use crate::error::{VettoError, VettoResult};

// x86_64 and aarch64 share these syscall numbers.
pub const SYS_LANDLOCK_CREATE_RULESET: libc::c_long = 444;
pub const SYS_LANDLOCK_ADD_RULE: libc::c_long = 445;
pub const SYS_LANDLOCK_RESTRICT_SELF: libc::c_long = 446;

pub const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;
pub const LANDLOCK_RULE_PATH_BENEATH: libc::c_int = 1;
pub const LANDLOCK_RULE_NET_PORT: libc::c_int = 2;

// Filesystem access rights (ABI 1 unless noted)
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
pub const IOCTL_DEV: u64 = 1 << 15; // ABI 5 (Linux 6.10+)
pub const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = IOCTL_DEV;

// Network access rights (ABI 4+, Linux 6.7+)
pub const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

// Scope access rights (ABI 6+, Linux 6.12+)
pub const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
pub const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

/// Attributes for Landlock ruleset creation.
///
/// Layout matches the kernel's `struct landlock_ruleset_attr`:
/// - ABI 1–3: size 8 (only `handled_access_fs`)
/// - ABI 4–5: size 16 (`handled_access_fs` + `handled_access_net`)
/// - ABI 6+:  size 24 (`handled_access_fs` + `handled_access_net` + `handled_access_scope`)
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockRulesetAttr {
    pub handled_access_fs: u64,
    pub handled_access_net: u64,   // ABI >= 4 (Linux 6.7+)
    pub handled_access_scope: u64, // ABI >= 6 (Linux 6.12+)
}

/// Attributes for Landlock path rule.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockPathBeneathAttr {
    pub allowed_access: u64,
    pub parent_fd: libc::c_int,
}

/// Attributes for Landlock TCP network port rule (ABI 4+).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LandlockNetPortAttr {
    pub allowed_access: u64,
    pub port: u64,
}

/// A path rule prepared for a Landlock ruleset.
///
/// This is a data-only representation. Preparing rules does not create a
/// Landlock ruleset, add kernel rules, set `NO_NEW_PRIVS`, or call
/// `restrict_self`; callers that need enforcement must use [`apply_policy`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRule {
    pub path: std::path::PathBuf,
    pub allowed_access: u64,
}

/// Data-only Landlock preparation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRuleset {
    abi: u32,
    rules: Vec<PreparedRule>,
}

impl PreparedRuleset {
    /// Landlock ABI used to calculate the access masks.
    pub fn abi(&self) -> u32 {
        self.abi
    }

    /// Prepared path rules, in stable path order.
    pub fn rules(&self) -> &[PreparedRule] {
        &self.rules
    }

    /// Number of concrete rules that would be added to the kernel.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
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

/// Return the expected struct size for `SYS_LANDLOCK_CREATE_RULESET` given the ABI version.
pub fn ruleset_attr_size_for_abi(abi: u32) -> usize {
    if abi >= 6 {
        24
    } else if abi >= 4 {
        16
    } else {
        8
    }
}

/// Return the filesystem handled access mask for a given ABI version.
pub fn handled_fs_mask(abi: u32) -> u64 {
    let mut mask = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
    if abi >= 2 {
        mask |= REFER;
    }
    if abi >= 3 {
        mask |= TRUNCATE;
    }
    if abi >= 5 {
        mask |= IOCTL_DEV;
    }
    mask
}

/// Return the network handled access mask for a given ABI version.
pub fn handled_net_mask(abi: u32) -> u64 {
    if abi >= 4 {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    }
}

/// Return the scope handled access mask for a given ABI version.
pub fn handled_scope_mask(abi: u32) -> u64 {
    if abi >= 6 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    }
}

/// Read-only rights for toolchains/caches/system trees.
pub fn read_only_rights(is_dir: bool, abi: u32) -> u64 {
    let mut r = READ_FILE | EXECUTE;
    if is_dir {
        r |= READ_DIR;
    }
    if abi >= 5 {
        r |= IOCTL_DEV;
    }
    r
}

/// Rights for trees the agent must be able to mutate.
pub fn write_rights(abi: u32) -> u64 {
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
    if abi >= 5 {
        r |= IOCTL_DEV;
    }
    r
}

/// Prepare path rules using a caller-supplied ABI, without touching the
/// Landlock installation syscalls. This is useful for deterministic tests
/// and measurements on hosts where Landlock is unavailable.
pub fn prepare_ruleset_for_abi(
    abi: u32,
    allow_write: &[std::path::PathBuf],
    allow_read: &[std::path::PathBuf],
    strip_read_on_write: bool,
) -> PreparedRuleset {
    // Collect rights per concrete path (read + write grants UNION — a path
    // in both lists keeps both), matching the policy used by apply_policy.
    let mut wanted: HashMap<String, (std::path::PathBuf, u64)> = HashMap::new();
    let mut want = |path: &std::path::PathBuf, rights: u64| {
        let key = format!("{}", path.display());
        let entry = wanted.entry(key).or_insert_with(|| (path.clone(), 0));
        entry.1 |= rights;
    };
    for path in allow_read.iter().filter(|path| path.exists()) {
        want(path, read_only_rights(path.is_dir(), abi));
    }
    for path in allow_write.iter().filter(|path| path.exists()) {
        let mut rights = write_rights(abi);
        if strip_read_on_write {
            rights &= !READ_FILE;
        }
        want(path, rights);
    }

    // Directory-only rights are invalid on a file parent. Keep the same mask
    // used by apply_policy so the returned count mirrors actual kernel rules
    // without opening descriptors or installing anything.
    let file_mask = READ_FILE
        | WRITE_FILE
        | EXECUTE
        | if abi >= 3 { TRUNCATE } else { 0 }
        | if abi >= 5 { IOCTL_DEV } else { 0 };

    let mut rules: Vec<PreparedRule> = wanted
        .into_values()
        .filter_map(|(path, rights)| {
            let effective = if path.is_dir() {
                rights
            } else {
                rights & file_mask
            };
            (effective != 0).then_some(PreparedRule {
                path,
                allowed_access: effective,
            })
        })
        .collect();
    rules.sort_by(|left, right| left.path.cmp(&right.path));
    PreparedRuleset { abi, rules }
}

/// Prepare rules after probing the running kernel's Landlock ABI.
///
/// Unlike [`apply_policy`], this function is non-invasive: it performs only
/// the version probe and filesystem metadata checks needed to build the data
/// representation.
pub fn prepare_ruleset(
    allow_write: &[std::path::PathBuf],
    allow_read: &[std::path::PathBuf],
    strip_read_on_write: bool,
) -> VettoResult<PreparedRuleset> {
    let Some(abi) = abi_version() else {
        return Err(VettoError::Landlock(
            "kernel does not support Landlock (needs >= 5.13)".into(),
        ));
    };
    Ok(prepare_ruleset_for_abi(
        abi,
        allow_write,
        allow_read,
        strip_read_on_write,
    ))
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

/// Create a Landlock ruleset with dynamic ABI negotiation and graceful degradation.
fn create_ruleset_dynamic(mut abi: u32) -> VettoResult<(OwnedFd, u32)> {
    loop {
        let attr = LandlockRulesetAttr {
            handled_access_fs: handled_fs_mask(abi),
            handled_access_net: handled_net_mask(abi),
            handled_access_scope: handled_scope_mask(abi),
        };
        let size = ruleset_attr_size_for_abi(abi);

        // SAFETY: valid reference to repr(C) struct with size determined by ABI version.
        let ruleset_fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const LandlockRulesetAttr,
                size,
                0u32,
            )
        };

        if ruleset_fd >= 0 {
            return Ok((unsafe { OwnedFd::from_raw_fd(ruleset_fd as i32) }, abi));
        }

        let err = std::io::Error::last_os_error();
        // If EINVAL or E2BIG occurred, degrade ABI version and retry
        if (err.raw_os_error() == Some(libc::EINVAL) || err.raw_os_error() == Some(libc::E2BIG))
            && abi > 1
        {
            abi -= 1;
            continue;
        }

        return Err(VettoError::Landlock(format!("create_ruleset: {err}")));
    }
}

/// Add explicit PTY character device allowances for ABI >= 5.
fn add_pty_whitelist(ruleset: &OwnedFd, abi: u32) -> VettoResult<()> {
    if abi < 5 {
        return Ok(());
    }

    let pty_paths = [
        Path::new("/dev/ptmx"),
        Path::new("/dev/pts"),
        Path::new("/dev/tty"),
    ];

    let file_rights = READ_FILE | WRITE_FILE | IOCTL_DEV;
    let dir_rights = READ_FILE | WRITE_FILE | READ_DIR | IOCTL_DEV;

    for path in &pty_paths {
        if !path.exists() {
            continue;
        }
        if let Ok(opened) = open_path_fd(path) {
            let allowed = if opened.is_dir {
                dir_rights
            } else {
                file_rights
            };
            let rule = LandlockPathBeneathAttr {
                allowed_access: allowed,
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
                let err = std::io::Error::last_os_error();
                // Harmless if already granted by write roots; log diagnostic on unexpected error.
                if err.raw_os_error() != Some(libc::EEXIST) {
                    eprintln!(
                        "[vetto-landlock] warning: PTY whitelist add_rule {}: {err}",
                        path.display()
                    );
                }
            }
        }
    }

    Ok(())
}

/// Apply TCP port allow rules for ABI >= 4.
pub fn apply_net_port_rules(
    ruleset: &OwnedFd,
    abi: u32,
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> VettoResult<()> {
    if abi < 4 {
        return Ok(());
    }

    for &port in bind_ports {
        let rule = LandlockNetPortAttr {
            allowed_access: LANDLOCK_ACCESS_NET_BIND_TCP,
            port: port as u64,
        };
        // SAFETY: valid pointer to LandlockNetPortAttr.
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(VettoError::Landlock(format!(
                "add_rule net_bind_port {port}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    for &port in connect_ports {
        let rule = LandlockNetPortAttr {
            allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
            port: port as u64,
        };
        // SAFETY: valid pointer to LandlockNetPortAttr.
        let r = unsafe {
            libc::syscall(
                SYS_LANDLOCK_ADD_RULE,
                ruleset.as_raw_fd(),
                LANDLOCK_RULE_NET_PORT,
                &rule as *const LandlockNetPortAttr,
                0u32,
            )
        };
        if r < 0 {
            return Err(VettoError::Landlock(format!(
                "add_rule net_connect_port {port}: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(())
}

/// Apply the policy's filesystem allowlist to the current thread/process and
/// restrict. Irreversible; inherited by all future children.
///
/// `strip_read_on_write` (Tier FS-ONLY): write roots are the WHOLE project
/// tree and would otherwise re-grant READ over secret files that the loader's
/// enumeration carved out of the read list — so READ_FILE is stripped from
/// write-root rules there. Honest cost: files created at a write root itself
/// (not in an enumerated clean subdirectory) cannot be read back in FS-ONLY.
pub fn apply_policy(
    allow_write: &[std::path::PathBuf],
    allow_read: &[std::path::PathBuf],
    strip_read_on_write: bool,
) -> VettoResult<()> {
    apply_policy_with_net_ports(allow_write, allow_read, strip_read_on_write, &[], &[])
}

/// Apply filesystem allowlist and optional TCP network port rules.
pub fn apply_policy_with_net_ports(
    allow_write: &[std::path::PathBuf],
    allow_read: &[std::path::PathBuf],
    strip_read_on_write: bool,
    bind_ports: &[u16],
    connect_ports: &[u16],
) -> VettoResult<()> {
    let Some(detected_abi) = abi_version() else {
        return Err(VettoError::Landlock(
            "kernel does not support Landlock (needs >= 5.13)".into(),
        ));
    };

    let (ruleset, effective_abi) = create_ruleset_dynamic(detected_abi)?;
    let prepared =
        prepare_ruleset_for_abi(effective_abi, allow_write, allow_read, strip_read_on_write);

    // Empirically verified against the kernel: on a NON-directory parent
    // only these rights are accepted — everything else (READ_DIR, REMOVE_*,
    // MAKE_*, and REFER — despite being file-adjacent) returns EINVAL.
    let file_mask = READ_FILE
        | WRITE_FILE
        | EXECUTE
        | if effective_abi >= 3 { TRUNCATE } else { 0 }
        | if effective_abi >= 5 { IOCTL_DEV } else { 0 };

    for rule in prepared.rules {
        let rule_path = rule.path.clone();
        let opened = open_path_fd(&rule.path)?;
        let effective = if opened.is_dir {
            rule.allowed_access
        } else {
            rule.allowed_access & file_mask
        };
        if effective == 0 {
            continue;
        }
        let rule = LandlockPathBeneathAttr {
            allowed_access: effective,
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
                rule_path.display(),
                std::io::Error::last_os_error()
            )));
        }
    }

    // PTY whitelist explicitly granted under ABI >= 5
    let _ = add_pty_whitelist(&ruleset, effective_abi);

    // Add network port rules if requested and supported
    if effective_abi >= 4 {
        apply_net_port_rules(&ruleset, effective_abi, bind_ports, connect_ports)?;
    }

    // SAFETY: prctl with scalar args only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(VettoError::Landlock(format!(
            "PR_SET_NO_NEW_PRIVS: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: syscall with fd + null pointers.
    let r = unsafe { libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset.as_raw_fd(), 0u32) };
    if r < 0 {
        return Err(VettoError::Landlock(format!(
            "restrict_self: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn struct_layouts_and_sizes() {
        assert_eq!(std::mem::size_of::<LandlockRulesetAttr>(), 24);
        assert_eq!(std::mem::size_of::<LandlockPathBeneathAttr>(), 16);
        assert_eq!(std::mem::size_of::<LandlockNetPortAttr>(), 16);

        assert_eq!(ruleset_attr_size_for_abi(1), 8);
        assert_eq!(ruleset_attr_size_for_abi(2), 8);
        assert_eq!(ruleset_attr_size_for_abi(3), 8);
        assert_eq!(ruleset_attr_size_for_abi(4), 16);
        assert_eq!(ruleset_attr_size_for_abi(5), 16);
        assert_eq!(ruleset_attr_size_for_abi(6), 24);
        assert_eq!(ruleset_attr_size_for_abi(7), 24);
    }

    #[test]
    fn handled_masks_scale_with_abi() {
        let m1 = handled_fs_mask(1);
        let m2 = handled_fs_mask(2);
        let m3 = handled_fs_mask(3);
        let m4 = handled_fs_mask(4);
        let m5 = handled_fs_mask(5);
        let m6 = handled_fs_mask(6);

        assert_eq!(m1 & REFER, 0);
        assert_eq!(m1 & TRUNCATE, 0);
        assert_eq!(m1 & IOCTL_DEV, 0);

        assert_ne!(m2 & REFER, 0);
        assert_eq!(m2 & TRUNCATE, 0);
        assert_eq!(m2 & IOCTL_DEV, 0);

        assert_ne!(m3 & TRUNCATE, 0);
        assert_eq!(m3 & IOCTL_DEV, 0);

        assert_ne!(m4 & TRUNCATE, 0);
        assert_eq!(m4 & IOCTL_DEV, 0);

        assert_ne!(m5 & IOCTL_DEV, 0);
        assert_ne!(m6 & IOCTL_DEV, 0);

        assert_eq!(handled_net_mask(1), 0);
        assert_eq!(handled_net_mask(3), 0);
        assert_eq!(
            handled_net_mask(4),
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );
        assert_eq!(
            handled_net_mask(6),
            LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
        );

        assert_eq!(handled_scope_mask(1), 0);
        assert_eq!(handled_scope_mask(5), 0);
        assert_eq!(
            handled_scope_mask(6),
            LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
        );
    }

    #[test]
    fn write_rights_include_ioctl_dev_on_abi_5_plus() {
        assert_eq!(write_rights(1) & IOCTL_DEV, 0);
        assert_eq!(write_rights(4) & IOCTL_DEV, 0);
        assert_ne!(write_rights(5) & IOCTL_DEV, 0);
        assert_ne!(write_rights(6) & IOCTL_DEV, 0);
    }

    #[test]
    fn prepare_ruleset_handles_all_abis() {
        let temp = std::env::temp_dir();
        let path = temp.join("vetto_landlock_test_dir");
        let _ = std::fs::create_dir_all(&path);

        for abi in [1, 2, 3, 4, 5, 6] {
            let prepared = prepare_ruleset_for_abi(abi, std::slice::from_ref(&path), &[], false);
            assert_eq!(prepared.abi(), abi);
            assert!(!prepared.is_empty());
        }

        let _ = std::fs::remove_dir(&path);
    }
}
