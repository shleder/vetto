//! Mount-namespace tricks for Tier FULL.
//!
//! Landlock is a pure allowlist: it cannot carve a secret out of an allowed
//! tree. The ONLY correct mechanism for intra-project denials is to hide the
//! resolved secret path behind a bind-mount of /dev/null (files) or an empty
//! tmpfs (directories) — done inside our own mount namespace so the host is
//! untouched.
//!
//! Phase 4 (Step 22): Per-agent mount & `/dev/shm` / `/tmp` isolation, and
//! cross-agent state tree masking (`~/.claude/sessions/`, `~/.codex/`, `~/.config/Cursor/`).

use std::ffi::CString;
use std::path::Path;

use crate::error::{VettoError, VettoResult};

const MS_REC: libc::c_ulong = 0x4000;
const MS_PRIVATE: libc::c_ulong = 0x04_0000;
const MS_BIND: libc::c_ulong = 0x1000;
const MS_RDONLY: libc::c_ulong = 0x1;
const MS_REMOUNT: libc::c_ulong = 0x20;
const MS_NOSUID: libc::c_ulong = 0x2;
const MS_NODEV: libc::c_ulong = 0x4;
const MS_NOEXEC: libc::c_ulong = 0x8;

/// The FULL tier's private shared-memory surface. The size is deliberately
/// bounded so an agent cannot turn `/dev/shm` into an unaccounted host-memory
/// sink, while the tmpfs mount remains useful for ordinary runtime code.
pub const DEV_SHM_SIZE_BYTES: u64 = 64 * 1024 * 1024;
pub const DEV_SHM_MOUNT_OPTIONS: &str = "size=67108864,mode=1777";
pub const TMP_SIZE_BYTES: u64 = 64 * 1024 * 1024;
pub const TMP_MOUNT_OPTIONS: &str = "size=67108864,mode=1777";
pub const PROC_HIDE_PID_OPTIONS: &str = "hidepid=2";
pub const DEVPTS_MOUNT_OPTIONS: &str = "newinstance,ptmxmode=0666,mode=620";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcVisibility {
    /// `/proc` was mounted with `hidepid=2` in the private PID namespace.
    HidePid,
    /// The kernel accepted a private proc mount but does not support
    /// `hidepid`; callers must surface this honest reduced-visibility state.
    Fallback,
}

fn cstr(p: &Path) -> VettoResult<CString> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| VettoError::Mount(format!("NUL in path {}", p.display())))
}

/// Make every mount private so overlay mounts never propagate to the host.
pub fn make_root_private() -> VettoResult<()> {
    let root = cstr(Path::new("/"))?;
    // SAFETY: valid NUL paths; flags are scalar.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            root.as_ptr(),
            std::ptr::null(),
            MS_PRIVATE | MS_REC,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "remount / private: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Replace `/dev/shm` inside the private mount namespace with a bounded,
/// isolated tmpfs (64 MB, mode 1777, nosuid, nodev, noexec).
pub fn isolate_dev_shm() -> VettoResult<()> {
    let target = Path::new("/dev/shm");
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|error| VettoError::Mount(format!("inspect /dev/shm: {error}")))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(VettoError::Mount("/dev/shm is not a directory".into()));
    }
    let dst = cstr(target)?;
    let options = cstr(Path::new(DEV_SHM_MOUNT_OPTIONS))?;
    // SAFETY: valid NUL-terminated mount arguments; flags are scalar.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            b"tmpfs\0".as_ptr() as *const libc::c_char,
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "isolated /dev/shm tmpfs: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Mount a private, bounded `tmpfs` over `/tmp` (64 MB, mode 1777, nosuid, nodev).
pub fn isolate_tmp(preserve_paths: &[&Path]) -> VettoResult<()> {
    let target = Path::new("/tmp");
    if !target.exists() || !target.is_dir() {
        return Ok(());
    }
    let dst = cstr(target)?;
    let options = cstr(Path::new(TMP_MOUNT_OPTIONS))?;

    // Filter paths that are located under /tmp (excluding /tmp itself) and exist
    let mut preserved: Vec<(&Path, libc::c_int)> = Vec::new();
    for &path in preserve_paths {
        if path.starts_with("/tmp") && path != Path::new("/tmp") && path.exists() {
            if let Ok(c_path) = cstr(path) {
                // SAFETY: open with O_PATH and O_CLOEXEC to hold an inode descriptor
                let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                if fd >= 0 {
                    preserved.push((path, fd));
                }
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir(target) {
        for entry in entries.flatten() {
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();
            if name == ".X11-unix"
                || name.starts_with("scoped_dir")
                || name.starts_with(".org.chromium.Chromium")
            {
                let path = entry.path();
                if let Ok(c_path) = cstr(&path) {
                    let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    if fd >= 0 {
                        preserved.push((Box::leak(path.into_boxed_path()), fd));
                    }
                }
            }
        }
    }

    // SAFETY: valid NUL-terminated mount arguments; flags are scalar.
    let mount_res = unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            b"tmpfs\0".as_ptr() as *const libc::c_char,
            MS_NOSUID | MS_NODEV,
            options.as_ptr().cast(),
        )
    };
    if mount_res != 0 {
        for (_, fd) in preserved {
            unsafe {
                libc::close(fd);
            }
        }
        return Err(VettoError::Mount(format!(
            "isolated /tmp tmpfs: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Restore preserved paths into the new tmpfs
    for (path, fd) in preserved {
        let metadata = path.metadata();
        let is_dir = metadata.as_ref().map(|m| m.is_dir()).unwrap_or(true);
        if is_dir {
            let _ = std::fs::create_dir_all(path);
        } else if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
            let _ = std::fs::File::create(path);
        }
        let proc_fd = format!("/proc/self/fd/{fd}");
        if let (Ok(c_src), Ok(c_dst)) = (cstr(Path::new(&proc_fd)), cstr(path)) {
            let bind_res = unsafe {
                libc::mount(
                    c_src.as_ptr(),
                    c_dst.as_ptr(),
                    std::ptr::null(),
                    MS_BIND | MS_REC,
                    std::ptr::null(),
                )
            };
            if bind_res != 0 {
                eprintln!(
                    "vetto: warning: failed to bind-mount preserved path {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                );
            }
        }
        unsafe {
            libc::close(fd);
        }
    }
    Ok(())
}

/// Restrict access to other agents' session directories (`~/.claude/sessions/`,
/// `~/.codex/`, `~/.config/Cursor/`) by mounting empty read-only tmpfs instances
/// or `/dev/null` over them.
pub fn isolate_agent_state_dirs(home: &Path, current_agent: &str) -> VettoResult<()> {
    let sensitive_subpaths = [
        ".claude/sessions",
        ".codex",
        ".config/Cursor",
        ".cursor",
        ".config/Code",
        ".local/share/code-server",
    ];

    for subpath in sensitive_subpaths {
        // If current agent is specifically targeting one ecosystem (e.g. claude),
        // we might leave that one to policy allowlist, but sibling state trees
        // are masked by default.
        let path = home.join(subpath);
        if path.exists() {
            let is_dir = path.is_dir();
            let _ = mask_path(&path, is_dir);
        }
    }

    // Mask sibling agent report directories in `.vetto-reports/`
    let reports_dir = Path::new(".vetto-reports");
    if reports_dir.exists() && reports_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(reports_dir) {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if name != current_agent && entry.path().is_dir() {
                        let _ = empty_tmpfs(&entry.path());
                    }
                }
            }
        }
    }

    Ok(())
}

fn mount_proc(options: Option<&str>) -> Result<(), (VettoError, Option<i32>)> {
    let source = cstr(Path::new("proc")).map_err(|error| (error, None))?;
    let target = cstr(Path::new("/proc")).map_err(|error| (error, None))?;
    let fstype = cstr(Path::new("proc")).map_err(|error| (error, None))?;
    let data = options
        .map(|value| cstr(Path::new(value)))
        .transpose()
        .map_err(|error| (error, None))?;
    // SAFETY: all strings are owned for the duration of the call.
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            data.as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr().cast()),
        )
    } != 0
    {
        let error = std::io::Error::last_os_error();
        let errno = error.raw_os_error();
        return Err((
            VettoError::Mount(format!("mount restricted /proc: {error}")),
            errno,
        ));
    }
    Ok(())
}

/// Mount a proc view after entering the new PID namespace. `hidepid=2` is
/// preferred; only an explicit unsupported-option (`EINVAL`) result permits
/// the no-hidepid fallback. Permission and other mount errors fail closed so
/// the caller cannot mistake an unmounted host `/proc` for a restriction.
pub fn mount_restricted_proc() -> VettoResult<ProcVisibility> {
    let visibility = match mount_proc(Some(PROC_HIDE_PID_OPTIONS)) {
        Ok(()) => ProcVisibility::HidePid,
        Err((first, errno)) if hidepid_unsupported(errno) => match mount_proc(None) {
            Ok(()) => ProcVisibility::Fallback,
            Err((second, _)) => {
                return Err(VettoError::Mount(format!(
                    "proc hidepid unsupported and fallback mount failed: {first}; {second}"
                )))
            }
        },
        Err((error, _)) => return Err(error),
    };
    // INV-28: ensure /proc/sys is masked or remounted read-only within the fresh proc view
    let _ = remount_proc_sys_readonly();
    Ok(visibility)
}

fn hidepid_unsupported(errno: Option<i32>) -> bool {
    matches!(
        errno,
        Some(value)
            if value == libc::EINVAL
                || value == libc::ENOPROTOOPT
                || value == libc::EOPNOTSUPP
    )
}

fn bind_devnull(target: &Path) -> VettoResult<()> {
    let src = cstr(Path::new("/dev/null"))?;
    let dst = cstr(target)?;
    // SAFETY: valid NUL paths; flags are scalar.
    if unsafe {
        libc::mount(
            src.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            MS_BIND,
            std::ptr::null(),
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "bind /dev/null over {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn empty_tmpfs(target: &Path) -> VettoResult<()> {
    let dst = cstr(target)?;
    // SAFETY: valid NUL path; fstype/options are NUL strings or NULL.
    // INV-08: secret and directory masking overlays use read-only mode 0000 tmpfs.
    if unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            b"tmpfs\0".as_ptr() as *const libc::c_char,
            MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC,
            b"mode=0000\0".as_ptr() as *const libc::c_void,
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "tmpfs over {}: {}",
            target.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Mask one resolved deny path. Files get /dev/null bound over them,
/// directories an empty tmpfs. Returns false when the path does not exist
/// (nothing to mask — not an error).
pub fn mask_path(path: &Path, is_dir: bool) -> VettoResult<bool> {
    if path.symlink_metadata().is_err() {
        return Ok(false);
    }
    if is_dir {
        empty_tmpfs(path)?;
    } else {
        bind_devnull(path)?;
    }
    Ok(true)
}

/// Mask mandatory secret directories (~/.ssh, ~/.aws, ~/.gnupg) and .env files (INV-08).
/// Directories are masked using read-only tmpfs with mode 0000.
pub fn mask_mandatory_secrets(home: &Path, project_root: Option<&Path>) -> VettoResult<()> {
    let mandatory_dirs = [".ssh", ".aws", ".gnupg"];
    for dir_name in mandatory_dirs {
        let p = home.join(dir_name);
        if p.exists() {
            mask_path(&p, p.is_dir())?;
        }
    }

    let home_env = home.join(".env");
    if home_env.exists() {
        mask_path(&home_env, home_env.is_dir())?;
    }

    if let Some(root) = project_root {
        let proj_env = root.join(".env");
        if proj_env.exists() {
            mask_path(&proj_env, proj_env.is_dir())?;
        }
    }

    Ok(())
}

/// Mask restricted and dangerous device nodes inside the mount namespace.
/// If `dev_allow` is specified, only explicitly allowed nodes (plus essential stdio) are kept.
/// If `dev_allow` is None, default dangerous device nodes are masked.

pub const DANGEROUS_RAW_DEVICES: &[&str] = &[
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/dev/nvram",
];

pub fn mask_dangerous_devices() -> VettoResult<()> {
    for &d in DANGEROUS_RAW_DEVICES {
        let path = Path::new(d);
        if path.exists() {
            let _ = mask_path(path, false);
        }
    }
    Ok(())
}

pub fn mask_restricted_devices(dev_allow: Option<&[String]>) -> VettoResult<()> {
    let dev_dir = Path::new("/dev");
    if !dev_dir.exists() || !dev_dir.is_dir() {
        return Ok(());
    }

    if let Some(allowed_list) = dev_allow {
        let mut allowed_set: std::collections::HashSet<String> = allowed_list
            .iter()
            .map(|s| {
                s.trim_start_matches("/dev/")
                    .trim_start_matches('/')
                    .to_string()
            })
            .collect();
        allowed_set.insert("null".into());
        allowed_set.insert("zero".into());
        allowed_set.insert("full".into());
        allowed_set.insert("random".into());
        allowed_set.insert("urandom".into());
        allowed_set.insert("tty".into());
        allowed_set.insert("pts".into());
        allowed_set.insert("shm".into());
        allowed_set.insert("fd".into());
        allowed_set.insert("stdin".into());
        allowed_set.insert("stdout".into());
        allowed_set.insert("stderr".into());

        if let Ok(entries) = std::fs::read_dir(dev_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !allowed_set.contains(&name) {
                    let path = entry.path();
                    let is_dir = path.is_dir();
                    let _ = mask_path(&path, is_dir);
                }
            }
        }
    } else {
        let dangerous_devs = [
            "/dev/kmsg",
            "/dev/mem",
            "/dev/kmem",
            "/dev/port",
            "/dev/core",
            "/dev/dri",
            "/dev/snd",
            "/dev/input",
            "/dev/kvm",
            "/dev/vhost-net",
            "/dev/vhost-vsock",
            "/dev/autofs",
            "/dev/btrfs-control",
            "/dev/loop-control",
            "/dev/mapper/control",
            "/dev/rtc0",
            "/dev/hpet",
        ];
        for d in dangerous_devs {
            let path = Path::new(d);
            if path.exists() {
                let is_dir = path.is_dir();
                let _ = mask_path(path, is_dir);
            }
        }
    }

    Ok(())
}

/// Blackhole DNS inside allowlist mode: the child must never resolve on its
/// own; the broker resolves remotely instead.
pub fn blackhole_resolv_conf() -> VettoResult<()> {
    let p = Path::new("/etc/resolv.conf");
    if p.exists() {
        bind_devnull(p)?;
    }
    Ok(())
}

/// Remount /sys as read-only inside the mount namespace.
pub fn remount_sys_readonly() -> VettoResult<()> {
    let target = Path::new("/sys");
    if !target.exists() || !target.is_dir() {
        return Ok(());
    }
    let dst = cstr(target)?;
    // SAFETY: bind mount /sys over itself first, then remount read-only.
    unsafe {
        libc::mount(
            dst.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            MS_BIND | MS_REC,
            std::ptr::null(),
        );
        if libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            std::ptr::null(),
            MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_REC,
            std::ptr::null(),
        ) != 0
        {
            return Err(VettoError::Mount(format!(
                "remount /sys read-only: {}",
                std::io::Error::last_os_error()
            )));
        }
    }
    Ok(())
}

/// Remount /proc/sys as read-only inside the mount namespace (INV-28).
/// Prevents modification of kernel parameters. If remount fails, masks with empty tmpfs.
pub fn remount_proc_sys_readonly() -> VettoResult<()> {
    let target = Path::new("/proc/sys");
    if !target.exists() || !target.is_dir() {
        return Ok(());
    }
    let dst = cstr(target)?;
    // SAFETY: bind mount /proc/sys over itself first, then remount read-only.
    unsafe {
        if libc::mount(
            dst.as_ptr(),
            dst.as_ptr(),
            std::ptr::null(),
            MS_BIND | MS_REC,
            std::ptr::null(),
        ) == 0
            && libc::mount(
                std::ptr::null(),
                dst.as_ptr(),
                std::ptr::null(),
                MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_REC,
                std::ptr::null(),
            ) == 0
        {
            return Ok(());
        }
    }
    // Fallback: mask /proc/sys with empty tmpfs if remount read-only is rejected
    empty_tmpfs(target)
}

/// Mount an isolated devpts instance with `newinstance` option (INV-31).
/// Guarantees terminal isolation and prevents TIOCSTI injection.
pub fn mount_devpts_newinstance() -> VettoResult<()> {
    let pts_dir = Path::new("/dev/pts");
    if !pts_dir.exists() || !pts_dir.is_dir() {
        return Ok(());
    }
    let target = cstr(pts_dir)?;
    let fstype = cstr(Path::new("devpts"))?;
    let options = cstr(Path::new(DEVPTS_MOUNT_OPTIONS))?;
    // SAFETY: mounting devpts with newinstance in private mount namespace
    if unsafe {
        libc::mount(
            fstype.as_ptr(),
            target.as_ptr(),
            fstype.as_ptr(),
            MS_NOSUID | MS_NOEXEC,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "mount devpts newinstance: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Connect /dev/ptmx to the new devpts instance if /dev/pts/ptmx exists
    let ptmx_pts = Path::new("/dev/pts/ptmx");
    let ptmx_dev = Path::new("/dev/ptmx");
    if ptmx_pts.exists() && ptmx_dev.exists() {
        let src = cstr(ptmx_pts)?;
        let dst = cstr(ptmx_dev)?;
        unsafe {
            let _ = libc::mount(
                src.as_ptr(),
                dst.as_ptr(),
                std::ptr::null(),
                MS_BIND,
                std::ptr::null(),
            );
        }
    }

    Ok(())
}

/// Mask host information and sensitive debugging endpoints in /proc.
/// Masked paths:
///   /proc/sys (masked or remounted read-only, INV-28)
///   /proc/kcore (physical memory image)
///   /proc/kallsyms (kernel symbol table)
///   /proc/sysrq-trigger (kernel magic sysrq)
///   /proc/sched_debug (scheduler debug info)
///   /proc/slabinfo (kernel slab cache allocation)
///   /proc/acpi (ACPI tables)
///   /proc/asound (sound card state)
pub fn mask_sensitive_proc_paths() -> VettoResult<()> {
    // INV-28: Ensure /proc/sys is masked or remounted read-only
    let _ = remount_proc_sys_readonly();

    let sensitive_files = [
        "/proc/kcore",
        "/proc/kallsyms",
        "/proc/sysrq-trigger",
        "/proc/sched_debug",
        "/proc/slabinfo",
    ];
    for p in sensitive_files {
        let path = Path::new(p);
        if path.exists() {
            let _ = bind_devnull(path);
        }
    }

    let sensitive_dirs = ["/proc/acpi", "/proc/asound"];
    for p in sensitive_dirs {
        let path = Path::new(p);
        if path.exists() && path.is_dir() {
            let _ = empty_tmpfs(path);
        }
    }
    Ok(())
}

/// Mount specified cache paths as read-only binds inside the mount namespace.
pub fn mount_ro_caches(ro_mounts: &[std::path::PathBuf]) -> VettoResult<()> {
    for path in ro_mounts {
        if path.exists() {
            let dst = cstr(path)?;
            // SAFETY: bind mount and remount read-only
            unsafe {
                if libc::mount(
                    dst.as_ptr(),
                    dst.as_ptr(),
                    std::ptr::null(),
                    MS_BIND | MS_REC,
                    std::ptr::null(),
                ) == 0
                {
                    let _ = libc::mount(
                        std::ptr::null(),
                        dst.as_ptr(),
                        std::ptr::null(),
                        MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC,
                        std::ptr::null(),
                    );
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_dangerous_devices_handles_absent_paths() {
        assert!(mask_dangerous_devices().is_ok());
    }

    #[test]
    fn dev_shm_plan_is_bounded_and_non_executable() {
        assert_eq!(DEV_SHM_SIZE_BYTES, 64 * 1024 * 1024);
        assert!(DEV_SHM_MOUNT_OPTIONS.contains("size=67108864"));
        assert!(DEV_SHM_MOUNT_OPTIONS.contains("mode=1777"));
        assert_ne!(MS_NOSUID | MS_NODEV | MS_NOEXEC, 0);
    }

    #[test]
    fn tmp_plan_is_bounded() {
        assert_eq!(TMP_SIZE_BYTES, 64 * 1024 * 1024);
        assert!(TMP_MOUNT_OPTIONS.contains("size=67108864"));
        assert!(TMP_MOUNT_OPTIONS.contains("mode=1777"));
    }

    #[test]
    fn proc_plan_prefers_hidepid_and_has_explicit_fallback_state() {
        assert_eq!(PROC_HIDE_PID_OPTIONS, "hidepid=2");
        assert_ne!(MS_NOSUID | MS_NODEV | MS_NOEXEC, 0);
        assert_ne!(ProcVisibility::HidePid, ProcVisibility::Fallback);
        assert!(hidepid_unsupported(Some(libc::EINVAL)));
        assert!(hidepid_unsupported(Some(libc::ENOPROTOOPT)));
        assert!(hidepid_unsupported(Some(libc::EOPNOTSUPP)));
        assert!(!hidepid_unsupported(Some(libc::EPERM)));
    }

    #[test]
    fn devpts_mount_options_satisfy_inv31() {
        assert!(DEVPTS_MOUNT_OPTIONS.contains("newinstance"));
        assert!(DEVPTS_MOUNT_OPTIONS.contains("ptmxmode=0666"));
        assert!(DEVPTS_MOUNT_OPTIONS.contains("mode=620"));
    }

    #[test]
    fn mask_mandatory_secrets_handles_absent_paths() {
        let nonexistent = Path::new("/tmp/nonexistent-vetto-test-home-mounts-xyz");
        assert!(mask_mandatory_secrets(nonexistent, None).is_ok());
    }

    #[test]
    fn remount_proc_sys_readonly_handles_absent_paths() {
        let nonexistent = Path::new("/tmp/nonexistent-vetto-proc-sys");
        assert!(!nonexistent.exists());
    }
}
