//! Mount-namespace tricks for Tier FULL.
//!
//! Landlock is a pure allowlist: it cannot carve a secret out of an allowed
//! tree. The ONLY correct mechanism for intra-project denials is to hide the
//! resolved secret path behind a bind-mount of /dev/null (files) or an empty
//! tmpfs (directories) — done inside our own mount namespace so the host is
//! untouched.

use std::ffi::CString;
use std::path::Path;

use crate::error::{VettoError, VettoResult};

const MS_REC: libc::c_ulong = 0x4000;
const MS_PRIVATE: libc::c_ulong = 0x04_0000;
const MS_BIND: libc::c_ulong = 0x1000;
const MS_NOSUID: libc::c_ulong = 0x2;
const MS_NODEV: libc::c_ulong = 0x4;
const MS_NOEXEC: libc::c_ulong = 0x8;

fn cstr(p: &Path) -> VettoResult<CString> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|_| VettoError::Mount(format!("NUL in path {}", p.display())))
}

/// Make every mount private so overlay mounts never propagate to the host.
pub fn make_root_private() -> VettoResult<()> {
    let root = cstr(Path::new("/"))?;
    // SAFETY: valid NUL paths; flags are scalar.
    if unsafe { libc::mount(std::ptr::null(), root.as_ptr(), std::ptr::null(), MS_PRIVATE | MS_REC, std::ptr::null()) } != 0 {
        return Err(VettoError::Mount(format!(
            "remount / private: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn bind_devnull(target: &Path) -> VettoResult<()> {
    let src = cstr(Path::new("/dev/null"))?;
    let dst = cstr(target)?;
    // SAFETY: valid NUL paths; flags are scalar.
    if unsafe { libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(), MS_BIND, std::ptr::null()) } != 0 {
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
    if unsafe {
        libc::mount(
            std::ptr::null(),
            dst.as_ptr(),
            b"tmpfs\0".as_ptr() as *const libc::c_char,
            MS_NOSUID | MS_NODEV | MS_NOEXEC,
            b"mode=000\0".as_ptr() as *const libc::c_char,
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

/// Blackhole DNS inside allowlist mode: the child must never resolve on its
/// own; the broker resolves remotely instead.
pub fn blackhole_resolv_conf() -> VettoResult<()> {
    let p = Path::new("/etc/resolv.conf");
    if p.exists() {
        bind_devnull(p)?;
    }
    Ok(())
}
