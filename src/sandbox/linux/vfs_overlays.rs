use std::path::Path;

use super::mounts;
use crate::error::{VettoError, VettoResult};

/// Set up a Copy-on-Write overlay using overlayfs.
pub fn setup_cow_overlay(
    lower: &Path,
    upper: &Path,
    work: &Path,
    target: &Path,
) -> VettoResult<()> {
    let lower_str = lower
        .to_str()
        .ok_or_else(|| VettoError::Mount("invalid lower".into()))?;
    let upper_str = upper
        .to_str()
        .ok_or_else(|| VettoError::Mount("invalid upper".into()))?;
    let work_str = work
        .to_str()
        .ok_or_else(|| VettoError::Mount("invalid work".into()))?;

    let options = format!(
        "lowerdir={},upperdir={},workdir={}\0",
        lower_str, upper_str, work_str
    );

    let dst = std::ffi::CString::new(target.as_os_str().as_encoded_bytes())
        .map_err(|_| VettoError::Mount("NUL in path".into()))?;

    // SAFETY: flags and options
    if unsafe {
        libc::mount(
            b"overlay\0".as_ptr() as *const libc::c_char,
            dst.as_ptr(),
            b"overlay\0".as_ptr() as *const libc::c_char,
            0,
            options.as_ptr().cast(),
        )
    } != 0
    {
        return Err(VettoError::Mount(format!(
            "cow overlay mount failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    Ok(())
}

/// Mask ~/.ssh and .env via tmpfs.
pub fn mask_ssh_and_env(home: &Path, project_root: Option<&Path>) -> VettoResult<()> {
    let ssh_dir = home.join(".ssh");
    if ssh_dir.exists() {
        let _ = mounts::mask_path(&ssh_dir, ssh_dir.is_dir());
    }

    let home_env = home.join(".env");
    if home_env.exists() {
        let _ = mounts::mask_path(&home_env, home_env.is_dir());
    }

    if let Some(root) = project_root {
        let proj_env = root.join(".env");
        if proj_env.exists() {
            let _ = mounts::mask_path(&proj_env, proj_env.is_dir());
        }
    }

    Ok(())
}
