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

/// Mask ~/.ssh, ~/.aws, ~/.gnupg, and .env via read-only tmpfs / devnull (INV-08).
pub fn mask_ssh_and_env(home: &Path, project_root: Option<&Path>) -> VettoResult<()> {
    mask_mandatory_secrets(home, project_root)
}

/// Mandatory secret masking for ~/.ssh, ~/.aws, ~/.gnupg, and .env (INV-08).
/// Directories are masked using read-only mode 0000 tmpfs overlays.
pub fn mask_mandatory_secrets(home: &Path, project_root: Option<&Path>) -> VettoResult<()> {
    let mandatory_dirs = [".ssh", ".aws", ".gnupg"];
    for dir_name in mandatory_dirs {
        let dir_path = home.join(dir_name);
        if dir_path.exists() {
            mounts::mask_path(&dir_path, dir_path.is_dir())?;
        }
    }

    let home_env = home.join(".env");
    if home_env.exists() {
        mounts::mask_path(&home_env, home_env.is_dir())?;
    }

    if let Some(root) = project_root {
        let proj_env = root.join(".env");
        if proj_env.exists() {
            mounts::mask_path(&proj_env, proj_env.is_dir())?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_mandatory_secrets_handles_absent_paths() {
        let nonexistent = Path::new("/tmp/nonexistent-vetto-test-home-xyz");
        assert!(mask_mandatory_secrets(nonexistent, None).is_ok());
        assert!(mask_ssh_and_env(nonexistent, None).is_ok());
    }
}
