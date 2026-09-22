use std::path::{Path, PathBuf};

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

/// Return potential dangerous Unix domain sockets that must be blocked/masked:
/// - Daemon sockets: `/var/run/docker.sock`, `/run/docker.sock`, `/run/podman/podman.sock`
/// - Per-user runtime sockets: `/run/user/{uid}/docker.sock`, `/run/user/{uid}/podman/podman.sock`
///   and gpg-agent sockets `/run/user/{uid}/gnupg/S.gpg-agent`, `/run/user/{uid}/gnupg/S.gpg-agent.ssh`
/// - `SSH_AUTH_SOCK` environment socket if configured.
pub fn get_dangerous_unix_sockets() -> Vec<PathBuf> {
    let mut sockets = Vec::new();

    sockets.push(PathBuf::from("/var/run/docker.sock"));
    sockets.push(PathBuf::from("/run/docker.sock"));
    sockets.push(PathBuf::from("/run/podman/podman.sock"));

    let mut uids = Vec::new();
    #[cfg(unix)]
    {
        // SAFETY: getuid has no failure mode and requires no privileges.
        let uid = unsafe { libc::getuid() };
        uids.push(uid.to_string());
    }
    if let Ok(sudo_uid) = std::env::var("SUDO_UID") {
        if !sudo_uid.is_empty() && !uids.contains(&sudo_uid) {
            uids.push(sudo_uid);
        }
    }
    if let Ok(env_uid) = std::env::var("UID") {
        if !env_uid.is_empty() && !uids.contains(&env_uid) {
            uids.push(env_uid);
        }
    }

    for uid in &uids {
        sockets.push(PathBuf::from(format!("/run/user/{uid}/docker.sock")));
        sockets.push(PathBuf::from(format!("/run/user/{uid}/podman/podman.sock")));
        sockets.push(PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent")));
        sockets.push(PathBuf::from(format!(
            "/run/user/{uid}/gnupg/S.gpg-agent.ssh"
        )));
    }

    if let Ok(ssh_sock) = std::env::var("SSH_AUTH_SOCK") {
        if !ssh_sock.is_empty() {
            sockets.push(PathBuf::from(ssh_sock));
        }
    }

    let mut deduped = Vec::new();
    for sock in sockets {
        if !deduped.contains(&sock) {
            deduped.push(sock);
        }
    }
    deduped
}

/// Mask caller-specified unix domain sockets with /dev/null bind mounts.
pub fn mask_unix_sockets(custom_sockets: &[PathBuf]) -> VettoResult<()> {
    for socket_path in custom_sockets {
        if socket_path.exists() {
            if let Err(e) = mounts::mask_path(socket_path, false) {
                if unsafe { libc::geteuid() } != 0
                    && (e.to_string().contains("Operation not permitted")
                        || e.to_string().contains("Permission denied"))
                {
                    tracing::warn!(
                        path = %socket_path.display(),
                        "skipping custom unix socket masking without privileges: {e}"
                    );
                } else {
                    return Err(e);
                }
            }
        }
    }
    Ok(())
}

/// Mandatory secret masking for ~/.ssh, ~/.aws, ~/.gnupg, and .env (INV-08).
/// Directories are masked using read-only mode 0000 tmpfs overlays.
/// Dangerous unix sockets are masked by bind mounting /dev/null.
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

    for socket_path in get_dangerous_unix_sockets() {
        if socket_path.exists() {
            if let Err(e) = mounts::mask_path(&socket_path, false) {
                if unsafe { libc::geteuid() } != 0
                    && (e.to_string().contains("Operation not permitted")
                        || e.to_string().contains("Permission denied"))
                {
                    tracing::warn!(
                        path = %socket_path.display(),
                        "skipping dangerous unix socket masking without privileges: {e}"
                    );
                } else {
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: test thread holding serialized lock
            unsafe { std::env::set_var(key, val) };
            Self { key, prev }
        }

        fn unset(key: &'static str) -> Self {
            let prev = std::env::var_os(key);
            // SAFETY: test thread holding serialized lock
            unsafe { std::env::remove_var(key) };
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.prev {
                Some(v) => unsafe { std::env::set_var(self.key, v) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[test]
    fn mask_mandatory_secrets_handles_absent_paths() {
        let nonexistent = Path::new("/tmp/nonexistent-vetto-test-home-xyz");
        assert!(mask_mandatory_secrets(nonexistent, None).is_ok());
        assert!(mask_ssh_and_env(nonexistent, None).is_ok());
    }

    #[test]
    fn test_get_dangerous_unix_sockets_contains_standard_sockets() {
        let sockets = get_dangerous_unix_sockets();
        assert!(sockets.contains(&PathBuf::from("/var/run/docker.sock")));
        assert!(sockets.contains(&PathBuf::from("/run/docker.sock")));
        assert!(sockets.contains(&PathBuf::from("/run/podman/podman.sock")));

        #[cfg(unix)]
        {
            let uid = unsafe { libc::getuid() };
            let user_docker = PathBuf::from(format!("/run/user/{uid}/docker.sock"));
            let user_podman = PathBuf::from(format!("/run/user/{uid}/podman/podman.sock"));
            let user_gpg = PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent"));
            let user_gpg_ssh = PathBuf::from(format!("/run/user/{uid}/gnupg/S.gpg-agent.ssh"));
            assert!(sockets.contains(&user_docker));
            assert!(sockets.contains(&user_podman));
            assert!(sockets.contains(&user_gpg));
            assert!(sockets.contains(&user_gpg_ssh));
        }
    }

    #[test]
    fn test_dangerous_unix_sockets_includes_ssh_auth_sock() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fake_sock = "/tmp/test-vetto-fake-ssh-agent.sock";
        let _guard = EnvVarGuard::set("SSH_AUTH_SOCK", fake_sock);

        let sockets = get_dangerous_unix_sockets();
        assert!(sockets.contains(&PathBuf::from(fake_sock)));
    }

    #[test]
    fn test_dangerous_unix_sockets_without_ssh_auth_sock() {
        let _lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvVarGuard::unset("SSH_AUTH_SOCK");

        let sockets = get_dangerous_unix_sockets();
        assert!(!sockets.contains(&PathBuf::from("/tmp/test-vetto-fake-ssh-agent.sock")));
    }

    #[test]
    fn test_mask_unix_sockets_handles_absent_paths() {
        let absent = vec![
            PathBuf::from("/tmp/nonexistent-vetto-sock1.sock"),
            PathBuf::from("/tmp/nonexistent-vetto-sock2.sock"),
        ];
        assert!(mask_unix_sockets(&absent).is_ok());
    }
}
