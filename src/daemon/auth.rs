//! Authentication and security validation for vetto daemon and REST endpoints.
//!
//! Enforces:
//! 1. SO_PEERCRED / getpeereid Unix socket ownership verification (peer UID == euid).
//! 2. Bearer token cryptographic authentication for loopback HTTP endpoints.

use std::fs;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use anyhow::bail;
use anyhow::{Context, Result};
use rand_core::{OsRng, RngCore};

pub const TOKEN_FILENAME: &str = "token";

/// Returns the default daemon state directory (`~/.vetto/daemon`).
pub fn default_daemon_dir() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("Unable to resolve home directory for daemon state")?;
    Ok(home.join(".vetto").join("daemon"))
}

/// Ensures that the daemon directory exists with restrictive permissions (0700 on Unix).
pub fn ensure_daemon_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o700);
        let _ = fs::set_permissions(dir, perms);
    }
    Ok(())
}

/// Generates or loads the secret daemon authorization token (0600 on Unix).
pub fn ensure_daemon_token(dir: &Path) -> Result<String> {
    let token_path = dir.join(TOKEN_FILENAME);
    if token_path.is_file() {
        let raw = fs::read_to_string(&token_path).with_context(|| {
            format!("failed to read daemon token from {}", token_path.display())
        })?;
        let trimmed = raw.trim().to_string();
        if !trimmed.is_empty() {
            return Ok(trimmed);
        }
    }

    // Generate 32 cryptographically secure random bytes as hex token
    let mut random_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut random_bytes);
    let mut token = String::with_capacity(64);
    for b in random_bytes {
        use std::fmt::Write;
        let _ = write!(token, "{:02x}", b);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts
            .open(&token_path)
            .with_context(|| format!("failed to create token at {}", token_path.display()))?;
        use std::io::Write;
        file.write_all(token.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&token_path, token.as_bytes())
            .with_context(|| format!("failed to create token at {}", token_path.display()))?;
    }

    Ok(token)
}

/// Validates that a Unix socket connection originates from the same effective UID as the daemon.
#[cfg(unix)]
pub fn verify_peer_cred(stream: &std::os::unix::net::UnixStream) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut ucred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut ucred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if ret != 0 {
            bail!(
                "failed to get SO_PEERCRED on Unix socket: {}",
                std::io::Error::last_os_error()
            );
        }
        let my_uid = unsafe { libc::geteuid() };
        if ucred.uid != my_uid {
            bail!(
                "unauthorized peer UID {} (expected daemon owner UID {})",
                ucred.uid,
                my_uid
            );
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        use std::os::fd::AsRawFd;
        let fd = stream.as_raw_fd();
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        let ret = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        if ret != 0 {
            bail!(
                "failed to getpeereid on Unix socket: {}",
                std::io::Error::last_os_error()
            );
        }
        let my_uid = unsafe { libc::geteuid() };
        if uid != my_uid {
            bail!(
                "unauthorized peer UID {} (expected daemon owner UID {})",
                uid,
                my_uid
            );
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = stream;
        Ok(())
    }
}

#[cfg(not(unix))]
pub fn verify_peer_cred<T>(_stream: &T) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_generation_and_length() {
        let dir = std::env::temp_dir().join(format!("vetto-auth-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        ensure_daemon_dir(&dir).unwrap();

        let token = ensure_daemon_token(&dir).unwrap();
        assert_eq!(token.len(), 64);

        let token_again = ensure_daemon_token(&dir).unwrap();
        assert_eq!(token, token_again);

        let _ = fs::remove_dir_all(&dir);
    }
}
