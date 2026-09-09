//! Host-owned positive-control channel (Stage 2).
//!
//! Why this channel is host-owned while env/HOME/stdio/exit-code are not:
//!
//! - The host creates a FIFO in a host-private temp dir (outside the fixture
//!   root, HOME and `VETTO_VNG_ROOT`) BEFORE spawn and holds the read end
//!   open across the spawn. The child receives the FIFO path plus a
//!   per-execution token as capabilities, but neither value is proof: proof
//!   is the ARRIVAL of the exact identity-bound token on the host-held read
//!   end before the deadline, verified by the pure [`crate::verify_ng::evidence::attest_control`].
//! - The child cannot create a new valid endpoint: the host reads only from
//!   its own FIFO. Files the child writes into HOME/fixture, stdout/stderr
//!   markers, env echoes and exit codes are never read as control — they
//!   stay `SELF_REPORT` or diagnostics.
//! - The token binds [`crate::verify_ng::evidence::ExecutionIdentity`]
//!   (scenario + session nonce + registry hash + frozen-spec hash), so bytes
//!   replayed from another session, scenario or registry fail verification.
//! - Only a successful verification mints
//!   [`crate::verify_ng::evidence::VerifiedControl`], and only that
//!   capability stamps a `HOST_FACT` control fact. There is no path from a
//!   child-supplied value to a verified fact.
//!
//! Honest ceilings (not false security):
//!
//! - Same-uid visibility is acknowledged: on direct-exec the child runs as
//!   the same user, so it can read its own env and find the FIFO path. That
//!   is the legitimate use (the staged, hash-verified payload answering the
//!   challenge), not a forge: a payload that answers AND violates still
//!   FAILs (violation dominates), a payload that answers with a mutated
//!   script is INCONCLUSIVE (payload integrity dominates), and answers from
//!   any other identity are rejected. What the channel rules out is control
//!   via any other medium (files, stdio, env echo, replay).
//! - The channel proves pipeline liveness, never containment. The runner
//!   assembles PASS-capable oracle input from it for `Aux` pipeline
//!   scenarios only; blocker categories stay INCONCLUSIVE/FAIL on
//!   direct-exec regardless of control.
//! - Non-Unix platforms have no channel here: creation fails, the run
//!   degrades to control-unobserved (INCONCLUSIVE, never PASS).
//!
//! I/O ownership: all OS work (mkfifo/open/read) lives in this module and
//! the runner. The oracle stays a pure decision function and only sees the
//! already-verified capability's stamped fact.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::evidence::ExecutionIdentity;

/// Child env carrying the FIFO path capability. A path, not proof.
pub const ENV_CONTROL_FIFO: &str = "VETTO_VNG_CONTROL_FIFO";
/// Child env carrying the per-execution control token capability. The token
/// in env alone proves nothing; only its arrival on the host-held FIFO end
/// counts, after exact verification.
pub const ENV_CONTROL_TOKEN: &str = "VETTO_VNG_CONTROL_TOKEN";
/// FIFO file name inside the host-private channel dir.
pub const FIFO_NAME: &str = "control.fifo";
/// Upper bound on one control message; anything larger fails closed.
pub const MAX_CONTROL_BYTES: usize = 256;
/// Budget for the post-termination control read.
pub const CONTROL_READ_BUDGET: Duration = Duration::from_secs(2);

/// Host end of one execution's control channel. Created before spawn, held
/// across it, verified once after collection, then dropped (removing the
/// host-private dir). Unix-only; see the non-Unix stub below.
#[cfg(unix)]
pub struct ControlChannel {
    dir: PathBuf,
    fifo: PathBuf,
    expected_token: String,
    reader: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl ControlChannel {
    /// Create the host-private dir + FIFO + expected token for `identity`.
    /// The read end is opened (nonblocking, cloexec) before returning, so a
    /// child open-for-write can never block the host and the host never
    /// blocks the child.
    pub fn create(identity: &ExecutionIdentity) -> std::io::Result<Self> {
        let channel_secret = format!(
            "{}{}",
            super::engine::new_nonce(),
            super::engine::new_nonce()
        );
        let expected_token = super::evidence::derive_control_token(&channel_secret, identity);
        // Unpredictable host-private dir: the path itself is a capability,
        // the token is the authenticator. Both are fresh per execution.
        let dir = std::env::temp_dir().join(format!(
            "vetto-vng-ctl-{}-{}",
            std::process::id(),
            &super::engine::new_nonce()[..16]
        ));
        std::fs::create_dir_all(&dir)?;
        // Best-effort 0700. Same-uid children can still reach it by design
        // (they are given the path); isolation is NOT claimed from perms —
        // it comes from the token + identity binding, documented above.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let fifo = dir.join(FIFO_NAME);
        let cpath = std::ffi::CString::new({
            use std::os::unix::ffi::OsStrExt;
            fifo.as_os_str().as_bytes().to_vec()
        })
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        // SAFETY: mkfifo on our own fresh path with a NUL-free C string.
        let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: open on our own FIFO path; return value checked.
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` was just returned by a successful open and is owned
        // by us from here on.
        let reader = unsafe {
            use std::os::fd::FromRawFd;
            std::os::fd::OwnedFd::from_raw_fd(fd)
        };
        Ok(Self {
            dir,
            fifo,
            expected_token,
            reader,
        })
    }

    pub fn fifo(&self) -> &Path {
        &self.fifo
    }

    /// Env capabilities merged into the child env (transport, not proof).
    pub fn env_entries(&self) -> [(String, String); 2] {
        [
            (
                ENV_CONTROL_FIFO.to_string(),
                self.fifo.display().to_string(),
            ),
            (ENV_CONTROL_TOKEN.to_string(), self.expected_token.clone()),
        ]
    }

    /// Read one control message with `deadline` and verify it. Consumes the
    /// channel (cleanup on drop either way). Returns the mint capability on
    /// exact token match, `None` on timeout/garbage/replay — fail-closed.
    pub fn verify(
        self,
        identity: &ExecutionIdentity,
        deadline: Instant,
    ) -> Option<super::evidence::VerifiedControl> {
        use std::os::fd::AsRawFd;
        let raw = self.reader.as_raw_fd();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 128];
        loop {
            // SAFETY: read into a stack buffer of known length from our own fd.
            let n = unsafe { libc::read(raw, tmp.as_mut_ptr().cast(), tmp.len()) };
            if n > 0 {
                buf.extend_from_slice(&tmp[..n as usize]);
                if buf.len() > MAX_CONTROL_BYTES {
                    return None;
                }
                if Instant::now() >= deadline {
                    break;
                }
                continue;
            }
            if n == 0 {
                break; // EOF: writer(s) closed.
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == libc::EAGAIN || code == libc::EWOULDBLOCK => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Some(code) if code == libc::EINTR => continue,
                _ => return None,
            }
        }
        if buf.is_empty() {
            return None;
        }
        // Tolerate a trailing newline (a forge attempt via `echo`); the
        // legitimate script uses `printf %s` with no newline.
        while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
            buf.pop();
        }
        super::evidence::attest_control(identity, &self.expected_token, &buf)
    }
}

#[cfg(unix)]
impl Drop for ControlChannel {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Non-Unix stub: no host-owned channel exists here by design. Creation
/// always fails so callers degrade to control-unobserved (INCONCLUSIVE,
/// never PASS). The method shapes mirror the Unix type so the runner needs
/// no platform-gated call sites.
#[cfg(not(unix))]
pub struct ControlChannel;

#[cfg(not(unix))]
impl ControlChannel {
    pub fn create(_identity: &ExecutionIdentity) -> std::io::Result<Self> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "host-owned control channel requires unix FIFO",
        ))
    }

    pub fn fifo(&self) -> &Path {
        Path::new("")
    }

    pub fn env_entries(&self) -> [(String, String); 2] {
        [
            (ENV_CONTROL_FIFO.to_string(), String::new()),
            (ENV_CONTROL_TOKEN.to_string(), String::new()),
        ]
    }

    pub fn verify(
        self,
        _identity: &ExecutionIdentity,
        _deadline: Instant,
    ) -> Option<super::evidence::VerifiedControl> {
        None
    }
}
