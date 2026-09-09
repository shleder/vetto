//! Host-owned challenge-response control (Stage 2 correction).
//!
//! Non-self-authorization invariant: the attacker cannot obtain PASS merely
//! by replaying or echoing a verifier-issued capability. The host therefore
//! NEVER issues a value whose echo counts as control. Instead:
//!
//! - The host creates TWO FIFOs in a host-private temp dir (outside the
//!   fixture root, HOME and `VETTO_VNG_ROOT`) BEFORE spawn: a downlink
//!   (host -> child) and an uplink (child -> host). The host holds the
//!   downlink write end and the uplink read end open across the spawn.
//! - The host generates a fresh 128-bit challenge per execution, writes it
//!   (plus newline) into the downlink buffer pre-spawn, and NEVER puts it
//!   (or anything derived into a PASS value) into env. The child receives
//!   only the two FIFO paths plus the pre-existing run-label nonce.
//! - The child must actively READ the challenge from the downlink, rotate
//!   (`challenge` + `session_nonce`) per
//!   [`crate::verify_ng::evidence::derive_expected_response`], and write
//!   the response to the uplink. Proof is the ARRIVAL of the exact expected
//!   response on the host-held uplink end before the deadline, verified by
//!   the pure [`crate::verify_ng::evidence::attest_control`].
//! - Echoing the challenge, the nonce, env values, stale responses, file
//!   content, or stdio markers all differ from the expected response and
//!   fail verification. The host reads control from nowhere else.
//!
//! Why echo/copy cannot self-authorize: no env value, no file the child
//! can write, and no previously observed bytes equal the expected
//! response, because the challenge is fresh per execution and the rotation
//! is applied by the child, not issued by the host. A payload that only
//! copies verifier material performs no rotation and fails.
//!
//! Honest ceilings (not false security):
//!
//! - The protocol proves live challenge-response execution by the staged
//!   payload, never containment. The runner assembles PASS-capable oracle
//!   input from a verified response for `Aux` pipeline scenarios only;
//!   blocker categories stay INCONCLUSIVE/FAIL on direct-exec regardless.
//! - Same-uid caveat is unchanged: the guarantee is "no trivial
//!   self-authorization", not "an omniscient same-user attacker cannot
//!   reimplement the rotation". Reimplementation IS the required behavior.
//! - Non-Unix platforms have no channel here: creation fails, the run
//!   degrades to control-unobserved (INCONCLUSIVE, never PASS).
//!
//! I/O ownership: all OS work (mkfifo/open/read/write) lives in this
//! module and the runner. The oracle stays a pure decision function and
//! only sees the already-verified capability's stamped fact.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::evidence::ExecutionIdentity;

/// Child env carrying the downlink (challenge) FIFO path. A path capability,
/// not proof; the challenge bytes themselves are never in env.
pub const ENV_CONTROL_DOWNLINK: &str = "VETTO_VNG_CONTROL_DOWNLINK";
/// Child env carrying the uplink (response) FIFO path. A path capability,
/// not proof.
pub const ENV_CONTROL_UPLINK: &str = "VETTO_VNG_CONTROL_UPLINK";
/// Downlink FIFO file name inside the host-private channel dir.
pub const CHALLENGE_FIFO: &str = "challenge.fifo";
/// Uplink FIFO file name inside the host-private channel dir.
pub const RESPONSE_FIFO: &str = "response.fifo";
/// Upper bound on one control message; anything larger fails closed.
pub const MAX_CONTROL_BYTES: usize = 256;
/// Budget for the post-termination control read.
pub const CONTROL_READ_BUDGET: Duration = Duration::from_secs(2);

/// Host end of one execution's challenge-response channel. Created before
/// spawn (challenge buffered into the downlink pre-spawn), held across it,
/// verified once after collection, then dropped (removing the host-private
/// dir). Unix-only; see the non-Unix stub below.
#[cfg(unix)]
pub struct ControlChannel {
    dir: PathBuf,
    downlink: PathBuf,
    uplink: PathBuf,
    expected: String,
    uplink_reader: std::os::fd::OwnedFd,
    /// Held open so the buffered challenge is never discarded (a pipe with
    /// zero open file descriptions loses its buffer) and so the child
    /// open-for-read never blocks.
    _downlink_writer: std::os::fd::OwnedFd,
}

#[cfg(unix)]
impl ControlChannel {
    /// Create the host-private dir + both FIFOs, generate the fresh
    /// challenge, buffer it into the downlink, and derive the expected
    /// response. Nothing PASS-capable is exposed: env will carry only the
    /// two FIFO paths (plus the pre-existing run-label nonce).
    pub fn create(identity: &ExecutionIdentity) -> std::io::Result<Self> {
        // Fresh 128-bit challenge per execution; never issued via env.
        let challenge = super::engine::new_nonce();
        let expected =
            super::evidence::derive_expected_response(&challenge, &identity.session_nonce);
        // Unpredictable host-private dir: the paths are capabilities, the
        // challenge is the secret. Both are fresh per execution.
        let dir = std::env::temp_dir().join(format!(
            "vetto-vng-ctl-{}-{}",
            std::process::id(),
            &super::engine::new_nonce()[..16]
        ));
        std::fs::create_dir_all(&dir)?;
        // Best-effort 0700. Same-uid children can still reach the paths by
        // design (they are given them); the guarantee does NOT come from
        // perms — it comes from challenge freshness plus the rotation the
        // child must perform, documented above.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
        let downlink = dir.join(CHALLENGE_FIFO);
        let uplink = dir.join(RESPONSE_FIFO);
        let mkfifo = |path: &Path| -> std::io::Result<()> {
            let cpath = std::ffi::CString::new({
                use std::os::unix::ffi::OsStrExt;
                path.as_os_str().as_bytes().to_vec()
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            // SAFETY: mkfifo on our own fresh path with a NUL-free C string.
            let rc = unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };
        if let Err(e) = mkfifo(&downlink).and_then(|()| mkfifo(&uplink)) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        let open_rw = |path: &Path, flags: i32| -> std::io::Result<std::os::fd::OwnedFd> {
            let cpath = std::ffi::CString::new({
                use std::os::unix::ffi::OsStrExt;
                path.as_os_str().as_bytes().to_vec()
            })
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            // SAFETY: open on our own FIFO path; return value checked.
            let fd = unsafe { libc::open(cpath.as_ptr(), flags) };
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: `fd` was just returned by a successful open and is
            // owned by us from here on.
            Ok(unsafe {
                use std::os::fd::FromRawFd;
                std::os::fd::OwnedFd::from_raw_fd(fd)
            })
        };
        let uplink_reader =
            match open_rw(&uplink, libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(e);
                }
            };
        // RDWR never blocks on open (no peer needed) and always accepts the
        // small buffered write; the held fd keeps the challenge alive.
        let downlink_writer =
            match open_rw(&downlink, libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = std::fs::remove_dir_all(&dir);
                    return Err(e);
                }
            };
        // Buffer "challenge\n" pre-spawn: atomic (far below PIPE_BUF), so
        // the child `read` sees exactly one line whenever it reads.
        let line = format!("{challenge}\n");
        let written = {
            use std::os::fd::AsRawFd;
            // SAFETY: write of a small buffer to our own pipe fd.
            unsafe {
                libc::write(
                    downlink_writer.as_raw_fd(),
                    line.as_ptr().cast(),
                    line.len(),
                )
            }
        };
        if written != line.len() as isize {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "challenge buffer write incomplete",
            ));
        }
        Ok(Self {
            dir,
            downlink,
            uplink,
            expected,
            uplink_reader,
            _downlink_writer: downlink_writer,
        })
    }

    /// Env capabilities merged into the child env (transport, not proof).
    /// Deliberately: NO token, NO challenge, NO response — echoing env
    /// can never satisfy verification.
    pub fn env_entries(&self) -> [(String, String); 2] {
        [
            (
                ENV_CONTROL_DOWNLINK.to_string(),
                self.downlink.display().to_string(),
            ),
            (
                ENV_CONTROL_UPLINK.to_string(),
                self.uplink.display().to_string(),
            ),
        ]
    }

    /// Read one response with `deadline` and verify it. Consumes the
    /// channel (cleanup on drop either way). Returns the mint capability
    /// only on exact arrival of the expected rotated response, `None` on
    /// timeout/echo/garbage/duplicates/replay — fail-closed.
    pub fn verify(
        self,
        identity: &ExecutionIdentity,
        deadline: Instant,
    ) -> Option<super::evidence::VerifiedControl> {
        use std::os::fd::AsRawFd;
        let raw = self.uplink_reader.as_raw_fd();
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
        // Tolerate a trailing newline (a forge attempt via `echo` still
        // fails on content: echo of anything but the exact rotation is
        // rejected below).
        while buf.last() == Some(&b'\n') || buf.last() == Some(&b'\r') {
            buf.pop();
        }
        super::evidence::attest_control(identity, &self.expected, &buf)
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

    pub fn env_entries(&self) -> [(String, String); 2] {
        [
            (ENV_CONTROL_DOWNLINK.to_string(), String::new()),
            (ENV_CONTROL_UPLINK.to_string(), String::new()),
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
