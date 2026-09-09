//! Collector stage: deadline-aware drain + post-mortem (FM-04).
//!
//! Two rules that fix the inherited `run_probe_script` hang:
//! - Pipes are drained with a deadline (poll on the read end); a grandchild
//!   holding the write end open cannot hang the harness forever.
//! - The collector gathers the fixed superset of facts (stdout hint,
//!   host-side post-mortem inputs); the oracle decides. The collector never
//!   judges (FM-14).

#[cfg(unix)]
use std::time::Duration;
use std::time::Instant;

#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};

/// Drain `fd` until EOF or `deadline`. Returns bytes read and whether EOF
/// was reached (`false` = deadline hit with the pipe still open, e.g. a
/// grandchild holds the write end: FM-04 HANG-GRANDCHILD-001).
///
/// Unix-only: pipe draining needs raw fds. On Windows the evidence path is
/// host-fact-only (see docs/verify-ng.md); the stub below returns
/// not-EOF so the oracle degrades to INCONCLUSIVE, never PASS.
#[cfg(unix)]
pub fn drain_with_deadline(fd: &OwnedFd, deadline: Instant) -> (Vec<u8>, bool) {
    let raw = fd.as_raw_fd();
    // SAFETY: F_GETFL on our own pipe fd.
    let orig = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    // SAFETY: restoring O_NONBLOCK on our own pipe fd.
    unsafe {
        libc::fcntl(raw, libc::F_SETFL, orig | libc::O_NONBLOCK);
    }
    struct Restore {
        fd: i32,
        flags: i32,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            // SAFETY: restoring saved flags on our own pipe fd.
            unsafe {
                libc::fcntl(self.fd, libc::F_SETFL, self.flags);
            }
        }
    }
    let _restore = Restore {
        fd: raw,
        flags: orig,
    };

    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        // SAFETY: read into a stack buffer of known length.
        let n = unsafe { libc::read(raw, buf.as_mut_ptr().cast(), buf.len()) };
        if n > 0 {
            out.extend_from_slice(&buf[..n as usize]);
            continue;
        }
        if n == 0 {
            return (out, true);
        }
        let err = std::io::Error::last_os_error();
        if let Some(code) = err.raw_os_error() {
            if code == libc::EAGAIN || code == libc::EWOULDBLOCK {
                if Instant::now() >= deadline {
                    return (out, false);
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            if code == libc::EINTR {
                continue;
            }
        }
        return (out, false);
    }
}

/// Windows stub: no raw-fd pipe drain on this platform. Returns not-EOF so
/// callers degrade to INCONCLUSIVE/FAIL, never PASS.
#[cfg(not(unix))]
pub fn drain_with_deadline(
    _fd: &std::os::windows::io::OwnedHandle,
    _deadline: Instant,
) -> (Vec<u8>, bool) {
    (Vec::new(), false)
}

/// Captured stdio of one child plus collection metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectedStdio {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// True only if both streams reached EOF before the deadline. `false`
    /// (e.g. a grandchild holding the write end, or the Windows fallback
    /// timing out) degrades the run toward INCONCLUSIVE, never PASS.
    pub eof: bool,
    /// True if either stream was cut at `max_bytes`.
    pub truncated: bool,
}

/// Collect a reaped (or killed) child's piped stdout/stderr with a deadline.
///
/// Must be called after the child was terminated/reaped via the killer stage:
/// with no live writer the pipes hit EOF immediately; a surviving grandchild
/// holding the write end cannot hang the harness past `deadline` (FM-04
/// HANG-GRANDCHILD-001). Never judges: bytes are returned raw for the
/// caller to store as `SELF_REPORT` evidence.
pub fn collect_child_stdio(
    stdout: std::process::ChildStdout,
    stderr: std::process::ChildStderr,
    deadline: Instant,
    max_bytes: usize,
) -> CollectedStdio {
    #[cfg(unix)]
    {
        let out_fd: OwnedFd = stdout.into();
        let err_fd: OwnedFd = stderr.into();
        let (mut out, out_eof) = drain_with_deadline(&out_fd, deadline);
        let (mut err, err_eof) = drain_with_deadline(&err_fd, deadline);
        let mut truncated = false;
        for buf in [&mut out, &mut err] {
            if buf.len() > max_bytes {
                buf.truncate(max_bytes);
                truncated = true;
            }
        }
        CollectedStdio {
            stdout: out,
            stderr: err,
            eof: out_eof && err_eof,
            truncated,
        }
    }
    #[cfg(not(unix))]
    {
        collect_child_stdio_threaded(stdout, stderr, deadline, max_bytes)
    }
}

/// Non-Unix fallback: reader threads + `recv_timeout` so a hung pipe still
/// respects the deadline. Late bytes are lost; the caller sees `eof=false`
/// and must degrade to INCONCLUSIVE/FAIL, never PASS (same contract as the
/// [`drain_with_deadline`] Windows stub).
#[cfg(not(unix))]
fn collect_child_stdio_threaded(
    mut stdout: std::process::ChildStdout,
    mut stderr: std::process::ChildStderr,
    deadline: Instant,
    max_bytes: usize,
) -> CollectedStdio {
    use std::io::Read;
    let (tx_out, rx_out) = std::sync::mpsc::channel::<Vec<u8>>();
    let (tx_err, rx_err) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        let _ = tx_out.send(buf);
    });
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        let _ = tx_err.send(buf);
    });
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut eof = true;
    let mut truncated = false;
    for (rx, slot) in [(rx_out, &mut out), (rx_err, &mut err)] {
        let wait = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(wait) {
            Ok(bytes) => {
                let mut bytes = bytes;
                if bytes.len() > max_bytes {
                    bytes.truncate(max_bytes);
                    truncated = true;
                }
                *slot = bytes;
            }
            Err(_) => {
                eof = false;
            }
        }
    }
    CollectedStdio {
        stdout: out,
        stderr: err,
        eof,
        truncated,
    }
}

/// Post-mortem filesystem probe result observed by the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostMortem {
    /// Target absent (or empty where emptiness is the enforced shape).
    Absent,
    /// Target exists with unexpected content (violation evidence).
    Present,
}

impl PostMortem {
    /// Stat `path` from the host after wait. `expect_empty_file` covers the
    /// overlay shape (masked files appear empty).
    pub fn stat(path: &std::path::Path, expect_empty_file: bool) -> Self {
        match std::fs::metadata(path) {
            Err(_) => PostMortem::Absent,
            Ok(meta) => {
                if expect_empty_file || meta.len() == 0 {
                    PostMortem::Absent
                } else {
                    PostMortem::Present
                }
            }
        }
    }
}

#[cfg(test)]
mod collector_tests {
    use super::*;

    #[test]
    fn postmortem_absent_for_missing() {
        let p = std::env::temp_dir().join("vetto-vng-no-such-file-xyz");
        assert_eq!(PostMortem::stat(&p, false), PostMortem::Absent);
    }

    #[test]
    fn postmortem_present_for_content() {
        let p = std::env::temp_dir().join(format!("vetto-vng-pm-{}", std::process::id()));
        std::fs::write(&p, b"leak").expect("write");
        assert_eq!(PostMortem::stat(&p, false), PostMortem::Present);
        let _ = std::fs::remove_file(&p);
    }
}
