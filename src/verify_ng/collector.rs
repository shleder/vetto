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
