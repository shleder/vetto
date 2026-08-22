//! PTY plumbing for statusline pass-through.
//!
//! vetto allocates the agent's PTY at `(rows-1, cols)` so the agent renders
//! above the one reserved status row; the master end stays in vetto for
//! byte pumping and resizing.

pub mod resizer;
pub mod sigwinch;

use std::ffi::CStr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::error::{VettoError, VettoResult};

pub struct Pty {
    pub master: OwnedFd,
    pub slave: OwnedFd,
}

impl Pty {
    /// Open a fresh pty pair sized `(rows, cols)`.
    pub fn open(rows: u16, cols: u16) -> VettoResult<Self> {
        // SAFETY: scalar-only pty master allocation.
        let master = unsafe {
            libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC)
        };
        if master < 0 {
            return Err(VettoError::Pty(format!(
                "posix_openpt: {}",
                std::io::Error::last_os_error()
            )));
        }
        let fail = |stage: &str, fd: RawFd| {
            // SAFETY: close the half-built master on error paths.
            unsafe { libc::close(fd) };
            VettoError::Pty(format!("{stage}: {}", std::io::Error::last_os_error()))
        };
        // SAFETY: master is a valid pty master fd.
        if unsafe { libc::grantpt(master) } != 0 {
            return Err(fail("grantpt", master));
        }
        // SAFETY: master is a valid pty master fd.
        if unsafe { libc::unlockpt(master) } != 0 {
            return Err(fail("unlockpt", master));
        }

        let mut name_buf = [0u8; 128];
        // SAFETY: master valid; buffer is the documented ptsname_r out-param.
        if unsafe { libc::ptsname_r(master, name_buf.as_mut_ptr().cast(), name_buf.len()) } != 0 {
            return Err(fail("ptsname_r", master));
        }
        let len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
        let Ok(name) = CStr::from_bytes_with_nul(&name_buf[..=len]) else {
            return Err(fail("ptsname_r", master));
        };

        // SAFETY: slave path is NUL-terminated (straight from ptsname_r).
        let slave = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC,
            )
        };
        if slave < 0 {
            return Err(fail("open slave", master));
        }

        set_winsize(master, rows, cols);
        // SAFETY: both descriptors come from successful calls above.
        Ok(Pty {
            master: unsafe { OwnedFd::from_raw_fd(master) },
            slave: unsafe { OwnedFd::from_raw_fd(slave) },
        })
    }

}

/// TIOCSWINSZ on a pty end. The kernel forwards SIGWINCH to the foreground
/// process group of the pty — no manual signaling needed.
pub fn set_winsize(fd: RawFd, rows: u16, cols: u16) {
    let ws = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: ioctl on a valid fd with a properly sized struct.
    unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
}

/// Toggle O_NONBLOCK on a descriptor.
pub fn set_nonblocking(fd: RawFd, on: bool) -> std::io::Result<()> {
    // SAFETY: fcntl(F_GETFL) on a live descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let new_flags = if on {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: fcntl(F_SETFL) with scalar flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Read whatever is ready on a nonblocking fd (empty slice when nothing).
pub fn read_ready(fd: RawFd, buf: &mut [u8]) -> usize {
    // SAFETY: raw read into the caller's buffer.
    let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if n > 0 {
        n as usize
    } else {
        0
    }
}

/// Blocking-write loop for a fd (EINTR-safe). Best-effort: returns on error.
pub fn write_all_fd(fd: RawFd, mut buf: &[u8]) {
    while !buf.is_empty() {
        // SAFETY: raw write of the remaining slice.
        let n = unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) };
        if n > 0 {
            buf = &buf[n as usize..];
        } else if n < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
        {
            continue;
        } else {
            return;
        }
    }
}
