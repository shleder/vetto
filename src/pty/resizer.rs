//! Outer-terminal resize propagation into the sandbox PTY.
//!
//! When the real terminal is resized, SIGWINCH fires (see sigwinch.rs), we
//! read the new outer size, resize the inner pty to `(rows-1, cols)` — one
//! row stays reserved for the statusline — and the kernel then delivers
//! SIGWINCH to the agent's foreground group on the pty. No manual signaling.

use std::os::fd::RawFd;

use super::set_winsize;

/// Apply a resize now (ignores the SIGWINCH latch). Returns the inner size.
pub fn apply_now(master_fd: RawFd) -> Option<(u16, u16)> {
    let (rows, cols) = crossterm::terminal::size().ok()?;
    let inner_rows = rows.saturating_sub(1).max(1);
    set_winsize(master_fd, inner_rows, cols);
    Some((inner_rows, cols))
}

/// If the SIGWINCH latch is set, propagate the outer size into the pty.
/// Returns the new inner size when a resize was applied.
pub fn sync_to_outer(master_fd: RawFd) -> Option<(u16, u16)> {
    if !super::sigwinch::take() {
        return None;
    }
    apply_now(master_fd)
}
