//! Raw stdin forwarding for statusline pass-through.
//!
//! Runs on a dedicated thread: reads the OUTER terminal in raw mode and
//! forwards bytes into the pty master. `Ctrl+]` (0x1d) is stripped and
//! latched as an overlay request instead of being forwarded.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::pty;

const OVERLAY_KEY: u8 = 0x1d; // Ctrl+]

pub struct Forwarder {
    pub overlay_requested: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
}

impl Forwarder {
    /// Spawn the forwarding thread. Stdin must already be in raw mode.
    pub fn spawn(master_fd: std::os::fd::RawFd) -> Self {
        let overlay_requested = Arc::new(AtomicBool::new(false));
        let paused = Arc::new(AtomicBool::new(false));
        let req = Arc::clone(&overlay_requested);
        let pau = Arc::clone(&paused);
        std::thread::Builder::new()
            .name("vetto-stdin".into())
            .spawn(move || forward_loop(master_fd, req, pau))
            .expect("spawn stdin forwarder");
        Self {
            overlay_requested,
            paused,
        }
    }

    pub fn pause(&self) {
        self.paused.store(true, Ordering::SeqCst);
    }

    pub fn resume(&self) {
        self.paused.store(false, Ordering::SeqCst);
    }

    pub fn take_overlay_request(&self) -> bool {
        self.overlay_requested.swap(false, Ordering::SeqCst)
    }
}

fn forward_loop(
    master_fd: std::os::fd::RawFd,
    overlay_requested: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 4096];
    loop {
        if paused.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        // SAFETY: raw blocking read on stdin (fd 0).
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR {
                continue;
            }
            return; // stdin gone; the session loop handles the rest
        }
        if n == 0 {
            return;
        }
        let chunk = &buf[..n as usize];
        if chunk.contains(&OVERLAY_KEY) {
            overlay_requested.store(true, Ordering::SeqCst);
            let filtered: Vec<u8> = chunk
                .iter()
                .copied()
                .filter(|&b| b != OVERLAY_KEY)
                .collect();
            if !filtered.is_empty() {
                pty::write_all_fd(master_fd, &filtered);
            }
        } else {
            pty::write_all_fd(master_fd, chunk);
        }
    }
}
