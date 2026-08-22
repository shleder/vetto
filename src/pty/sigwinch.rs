//! Global SIGWINCH latch (outer terminal resized).

use std::sync::atomic::{AtomicBool, Ordering};

static RESIZED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigwinch(_sig: libc::c_int) {
    // Async-signal-safe: a single atomic store, nothing else.
    RESIZED.store(true, Ordering::SeqCst);
}

/// Install the handler. Call once before the statusline loop starts.
pub fn install() -> bool {
    // SAFETY: registering our extern handler; returns SIG_ERR on failure.
    let r = unsafe { libc::signal(libc::SIGWINCH, on_sigwinch as *const () as libc::sighandler_t) };
    r != libc::SIG_ERR
}

/// Consume the pending-resize flag.
pub fn take() -> bool {
    RESIZED.swap(false, Ordering::SeqCst)
}
