//! ScopedSignalForwarder RAII signal management.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::context::ProductionSessionContext;
use super::error::ProductionError;

#[cfg(unix)]
static ACTIVE_FORWARDER_PID: AtomicI32 = AtomicI32::new(0);
#[cfg(unix)]
static ACTIVE_FORWARDER_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn forwarder_sig_handler(_sig: libc::c_int) {
    let t = ACTIVE_FORWARDER_PID.load(Ordering::SeqCst);
    if t != 0 {
        let count = ACTIVE_FORWARDER_COUNT.fetch_add(1, Ordering::SeqCst);
        if count == 0 {
            unsafe { libc::kill(t, libc::SIGINT) };
        } else {
            unsafe { libc::kill(t, libc::SIGKILL) };
        }
    }
}

/// Target to forward signals to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalTarget {
    Process(u32),
    ProcessGroup(i32),
}

impl SignalTarget {
    pub fn as_raw_target(&self) -> i32 {
        match *self {
            SignalTarget::Process(pid) => pid as i32,
            SignalTarget::ProcessGroup(pgid) => -(pgid.abs()),
        }
    }
}

/// Escalation policy for signal delivery.
#[derive(Debug, Clone)]
pub struct EscalationPolicy {
    pub sigint_grace: Duration,
    pub poll_interval: Duration,
}

impl Default for EscalationPolicy {
    fn default() -> Self {
        Self {
            sigint_grace: Duration::from_millis(500),
            poll_interval: Duration::from_millis(20),
        }
    }
}

/// RAII guard forwarding process signals to the active sandbox target.
pub struct ScopedSignalForwarder {
    pub context: ProductionSessionContext,
    pub target: SignalTarget,
    #[cfg(unix)]
    active: Arc<AtomicBool>,
    #[cfg(unix)]
    prev_sigint: libc::sighandler_t,
    #[cfg(unix)]
    prev_sigterm: libc::sighandler_t,
}

impl ScopedSignalForwarder {
    #[cfg(unix)]
    pub fn install(
        context: ProductionSessionContext,
        target: SignalTarget,
        policy: EscalationPolicy,
    ) -> Result<Self, ProductionError> {
        let raw_target = target.as_raw_target();
        if raw_target == 0 {
            return Err(ProductionError::SignalError("invalid signal target 0".into()));
        }

        if ACTIVE_FORWARDER_PID
            .compare_exchange(0, raw_target, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(ProductionError::SignalError(
                "Another ScopedSignalForwarder is already active in this process; concurrent forwarders are forbidden".into(),
            ));
        }

        context
            .signals
            .target_pid
            .store(raw_target, Ordering::SeqCst);
        context.signals.sigint_count.store(0, Ordering::SeqCst);
        ACTIVE_FORWARDER_COUNT.store(0, Ordering::SeqCst);

        let active = Arc::new(AtomicBool::new(true));
        let active_clone = Arc::clone(&active);
        let ctx_signals = Arc::clone(&context.signals);

        std::thread::Builder::new()
            .name("vetto-sigint-watchdog".into())
            .spawn(move || loop {
                if !active_clone.load(Ordering::SeqCst)
                    || ctx_signals.target_pid.load(Ordering::SeqCst) == 0
                {
                    break;
                }
                let count = ACTIVE_FORWARDER_COUNT.load(Ordering::SeqCst);
                if count > 0 {
                    std::thread::sleep(policy.sigint_grace);
                    if !active_clone.load(Ordering::SeqCst) {
                        break;
                    }
                    let t = ACTIVE_FORWARDER_PID.load(Ordering::SeqCst);
                    if t != 0 {
                        let pid = t.abs();
                        if unsafe { libc::kill(pid, 0) } == 0 {
                            unsafe { libc::kill(t, libc::SIGKILL) };
                        }
                    }
                    break;
                }
                std::thread::sleep(policy.poll_interval);
            })
            .map_err(|e| {
                ACTIVE_FORWARDER_PID.store(0, Ordering::SeqCst);
                ProductionError::SignalError(e.to_string())
            })?;

        let handler = forwarder_sig_handler as *const () as libc::sighandler_t;
        let (prev_sigint, prev_sigterm) = unsafe {
            (
                libc::signal(libc::SIGINT, handler),
                libc::signal(libc::SIGTERM, handler),
            )
        };

        Ok(Self {
            context,
            target,
            active,
            prev_sigint,
            prev_sigterm,
        })
    }

    #[cfg(not(unix))]
    pub fn install(
        context: ProductionSessionContext,
        target: SignalTarget,
        _policy: EscalationPolicy,
    ) -> Result<Self, ProductionError> {
        Ok(Self { context, target })
    }
}

impl Drop for ScopedSignalForwarder {
    fn drop(&mut self) {
        self.context.signals.target_pid.store(0, Ordering::SeqCst);
        #[cfg(unix)]
        {
            self.active.store(false, Ordering::SeqCst);
            ACTIVE_FORWARDER_PID.store(0, Ordering::SeqCst);
            unsafe {
                if self.prev_sigint != libc::SIG_ERR {
                    libc::signal(libc::SIGINT, self.prev_sigint);
                } else {
                    libc::signal(libc::SIGINT, libc::SIG_DFL);
                }
                if self.prev_sigterm != libc::SIG_ERR {
                    libc::signal(libc::SIGTERM, self.prev_sigterm);
                } else {
                    libc::signal(libc::SIGTERM, libc::SIG_DFL);
                }
            }
        }
    }
}
