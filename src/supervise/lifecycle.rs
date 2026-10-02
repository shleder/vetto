//! RAII signal controller and session lifecycle tracking (`src/supervise/lifecycle.rs`).
//!
//! Eliminates legacy static atomics and 20ms polling threads,
//! replacing them with an event-driven Self-Pipe architecture.
//!
//! Signal escalation protocol:
//! - 1st interrupt (`SIGINT`/`SIGTERM`): deliver `SIGINT` to the child or process group.
//! - 2nd interrupt within 500ms window: immediate escalation to `SIGKILL`.
//! - 500ms grace period expiry: escalation to `SIGKILL` if child is still running.

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::error::SuperviseError;
use super::pump::StdioPump;
use super::spawn::SupervisedSession;

#[cfg(unix)]
static ACTIVE_SIGNAL_WRITE_FD: AtomicI32 = AtomicI32::new(-1);

#[cfg(unix)]
extern "C" fn signal_dispatcher(sig: libc::c_int) {
    let fd = ACTIVE_SIGNAL_WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let b = sig as u8;
        unsafe {
            libc::write(fd, (&b as *const u8).cast(), 1);
        }
    }
}

/// RAII signal controller backed by a self-pipe and staged signal escalation.
pub struct SignalController {
    #[allow(dead_code)]
    target: i32,
    #[cfg(unix)]
    pipe_read: OwnedFd,
    #[cfg(unix)]
    pipe_write: OwnedFd,
    #[cfg(unix)]
    monitor_thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(unix)]
    prev_sigint: libc::sighandler_t,
    #[cfg(unix)]
    prev_sigterm: libc::sighandler_t,
    active: Arc<AtomicBool>,
}

impl SignalController {
    /// Installs a signal controller for the target root process or process group.
    ///
    /// For `Tier::FsOnly`, target PID is inverted (`-(root_pid as i32)`), targeting the whole process group.
    pub fn install(root_pid: u32, tier: Option<crate::policy::Tier>) -> Result<Self, SuperviseError> {
        let target = match tier {
            Some(crate::policy::Tier::FsOnly) => -(root_pid as i32),
            _ => root_pid as i32,
        };

        let active = Arc::new(AtomicBool::new(true));

        #[cfg(unix)]
        {
            let mut fds = [0i32; 2];
            let res = unsafe {
                #[cfg(target_os = "linux")]
                {
                    libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    let r = libc::pipe(fds.as_mut_ptr());
                    if r == 0 {
                        libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC);
                        libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC);
                        libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK);
                        libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK);
                    }
                    r
                }
            };

            if res != 0 {
                return Err(SuperviseError::SignalInstallationFailed(format!(
                    "self-pipe creation failed: {}",
                    std::io::Error::last_os_error()
                )));
            }

            let write_raw = fds[1];
            if ACTIVE_SIGNAL_WRITE_FD
                .compare_exchange(-1, write_raw, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
            {
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                return Err(SuperviseError::SignalInstallationFailed(
                    "concurrent SignalController instances are forbidden".into(),
                ));
            }

            let pipe_read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let pipe_write = unsafe { OwnedFd::from_raw_fd(fds[1]) };

            let handler = signal_dispatcher as *const () as libc::sighandler_t;
            let (prev_sigint, prev_sigterm) = unsafe {
                (
                    libc::signal(libc::SIGINT, handler),
                    libc::signal(libc::SIGTERM, handler),
                )
            };

            let read_raw = pipe_read.as_raw_fd();
            let thread_active = Arc::clone(&active);

            let monitor_thread = std::thread::Builder::new()
                .name("vetto-sig-watchdog".into())
                .spawn(move || {
                    let mut pfd = libc::pollfd {
                        fd: read_raw,
                        events: libc::POLLIN,
                        revents: 0,
                    };

                    // Step 1: Wait for 1st signal (blocking poll, 0% CPU)
                    loop {
                        if !thread_active.load(Ordering::Relaxed) {
                            return;
                        }
                        let r = unsafe { libc::poll(&mut pfd, 1, 100) };
                        if r > 0 && (pfd.revents & libc::POLLIN != 0) {
                            let mut b = 0u8;
                            let n = unsafe { libc::read(read_raw, (&mut b as *mut u8).cast(), 1) };
                            if n <= 0 {
                                continue;
                            }
                            if b == b'Q' || !thread_active.load(Ordering::Relaxed) {
                                return; // Shutdown requested
                            }
                            // 1st interrupt: send SIGINT to child or process group
                            unsafe { libc::kill(target, libc::SIGINT) };
                            break;
                        }
                    }

                    // Step 2: Escalation window of 500 ms
                    let start = Instant::now();
                    let grace = Duration::from_millis(500);

                    while start.elapsed() < grace {
                        if !thread_active.load(Ordering::Relaxed) {
                            return;
                        }
                        let pid = target.abs();
                        if unsafe { libc::kill(pid, 0) } != 0 {
                            // Child already terminated
                            return;
                        }

                        let remaining = grace.saturating_sub(start.elapsed());
                        let timeout_ms = remaining.as_millis().clamp(1, 50) as libc::c_int;
                        let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
                        if r > 0 && (pfd.revents & libc::POLLIN != 0) {
                            let mut b = 0u8;
                            let n = unsafe { libc::read(read_raw, (&mut b as *mut u8).cast(), 1) };
                            if n > 0 {
                                if b == b'Q' || !thread_active.load(Ordering::Relaxed) {
                                    return;
                                }
                                // 2nd interrupt: immediate SIGKILL
                                unsafe { libc::kill(target, libc::SIGKILL) };
                                return;
                            }
                        }
                    }

                    // Step 3: Grace period expired; escalate to SIGKILL if child is still alive
                    if thread_active.load(Ordering::Relaxed) {
                        let pid = target.abs();
                        if unsafe { libc::kill(pid, 0) } == 0 {
                            unsafe { libc::kill(target, libc::SIGKILL) };
                        }
                    }
                })
                .map_err(|e| SuperviseError::SignalInstallationFailed(e.to_string()))?;

            Ok(Self {
                target,
                pipe_read,
                pipe_write,
                monitor_thread: Some(monitor_thread),
                prev_sigint,
                prev_sigterm,
                active,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {
                target,
                active,
            })
        }
    }
}

impl Drop for SignalController {
    fn drop(&mut self) {
        self.active.store(false, Ordering::SeqCst);

        #[cfg(unix)]
        {
            // Send 'Q' byte to unblock poll immediately
            let q = b'Q';
            unsafe {
                libc::write(self.pipe_write.as_raw_fd(), (&q as *const u8).cast(), 1);
            }

            // Restore previous signal handlers
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

            ACTIVE_SIGNAL_WRITE_FD.store(-1, Ordering::SeqCst);

            if let Some(h) = self.monitor_thread.take() {
                let _ = h.join();
            }
        }
    }
}

/// Lifecycle tracking outcome.
#[derive(Debug)]
pub struct LifecycleOutcome {
    /// Agent process raw exit code.
    pub exit_code: i32,
    /// Whether session timeout occurred.
    pub timed_out: bool,
    /// Wall-clock duration in seconds.
    pub duration_secs: u64,
    /// Production sandbox execution result.
    pub production_result: Option<crate::sandbox::production::ProductionResult>,
}

/// Manages child session lifecycle, dispatching between Statusline TUI and headless mode.
pub fn manage_session_lifecycle(
    session: &mut SupervisedSession,
    pump: &mut StdioPump,
    cfg: &crate::config::RunConfig,
) -> Result<LifecycleOutcome, SuperviseError> {
    // 1. Install RAII signal controller
    let _sig_ctrl = SignalController::install(session.root_pid, session.tier)?;

    let start_time = session.started;
    let timeout = cfg.session_timeout;

    // 2. Dispatch wait based on TUI mode
    match cfg.tui {
        crate::config::TuiMode::Statusline => {
            #[cfg(unix)]
            {
                let pty_master = pump.pty_master().ok_or_else(|| {
                    SuperviseError::StdioAllocationFailed(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "statusline mode requires an allocated PTY master",
                    ))
                })?;

                let tier_label = session.tier_label();
                let spawned_ref = session.spawned.as_mut().ok_or_else(|| {
                    SuperviseError::Fatal(anyhow::anyhow!("spawned session execution is missing"))
                })?;

                let (code, timed_out) = crate::tui::statusline::run(
                    &session.bus,
                    pty_master,
                    &mut spawned_ref.handle,
                    tier_label,
                    &cfg.net.label(),
                    &session.policy.name,
                    timeout,
                );

                let spawned = session.spawned.take().expect("active spawned session");
                let result = spawned.finish(Some(code), timed_out);

                if timed_out {
                    session.bus.publish(crate::events::Event::SessionTimeout {
                        ts: crate::events::types::now(),
                    });
                }

                eprintln!(
                    "vetto: enforcement {}",
                    result.report.render_deterministic()
                );

                let duration_secs = start_time.elapsed().as_secs();
                Ok(LifecycleOutcome {
                    exit_code: result.exit_code.unwrap_or(code),
                    timed_out: result.timed_out,
                    duration_secs,
                    production_result: Some(result),
                })
            }

            #[cfg(not(unix))]
            {
                let spawned = session.spawned.take().ok_or_else(|| {
                    SuperviseError::Fatal(anyhow::anyhow!("spawned session execution is missing"))
                })?;
                let result = spawned.wait_collect();
                let duration_secs = start_time.elapsed().as_secs();
                Ok(LifecycleOutcome {
                    exit_code: result.exit_code.unwrap_or(-1),
                    timed_out: result.timed_out,
                    duration_secs,
                    production_result: Some(result),
                })
            }
        }
        crate::config::TuiMode::None => {
            let spawned = session.spawned.take().ok_or_else(|| {
                SuperviseError::Fatal(anyhow::anyhow!("spawned session execution is missing"))
            })?;

            let result = spawned.wait_collect();

            if result.timed_out && timeout.is_some() {
                eprintln!(
                    "vetto: session timeout ({}) reached; terminating the sandbox",
                    super::spawn::format_duration(timeout.unwrap_or_default())
                );
                session.bus.publish(crate::events::Event::SessionTimeout {
                    ts: crate::events::types::now(),
                });
            }

            eprintln!(
                "vetto: enforcement {}",
                result.report.render_deterministic()
            );

            let duration_secs = start_time.elapsed().as_secs();
            Ok(LifecycleOutcome {
                exit_code: result.exit_code.unwrap_or(-1),
                timed_out: result.timed_out,
                duration_secs,
                production_result: Some(result),
            })
        }
    }
}
