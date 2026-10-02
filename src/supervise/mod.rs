//! Sandboxed AI Agent Session Supervisor.
//!
//! Decomposes the monolithic session orchestrator into 5 focused submodules:
//! - `error`: Strongly typed errors and deterministic exit codes.
//! - `spawn`: Command preflight, policy loading, and sandbox preparation.
//! - `pump`: Non-blocking asynchronous I/O pump with secret masking.
//! - `lifecycle`: Self-pipe RAII signal controller and child lifecycle tracking.
//! - `finalize`: Post-exit verification, extinction audit, and verdict calculation.

pub mod error;
pub mod finalize;
pub mod lifecycle;
pub mod pump;
pub mod spawn;

pub use error::SuperviseError;
pub use finalize::SupervisionVerdict;

use crate::config::RunConfig;

/// Supervise a sandboxed AI agent session from start to authoritative verdict.
pub fn supervise(mut cfg: RunConfig) -> Result<SupervisionVerdict, SuperviseError> {
    // 0. Dry-run handler: diagnostics without process execution
    if cfg.dry_run {
        spawn::execute_dry_run(&cfg)?;
        return Ok(SupervisionVerdict::dry_run());
    }

    // 1. Preflight boundary check, policy resolution, and sandbox spawn
    let mut session = spawn::spawn_supervised_session(&mut cfg)?;

    // 2. Start streaming non-blocking I/O pump adhering to INV-25
    let mut pump = pump::StdioPump::start(
        session.stdio.pty_master.take(),
        session.stdio.stdout_r.take(),
        session.stdio.stderr_r.take(),
        session.stdio.mask_secrets,
    )?;

    // 3. Manage signals via RAII self-pipe, enforce timeouts, and await child
    let lifecycle = lifecycle::manage_session_lifecycle(&mut session, &mut pump, &cfg)?;

    // 4. Drain output streams and apply secret masking
    let pump_data = pump.drain_and_redact().ok();

    // 5. Audit process extinction, evaluate VerdictEngine, and finalize session
    finalize::finalize_session(finalize::FinalizeContext {
        cfg: &cfg,
        session,
        lifecycle,
        pump_data,
    })
}
