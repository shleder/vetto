//! Optional diagnostics exposed by explicit actions only: `doctor` flags and
//! the `verify` boundary battery. Probing is never implicit in policy loading
//! or sandbox setup.

pub mod agent_check;
pub mod environment;

pub use agent_check::{probe, probe_agent, AgentCheck, ProbeStatus};
pub use environment::{detect_environment, EnvironmentInfo};

// The probe spawn machinery is unix-only (Captured stdio contract).
#[cfg(unix)]
pub mod probe;

#[cfg(unix)]
pub use probe::{run_probe_script, ProbeOutput};
