//! Optional diagnostics exposed by explicit actions only: `doctor` flags and
//! the `verify` boundary battery. Probing is never implicit in policy loading
//! or sandbox setup.

pub mod agent_check;
pub mod environment;
pub mod fix;

pub use agent_check::{probe, probe_agent, AgentCheck, ProbeStatus};
pub use environment::{detect_environment, EnvironmentInfo};
#[cfg(target_os = "linux")]
pub use fix::collect_linux_fixes;
#[cfg(target_os = "macos")]
pub use fix::collect_macos_fixes;
#[cfg(target_os = "windows")]
pub use fix::collect_windows_fixes;
pub use fix::{print_fixes, DoctorFix};

// The probe spawn machinery is unix-only (Captured stdio contract).
#[cfg(unix)]
pub mod probe;

#[cfg(unix)]
pub use probe::{run_probe_script, ProbeOutput};
