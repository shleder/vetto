//! Optional diagnostics exposed by the explicit `doctor --check-agent` action.
//!
//! Probing an agent is never implicit in policy loading or sandbox setup.

pub mod agent_check;

pub use agent_check::{probe, probe_agent, AgentCheck, ProbeStatus};
