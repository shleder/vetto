//! Integration test harness: every test drives the COMPILED vetto binary as
//! a child process. All enforcement tests are conditional on the platform
//! actually supporting a tier (see common::detected_tier) — skipping on
//! unsupported environments is part of the spec, not a failure.

mod common;

mod cli_reporting;
#[cfg(unix)]
mod env_stripping;
#[cfg(target_os = "linux")]
mod linux_landlock;
#[cfg(target_os = "linux")]
mod linux_netmodes;
#[cfg(target_os = "linux")]
mod linux_orphans;
#[cfg(target_os = "linux")]
mod linux_seccomp_blocks;
#[cfg(target_os = "linux")]
mod linux_subagents;
#[cfg(target_os = "linux")]
mod linux_tiers;
#[cfg(target_os = "linux")]
mod linux_visibility;
mod macos_seatbelt;
mod multi_agent;
mod policy_loading;
mod policy_overlays;
mod secret_masking;
