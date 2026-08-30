//! Integration test harness: every test drives the COMPILED vetto binary as
//! a child process. All enforcement tests are conditional on the platform
//! actually supporting a tier (see common::detected_tier) — skipping on
//! unsupported environments is part of the spec, not a failure.

#![allow(clippy::all)]

mod common;

mod cli_reporting;
#[cfg(target_os = "linux")]
mod env_stripping;
mod git_hooks;
mod heavy_scenarios;
#[cfg(target_os = "linux")]
mod linux_downgrade;
#[cfg(target_os = "linux")]
mod linux_landlock;
#[cfg(target_os = "linux")]
mod linux_limits_cli;
#[cfg(target_os = "linux")]
mod linux_netmodes;
#[cfg(target_os = "linux")]
mod linux_orphans;
#[cfg(target_os = "linux")]
mod linux_redteam;
#[cfg(target_os = "linux")]
mod linux_seccomp_blocks;
#[cfg(target_os = "linux")]
mod linux_subagents;
#[cfg(target_os = "linux")]
mod linux_tiers;
#[cfg(target_os = "linux")]
mod linux_timeout;
#[cfg(target_os = "linux")]
mod linux_verify;
#[cfg(target_os = "linux")]
mod linux_visibility;
mod macos_seatbelt;
mod multi_agent;
mod onboarding;
mod policy_loading;
mod policy_overlays;
mod policy_parity;
mod policy_tools;
mod rescue;
mod secret_masking;
mod shim_interception;
mod tier3_files_secrets;
mod tier8_release;
mod tier9_friction;
mod windows_enforcement;
mod windows_sandbox;
