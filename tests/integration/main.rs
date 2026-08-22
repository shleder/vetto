//! Integration test harness: every test drives the COMPILED vetto binary as
//! a child process. All enforcement tests are conditional on the platform
//! actually supporting a tier (see common::detected_tier) — skipping on
//! unsupported environments is part of the spec, not a failure.

mod common;

mod linux_landlock;
mod linux_netmodes;
mod linux_orphans;
mod linux_tiers;
mod linux_visibility;
mod macos_seatbelt;
mod policy_loading;
mod policy_overlays;
mod secret_masking;
