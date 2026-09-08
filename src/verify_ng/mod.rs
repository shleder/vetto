//! Adversarial security verification (`verify-ng`).
//!
//! Design notes (from the Prompt-01 proposal and its adversarial self-review):
//! - The oracle judges a [`Verdict`] from host-observable facts only.
//!   Attacker-controlled stdout is a hint, never proof of PASS.
//! - [`ClaimStrength`] (how strong the guarantee can ever be on this
//!   platform/tier) is a static registry property, orthogonal to the per-run
//!   [`Verdict`]. There is no "Partial-PASS": the report carries both axes.
//! - Spawning follows the single-threaded fork contract of
//!   `crate::sandbox::Backend::spawn`: [`engine::SPAWN_SERIAL`] serializes
//!   every spawn up to fork-return. Parallelize preparation and judging,
//!   never the spawn itself.
//! - Enforcement stays in the sandbox backends. This module is a
//!   measurement harness, not part of the security boundary.

pub mod caps;
pub mod collector;
pub mod engine;
pub mod evidence;
pub mod exit;
pub mod fixture;
pub mod frozen;
pub mod killer;
pub mod model;
pub mod oracle;
pub mod redact;
pub mod registry;
pub mod report;
