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

/// CLI entry: `vetto verify-ng [--json] [--lint]`.
///
/// `--lint` checks the frozen scenario registry without spawning anything
/// and always exits 0/1 via anyhow (lint errors fail the command).
/// Without `--lint`, no execution engine is wired yet: fail closed with
/// exit 125 and never emit a PASS.
pub fn run_verify_ng(json: bool, lint: bool) -> anyhow::Result<()> {
    let scenarios = registry::registry();
    if lint {
        let errors = registry::lint_all(&scenarios);
        let hash = frozen::registry_hash(
            &scenarios.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        );
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "tool": "vetto verify-ng",
                    "registry_hash": hash,
                    "scenarios": scenarios.len(),
                    "errors": errors,
                })
            );
        } else if errors.is_empty() {
            println!("verify-ng lint clean: {} scenarios, registry {hash}", scenarios.len());
        } else {
            println!("verify-ng lint FAILED ({} error(s)):", errors.len());
            for e in &errors {
                println!("  - {e}");
            }
        }
        if errors.is_empty() {
            return Ok(());
        }
        anyhow::bail!("verify-ng registry lint failed ({} error(s))", errors.len());
    }
    // No suite execution yet: fail closed with a typed harness error so
    // the central mapper exits 125 (never a hollow PASS).
    let report = exit::GateReport {
        status: "failed".to_string(),
        passed: 0,
        failed: 0,
        inconclusive: 0,
        not_applicable: 0,
        blocking: vec!["verify-ng:suite-execution-not-wired".to_string()],
        results: vec![],
    };
    if json {
        let hash = frozen::registry_hash(
            &scenarios.iter().map(|s| s.id.clone()).collect::<Vec<_>>(),
        );
        println!("{}", serde_json::to_string_pretty(&report::gate_report_json(&report, &hash))?);
    } else {
        eprintln!("vetto: verify-ng: suite execution not wired yet; failing closed");
        println!("{}", report::render_text(&report));
    }
    Err(crate::error::VettoError::HarnessUnavailable(
        "verify-ng suite execution not wired".to_string(),
    )
    .into())
}
