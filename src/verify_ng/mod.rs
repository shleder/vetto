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
pub mod host_evidence;
pub mod killer;
pub mod model;
pub mod oracle;
pub mod redact;
pub mod registry;
pub mod report;
pub mod runner;
pub mod sandbox_backend;

/// CLI entry: `vetto verify-ng [--json] [--lint]`.
///
/// `--lint` checks the frozen scenario registry without spawning anything.
/// Without `--lint`: poison-check first (diagnostic env -> per-scenario
/// FAIL/INCONCLUSIVE, no spawn); otherwise every scenario reports
/// INCONCLUSIVE without spawning (the direct-exec library runner in
/// [`runner`] covers single-scenario execution; full registry-suite wiring
/// lands separately) and the
/// gate evaluates honestly — canary minimums keep it red. Never emits PASS.
pub fn run_verify_ng(json: bool, lint: bool) -> anyhow::Result<()> {
    let scenarios = registry::registry();
    if lint {
        let errors = registry::lint_all(&scenarios);
        let hash = registry::registry_hash_full(&scenarios);
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
            println!(
                "verify-ng lint clean: {} scenarios, registry {hash}",
                scenarios.len()
            );
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
    // Suite run without spawning: poison -> per-scenario poisoned results;
    // otherwise every scenario is INCONCLUSIVE (no measurement without the
    // spawn runner). Gate evaluates honestly; canary minimums keep it red.
    // Harness stays fail-closed: always exit 125 via the typed error below.
    use std::collections::BTreeMap;
    let target = engine::current_target(None);
    let poison = engine::detect_env_poison(false);
    let hash = registry::registry_hash_full(&scenarios);
    let results: Vec<model::ScenarioResult> = if poison.is_empty() {
        scenarios
            .iter()
            .map(|s| model::ScenarioResult {
                id: s.id.clone(),
                category: s.category,
                strength: s.strength_for(target),
                verdict: model::Verdict::Inconclusive,
                detail: redact::redact_text(&format!(
                    "no spawn runner yet; failing closed — {}",
                    s.known_limitation
                )),
            })
            .collect()
    } else {
        scenarios
            .iter()
            .map(|s| engine::poisoned_result(s, target, &poison))
            .collect()
    };
    let report = exit::evaluate_gate(&results, &BTreeMap::new(), &hash);
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report::gate_report_json(&report, &hash))?
        );
    } else {
        if poison.is_empty() {
            eprintln!("vetto: verify-ng: no spawn runner yet; failing closed");
        } else {
            eprintln!(
                "vetto: verify-ng: diagnostic env interference ({}); failing closed",
                poison.join(",")
            );
        }
        println!("{}", report::render_text(&report));
    }
    Err(crate::error::VettoError::HarnessUnavailable(
        "verify-ng suite execution needs the spawn runner".to_string(),
    )
    .into())
}
