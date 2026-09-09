//! Gate report + exit-code contract (FM-10/FM-12).
//!
//! The gate blocks promotion unless ALL hold:
//!
//! - No blocker-category FAIL or INCONCLUSIVE.
//! - Zero INCONCLUSIVE in blocker categories (fail-closed).
//! - Every NOT_APPLICABLE carries structured absence evidence.
//! - Scenario IDs are unique (one scenario result per registry entry).
//! - Canary scenarios (proof-of-enforcement-alive) all PASS.
//! - Per-category PASS minimums met (no vacuum PASS: FM-12).
//!
//! Exit codes reuse `crate::exit_codes`: 0 clean, 1 gate failure (leak or
//! inconclusive-in-blocker), 125 harness fail-closed (could not run).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::model::{Category, ScenarioResult, Verdict};

/// Canary scenario ids: proof the enforcement under test is alive.
/// A green gate with a failing canary is a contradiction -> gate FAIL.
pub const CANARY_IDS: &[&str] = &["VFS-TRAV-001", "ENV-LEAK-001", "PROC-ESC-001"];

/// Minimum PASS counts per blocker category for a meaningful gate.
pub fn min_pass_per_category() -> BTreeMap<Category, usize> {
    BTreeMap::from([
        (Category::FsRead, 1),
        (Category::FsWrite, 1),
        (Category::Net, 1),
        (Category::Proc, 1),
        (Category::Secrets, 1),
        (Category::Spawn, 1),
    ])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateReport {
    pub status: String,
    pub passed: usize,
    pub failed: usize,
    pub inconclusive: usize,
    pub not_applicable: usize,
    pub blocking: Vec<String>,
    pub results: Vec<ScenarioResult>,
}

impl GateReport {
    pub fn summary(&self) -> String {
        format!(
            "verify-ng gate: {} (pass={} fail={} inconclusive={} n/a={})",
            self.status, self.passed, self.failed, self.inconclusive, self.not_applicable
        )
    }
}

fn valid_absence_evidence(entries: &[String]) -> bool {
    !entries.is_empty()
        && entries
            .iter()
            .all(|e| e.contains(": absent (") && e.ends_with(')'))
}

/// Evaluate the gate. `na_evidence` maps scenario id -> structured capability
/// absence evidence for NOT_APPLICABLE results; entries missing proof, or
/// evidence not matching the capability-absence shape, fail the gate.
pub fn evaluate_gate(
    results: &[ScenarioResult],
    na_evidence: &BTreeMap<String, Vec<String>>,
    registry_hash: &str,
) -> GateReport {
    let mut blocking = Vec::new();
    let mut passed = 0;
    let mut failed = 0;
    let mut inconclusive = 0;
    let mut not_applicable = 0;
    let mut pass_per_category: BTreeMap<Category, usize> = BTreeMap::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();

    for r in results {
        if !seen.insert(r.id.clone()) {
            blocking.push(format!("{}:duplicate-result", r.id));
        }
        match r.verdict {
            Verdict::Pass => {
                passed += 1;
                *pass_per_category.entry(r.category).or_insert(0) += 1;
            }
            Verdict::Fail => failed += 1,
            Verdict::Inconclusive => inconclusive += 1,
            Verdict::NotApplicable => not_applicable += 1,
        }
        if r.blocks_release() {
            blocking.push(r.id.clone());
        }
        if r.verdict == Verdict::NotApplicable {
            let has_evidence = na_evidence
                .get(&r.id)
                .map(|e| valid_absence_evidence(e))
                .unwrap_or(false);
            if !has_evidence {
                blocking.push(format!("{}:N/A-without-absence-evidence", r.id));
            }
        }
    }

    // Canary rule: every canary that ran must PASS; a canary that did not
    // run at all also fails the gate (no vacuum PASS).
    for canary in CANARY_IDS {
        match results.iter().find(|r| &r.id == canary) {
            Some(r) if r.verdict == Verdict::Pass => {}
            Some(r) => blocking.push(format!("{canary}:canary-{:?}", r.verdict)),
            None => blocking.push(format!("{canary}:canary-missing")),
        }
    }

    // Per-category PASS minimums.
    for (category, min) in min_pass_per_category() {
        let got = pass_per_category.get(&category).copied().unwrap_or(0);
        if got < min {
            blocking.push(format!("{}:only-{got}-pass-min-{min}", category.label()));
        }
    }

    // Zero INCONCLUSIVE in blockers (fail-closed): already covered by
    // blocks_release, but stated explicitly for the report.
    let status = if blocking.is_empty() {
        "pass"
    } else {
        "failed"
    };
    let _ = registry_hash;
    GateReport {
        status: status.to_string(),
        passed,
        failed,
        inconclusive,
        not_applicable,
        blocking,
        results: results.to_vec(),
    }
}

/// CLI exit code for a gate report: 0 pass, 1 gate failure.
pub fn gate_exit_code(report: &GateReport) -> i32 {
    if report.status == "pass" {
        0
    } else {
        1
    }
}

#[cfg(test)]
mod exit_tests {
    use super::*;
    use crate::verify_ng::model::ClaimStrength;

    fn result(id: &str, category: Category, verdict: Verdict) -> ScenarioResult {
        ScenarioResult {
            id: id.to_string(),
            category,
            strength: ClaimStrength::Strong,
            verdict,
            detail: String::new(),
        }
    }

    fn full_pass_set() -> Vec<ScenarioResult> {
        vec![
            result("VFS-TRAV-001", Category::FsRead, Verdict::Pass),
            result("VFS-W-1", Category::FsWrite, Verdict::Pass),
            result("NET-DNS-IPV6-001", Category::Net, Verdict::Pass),
            result("PROC-ESC-001", Category::Proc, Verdict::Pass),
            result("ENV-LEAK-001", Category::Secrets, Verdict::Pass),
            result("RACE-BINDING-001", Category::Spawn, Verdict::Pass),
        ]
    }

    /// FM-12 GATE-VACUUM-001: empty suite must FAIL the gate, never pass.
    #[test]
    fn gate_vacuum_001_empty_suite_fails() {
        let report = evaluate_gate(&[], &BTreeMap::new(), "reg");
        assert_eq!(report.status, "failed");
        assert_eq!(gate_exit_code(&report), 1);
        assert!(report.blocking.iter().any(|b| b.contains("canary-missing")));
    }

    /// All-N/A suite must FAIL (missing canaries + minimums).
    #[test]
    fn all_na_suite_fails() {
        let results = vec![
            result("VFS-TRAV-001", Category::FsRead, Verdict::NotApplicable),
            result("ENV-LEAK-001", Category::Secrets, Verdict::NotApplicable),
        ];
        let mut ev = BTreeMap::new();
        ev.insert(
            "VFS-TRAV-001".to_string(),
            vec!["netns: absent (x)".to_string()],
        );
        ev.insert(
            "ENV-LEAK-001".to_string(),
            vec!["spawn: absent (y)".to_string()],
        );
        let report = evaluate_gate(&results, &ev, "reg");
        assert_eq!(report.status, "failed");
    }

    /// N/A without absence evidence blocks even a passing suite.
    #[test]
    fn na_without_evidence_blocks() {
        let mut results = full_pass_set();
        results.push(result(
            "WIN-WSL-001",
            Category::FsRead,
            Verdict::NotApplicable,
        ));
        let report = evaluate_gate(&results, &BTreeMap::new(), "reg");
        assert_eq!(report.status, "failed");
        assert!(report
            .blocking
            .iter()
            .any(|b| b.contains("N/A-without-absence-evidence")));
    }

    /// Arbitrary non-absence evidence must not justify NOT_APPLICABLE.
    #[test]
    fn malformed_na_evidence_blocks() {
        let mut results = full_pass_set();
        results.push(result(
            "WIN-WSL-001",
            Category::FsRead,
            Verdict::NotApplicable,
        ));
        let mut ev = BTreeMap::new();
        ev.insert("WIN-WSL-001".to_string(), vec!["looks absent".to_string()]);
        let report = evaluate_gate(&results, &ev, "reg");
        assert_eq!(report.status, "failed");
    }

    /// Duplicate scenario results cannot satisfy the gate.
    #[test]
    fn duplicate_result_id_blocks() {
        let mut results = full_pass_set();
        results.push(result("VFS-TRAV-001", Category::FsRead, Verdict::Pass));
        let report = evaluate_gate(&results, &BTreeMap::new(), "reg");
        assert_eq!(report.status, "failed");
        assert!(report
            .blocking
            .iter()
            .any(|b| b == "VFS-TRAV-001:duplicate-result"));
    }

    /// Full PASS set with N/A evidence passes.
    #[test]
    fn full_pass_set_passes() {
        let mut results = full_pass_set();
        results.push(result("WIN-WSL-001", Category::Aux, Verdict::NotApplicable));
        let mut ev = BTreeMap::new();
        ev.insert(
            "WIN-WSL-001".to_string(),
            vec!["wsl: absent (unmapped)".to_string()],
        );
        let report = evaluate_gate(&results, &ev, "reg");
        assert_eq!(report.status, "pass");
        assert_eq!(gate_exit_code(&report), 0);
    }

    /// One INCONCLUSIVE in a blocker fails the gate.
    #[test]
    fn inconclusive_in_blocker_fails() {
        let mut results = full_pass_set();
        results[2] = result("NET-DNS-IPV6-001", Category::Net, Verdict::Inconclusive);
        let report = evaluate_gate(&results, &BTreeMap::new(), "reg");
        assert_eq!(report.status, "failed");
    }
}
