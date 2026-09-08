//! Human + machine-readable reports (JSON via serde; text renderer).
//!
//! All detail strings pass through [`crate::verify_ng::redact`] before
//! rendering (FM-07). JSON is the machine contract; text is the dense
//! human table.

use super::exit::GateReport;
use super::model::ScenarioResult;

/// JSON value of a gate report (machine contract).
pub fn gate_report_json(report: &GateReport, registry_hash: &str) -> serde_json::Value {
    serde_json::json!({
        "tool": "vetto verify-ng",
        "registry_hash": registry_hash,
        "status": report.status,
        "passed": report.passed,
        "failed": report.failed,
        "inconclusive": report.inconclusive,
        "not_applicable": report.not_applicable,
        "blocking": report.blocking,
        "results": report.results.iter().map(scenario_json).collect::<Vec<_>>(),
    })
}

fn scenario_json(r: &ScenarioResult) -> serde_json::Value {
    serde_json::json!({
        "id": r.id,
        "category": r.category.label(),
        "strength": r.strength.label(),
        "verdict": r.verdict.label(),
        "detail": r.detail,
    })
}

/// Dense human-readable table.
pub fn render_text(report: &GateReport) -> String {
    let mut out = String::new();
    out.push_str(&report.summary());
    out.push('\n');
    for r in &report.results {
        out.push_str(&format!(
            "  {:<11} {:<8} {:<11} {} {}\n",
            r.verdict.label(),
            r.category.label(),
            r.strength.label(),
            r.id,
            r.detail
        ));
    }
    if !report.blocking.is_empty() {
        out.push_str("blocking:\n");
        for b in &report.blocking {
            out.push_str(&format!("  - {b}\n"));
        }
    }
    out
}

#[cfg(test)]
mod report_tests {
    use super::*;
    use crate::verify_ng::model::Category;
    use crate::verify_ng::model::{ClaimStrength, Verdict};

    #[test]
    fn json_carries_both_axes() {
        let report = GateReport {
            status: "failed".to_string(),
            passed: 0,
            failed: 1,
            inconclusive: 0,
            not_applicable: 0,
            blocking: vec!["X".to_string()],
            results: vec![ScenarioResult {
                id: "X".to_string(),
                category: Category::Net,
                strength: ClaimStrength::Partial,
                verdict: Verdict::Fail,
                detail: "d".to_string(),
            }],
        };
        let v = gate_report_json(&report, "reg");
        assert_eq!(v["results"][0]["verdict"], "FAIL");
        assert_eq!(v["results"][0]["strength"], "PARTIAL");
        assert_eq!(v["registry_hash"], "reg");
    }
}
