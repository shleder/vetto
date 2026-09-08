//! Pure oracle: Scenario + Facts -> Verdict (FM-14).
//!
//! The oracle performs no I/O and never talks to the backend. The collector
//! always gathers the fixed superset of facts; the oracle only judges.
//! Structural rules (enforced here, not by convention):
//! - No host fact -> never PASS (FM-01).
//! - Nonce mismatch between control and probe -> INCONCLUSIVE (FM-02).
//! - Mutated payload -> INCONCLUSIVE (FM-06).
//! - Poisoned diagnostic env -> FAIL (blocker) / INCONCLUSIVE (aux) (FM-08).
//! - Quorum: multi-vector scenarios need >= quorum agreeing vectors (FM-13).

use super::evidence::{Evidence, EvidenceTier};
use super::model::{Category, Verdict};
use super::registry::Scenario;

/// Input to the oracle: everything collected for one run.
#[derive(Debug, Clone)]
pub struct OracleInput<'a> {
    pub scenario: &'a Scenario,
    pub evidence: &'a Evidence,
    /// Session nonce issued by the engine (None = engine failure).
    pub nonce: Option<&'a str>,
    /// Nonce echoed by the negative probe through the constrained channel.
    pub probe_nonce: Option<&'a str>,
    /// Nonce echoed by the positive control through the host-visible side effect.
    pub control_nonce: Option<&'a str>,
    /// Pre/post payload hashes matched.
    pub payload_intact: bool,
    /// Diagnostic env interference detected (VETTO_SEATBELT_MODE, ...).
    pub env_poisoned: bool,
    /// Number of independent agreeing vectors observed (quorum, FM-13).
    pub agreeing_vectors: usize,
    /// Host-observed violation flag (leak/write/reach/escape/residue).
    pub violation_observed: bool,
    /// Host-observed positive control flag (canary side effect verified).
    pub control_observed: bool,
}

pub fn judge(input: &OracleInput<'_>) -> Verdict {
    // FM-08: poisoned diagnostic env invalidates the run.
    if input.env_poisoned {
        return match input.scenario.category {
            Category::Aux => Verdict::Inconclusive,
            _ => Verdict::Fail,
        };
    }
    // FM-06: mutated fixture invalidates the run.
    if !input.payload_intact {
        return Verdict::Inconclusive;
    }
    // FM-02: control and probe must be bound to the same session nonce.
    match (input.nonce, input.probe_nonce, input.control_nonce) {
        (Some(n), Some(p), Some(c)) if p == n && c == n => {}
        _ => return Verdict::Inconclusive,
    }
    // A host-observed violation is a FAIL regardless of self-reports.
    if input.violation_observed {
        return Verdict::Fail;
    }
    // FM-01: PASS needs a host fact; FM-02: needs the control side effect.
    if !input.control_observed {
        return Verdict::Inconclusive;
    }
    if !input.evidence.has_host_fact() {
        return Verdict::Inconclusive;
    }
    // FM-13: quorum over independent vectors.
    if input.agreeing_vectors < input.scenario.quorum.max(1) {
        return Verdict::Inconclusive;
    }
    // Oracle-judged PASS is only valid on provable claims; UNSUPPORTED
    // ceilings can never PASS (FM-11: WIN-WSL-001 baseline).
    Verdict::Pass
}

/// Post-filter: an UNSUPPORTED strength claim must never report PASS;
/// a judging bug that yields one is demoted to INCONCLUSIVE loudly.
pub fn apply_strength_ceiling(
    verdict: Verdict,
    strength: super::model::ClaimStrength,
) -> Verdict {
    match (verdict, strength) {
        (Verdict::Pass, super::model::ClaimStrength::Unsupported) => Verdict::Inconclusive,
        _ => verdict,
    }
}

/// Convenience: judge and apply the ceiling in one step.
pub fn judge_with_ceiling(
    input: &OracleInput<'_>,
    strength: super::model::ClaimStrength,
    host_value: Option<&str>,
) -> Verdict {
    let _ = host_value;
    let v = judge(input);
    // Self-report-only "evidence" can never smuggle a PASS through:
    // `judge` already requires a host fact, this is belt-and-braces for
    // callers that bypass `judge` (there must be none).
    let v = if v == Verdict::Pass
        && !input.evidence.facts.iter().any(|f| f.tier == EvidenceTier::HostFact)
    {
        Verdict::Inconclusive
    } else {
        v
    };
    apply_strength_ceiling(v, strength)
}

#[cfg(test)]
mod oracle_tests {
    use super::*;
    use crate::verify_ng::model::ClaimStrength;
    use crate::verify_ng::registry::Severity;

    fn scenario() -> Scenario {
        Scenario {
            id: "T".to_string(),
            category: Category::FsRead,
            severity: Severity::High,
            required_caps: vec![],
            strength: Default::default(),
            quorum: 1,
            known_limitation: "test".to_string(),
            residual_risk: String::new(),
        }
    }

    fn input<'a>(
        scenario: &'a Scenario,
        evidence: &'a Evidence,
    ) -> OracleInput<'a> {
        OracleInput {
            scenario,
            evidence,
            nonce: Some("n"),
            probe_nonce: Some("n"),
            control_nonce: Some("n"),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
        }
    }

    /// FM-01: self-report-only evidence can never PASS.
    #[test]
    fn oracle_deceit_trap_self_report_only_is_not_pass() {
        let s = scenario();
        let mut e = Evidence::default();
        e.self_report("marker", "PASS PASS PASS".to_string());
        e.constrained("errno", "EACCES".to_string());
        let v = judge(&input(&s, &e));
        assert_eq!(v, Verdict::Inconclusive);
    }

    /// FM-01: host fact + control + nonce -> PASS.
    #[test]
    fn host_fact_with_control_passes() {
        let s = scenario();
        let mut e = Evidence::default();
        e.host_fact("postmortem", "absent".to_string());
        let v = judge(&input(&s, &e));
        assert_eq!(v, Verdict::Pass);
    }

    /// FM-02: control-only run (no probe nonce) -> INCONCLUSIVE.
    #[test]
    fn control_split_is_inconclusive() {
        let s = scenario();
        let mut e = Evidence::default();
        e.host_fact("control", "ok".to_string());
        let mut i = input(&s, &e);
        i.probe_nonce = None;
        assert_eq!(judge(&i), Verdict::Inconclusive);
    }

    /// FM-06: mutated payload -> INCONCLUSIVE even with host facts.
    #[test]
    fn mutated_payload_is_inconclusive() {
        let s = scenario();
        let mut e = Evidence::default();
        e.host_fact("postmortem", "absent".to_string());
        let mut i = input(&s, &e);
        i.payload_intact = false;
        assert_eq!(judge(&i), Verdict::Inconclusive);
    }

    /// Violation observed by the host -> FAIL even with PASS markers.
    #[test]
    fn host_violation_beats_self_report() {
        let s = scenario();
        let mut e = Evidence::default();
        e.host_fact("postmortem", "LEAK bytes present".to_string());
        e.self_report("marker", "PASS".to_string());
        let mut i = input(&s, &e);
        i.violation_observed = true;
        assert_eq!(judge(&i), Verdict::Fail);
    }

    /// FM-13: quorum not met -> INCONCLUSIVE.
    #[test]
    fn quorum_not_met_is_inconclusive() {
        let mut s = scenario();
        s.quorum = 2;
        let mut e = Evidence::default();
        e.host_fact("postmortem", "absent".to_string());
        let mut i = input(&s, &e);
        i.agreeing_vectors = 1;
        assert_eq!(judge(&i), Verdict::Inconclusive);
    }

    /// FM-11: UNSUPPORTED ceiling can never PASS.
    #[test]
    fn unsupported_ceiling_demotes_pass() {
        assert_eq!(
            apply_strength_ceiling(Verdict::Pass, ClaimStrength::Unsupported),
            Verdict::Inconclusive
        );
        assert_eq!(
            apply_strength_ceiling(Verdict::Fail, ClaimStrength::Unsupported),
            Verdict::Fail
        );
    }
}
