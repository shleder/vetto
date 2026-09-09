//! Pure oracle: Scenario + Facts -> Verdict (FM-14).
//!
//! The oracle performs no I/O and never talks to the backend: no file
//! access, no sockets, no pipes, no environment reads, no process control.
//! All OS work lives in the runner / collector / host-evidence layer; the
//! oracle only judges already-structured evidence. The collector always
//! gathers the fixed superset of facts; the oracle only judges.
//! Structural rules (enforced here, not by convention):
//! - No host fact -> never PASS (FM-01).
//! - Nonce mismatch between control and probe -> INCONCLUSIVE (FM-02).
//! - Mutated payload -> INCONCLUSIVE (FM-06).
//! - Poisoned diagnostic env -> FAIL (blocker) / INCONCLUSIVE (aux) (FM-08).
//! - Quorum: multi-vector scenarios need >= quorum agreeing vectors (FM-13).
//! - Stage 2: PASS additionally needs identity-bound host control — a
//!   `HOST_FACT` control fact whose provenance exactly matches the current
//!   [`ExecutionIdentity`](super::evidence::ExecutionIdentity) (scenario +
//!   session nonce + registry hash + frozen hash). Replayed evidence from
//!   another session, scenario or registry is INCONCLUSIVE, never PASS.

use super::evidence::{Evidence, EvidenceTier, ExecutionIdentity};
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
    /// Current execution identity. PASS requires the verified control fact
    /// to carry exactly this identity; `None` (or malformed) can never PASS.
    /// Set by the host runner, never by the child.
    pub execution_identity: Option<&'a ExecutionIdentity>,
    /// Collection completeness observed by the host: both stdio streams
    /// reached EOF before the drain deadline AND neither was cut at the
    /// capture cap. PASS on incomplete evidence is impossible, even when
    /// every other condition holds (a host-observed violation still FAILs).
    pub stdio_complete: bool,
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
    // A host-observed violation is a FAIL regardless of self-reports and
    // regardless of collection completeness (the violation proof does not
    // depend on stdio).
    if input.violation_observed {
        return Verdict::Fail;
    }
    // PASS on incomplete evidence is impossible: truncated or never-EOF
    // collection degrades to INCONCLUSIVE even with everything else present.
    if !input.stdio_complete {
        return Verdict::Inconclusive;
    }
    // FM-01: PASS needs a host fact; FM-02: needs the control side effect.
    if !input.control_observed {
        return Verdict::Inconclusive;
    }
    // Stage 2 identity binding: the verified control fact must carry exactly
    // the current execution identity (scenario + session nonce + registry +
    // frozen). This rejects cross-session replay, wrong-scenario and
    // wrong-registry evidence as INCONCLUSIVE — forged bytes can never
    // become PASS here.
    let identity = match input.execution_identity {
        Some(id) if id.is_well_formed() => id,
        _ => return Verdict::Inconclusive,
    };
    if identity.scenario_id != input.scenario.id {
        return Verdict::Inconclusive;
    }
    if input.nonce != Some(identity.session_nonce.as_str()) {
        return Verdict::Inconclusive;
    }
    if !input.evidence.has_verified_control(identity) {
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
pub fn apply_strength_ceiling(verdict: Verdict, strength: super::model::ClaimStrength) -> Verdict {
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
        && !input
            .evidence
            .facts
            .iter()
            .any(|f| f.tier == EvidenceTier::HostFact)
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

    fn input<'a>(scenario: &'a Scenario, evidence: &'a Evidence) -> OracleInput<'a> {
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
            stdio_complete: true,
            execution_identity: None,
        }
    }

    /// Build an identity-bound verified setup for `scenario_id`: the token
    /// is derived and attested exactly like the host runner does, so the
    /// evidence carries a genuine verified control fact. Tests that expect
    /// PASS (or INCONCLUSIVE for a reason OTHER than identity) use this;
    /// tests for deceit/absence keep the legacy helper above.
    fn verified_setup(scenario_id: &str) -> (ExecutionIdentity, Evidence) {
        let id = ExecutionIdentity::new(scenario_id, "n", "reg-test", "frozen-test");
        let token = crate::verify_ng::evidence::derive_control_token("test-secret", &id);
        let verified = crate::verify_ng::evidence::attest_control(&id, &token, token.as_bytes())
            .expect("test attestation must mint");
        let mut e = Evidence::default();
        e.host_fact("postmortem", "absent".to_string());
        e.host_control_fact(&verified);
        (id, e)
    }

    /// Full PASS-shaped input with explicit identity wiring (no struct-update
    /// subtyping games: every reference is spelled out at the call site).
    #[allow(clippy::too_many_arguments)]
    fn full_input<'a>(
        scenario: &'a Scenario,
        evidence: &'a Evidence,
        nonce: Option<&'a str>,
        probe_nonce: Option<&'a str>,
        control_nonce: Option<&'a str>,
        payload_intact: bool,
        violation_observed: bool,
        control_observed: bool,
        stdio_complete: bool,
        agreeing_vectors: usize,
        identity: Option<&'a ExecutionIdentity>,
    ) -> OracleInput<'a> {
        OracleInput {
            scenario,
            evidence,
            nonce,
            probe_nonce,
            control_nonce,
            payload_intact,
            env_poisoned: false,
            agreeing_vectors,
            violation_observed,
            control_observed,
            stdio_complete,
            execution_identity: identity,
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

    /// FM-01 + Stage 2: identity-bound host fact + control + nonce -> PASS.
    /// Legacy host facts WITHOUT a verified identity-bound control fact
    /// stay INCONCLUSIVE even when every other condition holds.
    #[test]
    fn host_fact_with_control_passes() {
        let s = scenario();
        // Legacy shape (no verified control, no identity) cannot PASS.
        let mut legacy = Evidence::default();
        legacy.host_fact("postmortem", "absent".to_string());
        assert_eq!(judge(&input(&s, &legacy)), Verdict::Inconclusive);
        // Identity-bound verified control passes.
        let (id, e) = verified_setup(&s.id);
        let i = OracleInput {
            scenario: &s,
            evidence: &e,
            nonce: Some("n"),
            probe_nonce: Some("n"),
            control_nonce: Some("n"),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(&id),
        };
        assert_eq!(judge(&i), Verdict::Pass);
    }

    /// FM-02: control-only run (no probe nonce) -> INCONCLUSIVE.
    #[test]
    fn control_split_is_inconclusive() {
        let s = scenario();
        let (id, e) = verified_setup(&s.id);
        let mut i = OracleInput {
            scenario: &s,
            evidence: &e,
            nonce: Some("n"),
            probe_nonce: None,
            control_nonce: Some("n"),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(&id),
        };
        assert_eq!(judge(&i), Verdict::Inconclusive);
        // Missing identity is INCONCLUSIVE too, even with verified control.
        i.probe_nonce = Some("n");
        i.execution_identity = None;
        assert_eq!(judge(&i), Verdict::Inconclusive);
    }

    /// Stage 2 replay/scenario/registry binding: verified evidence from any
    /// other identity is INCONCLUSIVE, never PASS.
    #[test]
    fn foreign_identity_evidence_is_inconclusive() {
        let s = scenario();
        let (id, e) = verified_setup(&s.id);
        // Own identity passes (sanity).
        let own = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&id),
        );
        assert_eq!(judge(&own), Verdict::Pass);
        // Cross-session replay: same scenario, different session nonce.
        let other_session = ExecutionIdentity::new(&s.id, "nonce-B", "reg-test", "frozen-test");
        let replay = full_input(
            &s,
            &e,
            Some("nonce-B"),
            Some("nonce-B"),
            Some("nonce-B"),
            true,
            false,
            true,
            true,
            1,
            Some(&other_session),
        );
        assert_eq!(judge(&replay), Verdict::Inconclusive);
        // Wrong scenario: evidence identity names another scenario.
        let mut other_scenario = scenario();
        other_scenario.id = "OTHER".to_string();
        let wrong_scen = full_input(
            &other_scenario,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&id),
        );
        assert_eq!(judge(&wrong_scen), Verdict::Inconclusive);
        // Wrong registry: current execution runs under another registry.
        let other_registry = ExecutionIdentity::new(&s.id, "n", "reg-B", "frozen-test");
        let wrong_reg = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&other_registry),
        );
        assert_eq!(judge(&wrong_reg), Verdict::Inconclusive);
        // Wrong frozen spec: same registry, different frozen identity.
        let other_frozen = ExecutionIdentity::new(&s.id, "n", "reg-test", "frozen-B");
        let wrong_frozen = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&other_frozen),
        );
        assert_eq!(judge(&wrong_frozen), Verdict::Inconclusive);
        // Malformed identity can never PASS.
        let malformed = ExecutionIdentity::new(&s.id, "", "reg-test", "frozen-test");
        let bad = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&malformed),
        );
        assert_eq!(judge(&bad), Verdict::Inconclusive);
    }

    /// FM-06: mutated payload -> INCONCLUSIVE even with host facts.
    #[test]
    fn mutated_payload_is_inconclusive() {
        let s = scenario();
        let (id, e) = verified_setup(&s.id);
        let i = OracleInput {
            scenario: &s,
            evidence: &e,
            nonce: Some("n"),
            probe_nonce: Some("n"),
            control_nonce: Some("n"),
            payload_intact: false,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(&id),
        };
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

    /// FM-13: quorum not met -> INCONCLUSIVE (with valid identity-bound
    /// control, so the failure is the quorum itself, not the identity).
    #[test]
    fn quorum_not_met_is_inconclusive() {
        let mut s = scenario();
        s.quorum = 2;
        let (id, e) = verified_setup(&s.id);
        let i = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            1,
            Some(&id),
        );
        assert_eq!(judge(&i), Verdict::Inconclusive);
        let i = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            true,
            2,
            Some(&id),
        );
        assert_eq!(judge(&i), Verdict::Pass);
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

    /// Incomplete stdio collection can never PASS, even with verified
    /// identity-bound control + nonce + quorum all present.
    #[test]
    fn incomplete_collection_cannot_pass() {
        let s = scenario();
        let (id, e) = verified_setup(&s.id);
        let i = full_input(
            &s,
            &e,
            Some("n"),
            Some("n"),
            Some("n"),
            true,
            false,
            true,
            false,
            1,
            Some(&id),
        );
        assert_eq!(judge(&i), Verdict::Inconclusive);
    }
}
