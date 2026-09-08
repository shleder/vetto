//! verify-ng oracle/fixture/gate traps: prove the harness cannot be fooled.
//!
//! These tests run the compiled units (oracle, fixture, redact, exit gate)
//! through the library boundary plus the `verify-ng --lint` CLI surface.
//! They assert the failure modes FM-01..FM-12 stay closed: a deceitful
//! payload, a split control, a mutated fixture, a poisoned env, or an empty
//! suite must never produce a PASS / green gate.
//!
//! Hermetic rules: unit-level traps use only temp dirs; CLI traps use
//! `TempProject` + isolated HOME via `run_vetto_in` (which sets HOME to
//! `test_home()`).

use crate::common::*;
use vetto::verify_ng::{
    caps, engine, evidence, exit, fixture, frozen, model, oracle, redact, registry, report,
};

fn test_scenario(id: &str, category: model::Category, quorum: usize) -> registry::Scenario {
    registry::Scenario {
        id: id.to_string(),
        category,
        severity: registry::Severity::High,
        required_caps: vec![],
        strength: Default::default(),
        quorum,
        known_limitation: "trap".to_string(),
        residual_risk: String::new(),
    }
}

fn full_evidence_host_fact() -> evidence::Evidence {
    let mut e = evidence::Evidence::default();
    e.host_fact("postmortem", "absent".to_string());
    e
}

fn oracle_input<'a>(
    scenario: &'a registry::Scenario,
    evidence: &'a evidence::Evidence,
) -> oracle::OracleInput<'a> {
    oracle::OracleInput {
        scenario,
        evidence,
        nonce: Some("nonce-1"),
        probe_nonce: Some("nonce-1"),
        control_nonce: Some("nonce-1"),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
    }
}

/// FM-01 ORACLE-DECEIT-001: all-PASS self-report, no host fact -> not PASS.
#[test]
fn trap_oracle_deceit_self_report_only_is_not_pass() {
    let s = test_scenario("ORACLE-DECEIT-001", model::Category::Aux, 1);
    let mut e = evidence::Evidence::default();
    e.self_report("marker", "PASS PASS PASS".to_string());
    e.constrained("errno", "EACCES".to_string());
    let v = oracle::judge(&oracle_input(&s, &e));
    assert_eq!(
        v,
        model::Verdict::Inconclusive,
        "deceit payload must not PASS"
    );
}

/// FM-02 CONTROL-SPLIT-001: control without probe -> INCONCLUSIVE.
#[test]
fn trap_control_split_missing_probe_nonce_is_inconclusive() {
    let s = test_scenario("CONTROL-SPLIT-001", model::Category::Aux, 1);
    let e = full_evidence_host_fact();
    let mut input = oracle_input(&s, &e);
    input.probe_nonce = None;
    assert_eq!(oracle::judge(&input), model::Verdict::Inconclusive);
}

/// FM-02b: nonce mismatch between probe and control -> INCONCLUSIVE.
#[test]
fn trap_control_split_nonce_mismatch_is_inconclusive() {
    let s = test_scenario("CONTROL-SPLIT-001", model::Category::Aux, 1);
    let e = full_evidence_host_fact();
    let mut input = oracle_input(&s, &e);
    input.control_nonce = Some("other-nonce");
    assert_eq!(oracle::judge(&input), model::Verdict::Inconclusive);
}

/// FM-06 FIXTURE-MUTATE-001: self-rewriting payload invalidates the run.
#[test]
fn trap_fixture_mutation_is_detected() {
    let mut fx = fixture::Fixture::create("trap-mutate").expect("create fixture");
    let p = fx.stage("payload.sh", b"echo attack").expect("stage");
    std::fs::write(&p, b"echo PASS").expect("payload rewrites itself");
    let mutated = fx
        .verify_untouched()
        .expect_err("mutation must be detected");
    assert_eq!(mutated, vec![p]);

    let s = test_scenario("FIXTURE-MUTATE-001", model::Category::Aux, 1);
    let e = full_evidence_host_fact();
    let mut input = oracle_input(&s, &e);
    input.payload_intact = false;
    assert_eq!(oracle::judge(&input), model::Verdict::Inconclusive);
}

/// FM-08 ENV-POISON-001: poisoned diagnostic env -> FAIL on blockers.
/// The poison list is unit-constructed (never mutating process-global env).
#[test]
fn trap_env_poison_fails_blockers() {
    assert!(engine::POISON_ENV.contains(&"VETTO_SEATBELT_MODE"));
    let target = engine::current_target(Some("full"));
    let poison = vec!["VETTO_SEATBELT_MODE".to_string()];
    let blocker = test_scenario("VFS-TRAV-001", model::Category::FsRead, 2);
    let r = engine::poisoned_result(&blocker, target, &poison);
    assert_eq!(r.verdict, model::Verdict::Fail);
    assert!(r.blocks_release());
    let aux = test_scenario("ORACLE-DECEIT-001", model::Category::Aux, 1);
    let r = engine::poisoned_result(&aux, target, &poison);
    assert_eq!(r.verdict, model::Verdict::Inconclusive);
}

/// FM-12 GATE-VACUUM-001: empty suite must FAIL the gate, never pass.
#[test]
fn trap_gate_vacuum_empty_suite_fails() {
    let gate = exit::evaluate_gate(&[], &std::collections::BTreeMap::new(), "reg");
    assert_eq!(gate.status, "failed");
    assert_eq!(exit::gate_exit_code(&gate), 1);
}

/// FM-12b: all-N/A without canaries must FAIL the gate.
#[test]
fn trap_gate_all_na_fails_without_canaries() {
    let mk = |id: &str| model::ScenarioResult {
        id: id.to_string(),
        category: model::Category::FsRead,
        strength: model::ClaimStrength::Partial,
        verdict: model::Verdict::NotApplicable,
        detail: "x".to_string(),
    };
    let results = vec![mk("WIN-WSL-001")];
    let mut ev = std::collections::BTreeMap::new();
    ev.insert(
        "WIN-WSL-001".to_string(),
        vec!["wsl: absent (unmapped)".to_string()],
    );
    let gate = exit::evaluate_gate(&results, &ev, "reg");
    assert_eq!(gate.status, "failed");
}

/// FM-07 EVIDENCE-REDACT-001: secrets + bulk output never reach the report.
#[test]
fn trap_evidence_redaction_holds() {
    let evil = "AWS_SECRET_ACCESS_KEY=topsecretvalue99\n".to_string() + &"y".repeat(50_000);
    let redacted = redact::redact_text(&evil);
    assert!(!redacted.contains("topsecretvalue99"));
    assert!(redacted.len() <= redact::MAX_DETAIL + 32);
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nSENSITIVE\n-----END RSA PRIVATE KEY-----";
    assert!(!redact::redact_text(pem).contains("SENSITIVE"));
}

/// FM-03 RACE-BINDING-001: spec continuity detects drift between freeze and spawn.
#[test]
fn trap_spec_continuity_detects_drift() {
    let mk = |nonce: &str| frozen::FrozenSpec {
        scenario_id: "RACE-BINDING-001".to_string(),
        registry_hash: "r".to_string(),
        tier: "full".to_string(),
        net_mode: "off".to_string(),
        backend: "b".to_string(),
        argv: vec!["/bin/sh".to_string()],
        env: Default::default(),
        cwd: std::path::PathBuf::from("/tmp"),
        allow_read: vec![],
        allow_write: vec![],
        deny_read: vec![],
        deny_write: vec![],
        deny_resolved: vec![],
        nonce: nonce.to_string(),
    };
    assert!(engine::verify_spec_continuity(&mk("n"), &mk("n")));
    assert!(!engine::verify_spec_continuity(&mk("n"), &mk("m")));
}

/// FM-11 WIN-WSL-001: UNSUPPORTED ceiling can never PASS.
#[test]
fn trap_unsupported_ceiling_demotes_pass() {
    let v = oracle::apply_strength_ceiling(model::Verdict::Pass, model::ClaimStrength::Unsupported);
    assert_eq!(v, model::Verdict::Inconclusive);
}

/// FM-10 SEMANTICS-001 is covered in `model.rs`; here assert the report
/// carries both axes for a trap result.
#[test]
fn trap_report_carries_both_axes() {
    let gate = exit::GateReport {
        status: "failed".to_string(),
        passed: 0,
        failed: 1,
        inconclusive: 0,
        not_applicable: 0,
        blocking: vec!["ORACLE-DECEIT-001".to_string()],
        results: vec![model::ScenarioResult {
            id: "ORACLE-DECEIT-001".to_string(),
            category: model::Category::Aux,
            strength: model::ClaimStrength::Strong,
            verdict: model::Verdict::Inconclusive,
            detail: "d".to_string(),
        }],
    };
    let v = report::gate_report_json(&gate, "reg");
    assert_eq!(v["results"][0]["verdict"], "INCONCLUSIVE");
    assert_eq!(v["results"][0]["strength"], "STRONG");
}

/// CLI surface: `verify-ng --lint` passes on the shipped registry.
#[test]
fn cli_verify_ng_lint_passes() {
    let proj = TempProject::new("vng-lint");
    let out = run_vetto_in(proj.path(), &["verify-ng", "--lint"]);
    let text = stdout(&out);
    assert!(
        out.status.success(),
        "registry lint must pass: {text}\nstderr: {}",
        stderr(&out)
    );
    assert!(text.contains("lint clean"), "output: {text}");
}

/// CLI surface: `verify-ng --lint --json` is parseable.
#[test]
fn cli_verify_ng_lint_json_parseable() {
    let proj = TempProject::new("vng-lint-json");
    let out = run_vetto_in(proj.path(), &["verify-ng", "--lint", "--json"]);
    let text = stdout(&out);
    assert!(out.status.success(), "lint --json must pass: {text}");
    let value: serde_json::Value = serde_json::from_str(text.trim())
        .unwrap_or_else(|error| panic!("lint --json must emit JSON: {error}\n{text}"));
    assert!(value.get("registry_hash").is_some(), "hash: {value}");
    assert!(
        value
            .get("errors")
            .and_then(|e| e.as_array())
            .map(|e| e.is_empty())
            .unwrap_or(false),
        "errors: {value}"
    );
}

/// CLI surface: `verify-ng` without execution never reports PASS (FM-01 at
/// the CLI layer: the harness refuses hollow verdicts, gate fails closed).
#[test]
fn cli_verify_ng_without_suite_never_passes() {
    let proj = TempProject::new("vng-gate");
    let out = run_vetto_in(proj.path(), &["verify-ng"]);
    let text = stdout(&out);
    assert!(!out.status.success(), "gate must fail closed: {text}");
    // No hollow PASS verdict: check line-level `PASS` verdict tokens, not
    // substrings (gate strings like `only-0-pass-min-1` legitimately
    // contain "pass" in the honest INCONCLUSIVE report).
    for line in text.lines() {
        let first = line.split_whitespace().next().unwrap_or("");
        assert_ne!(first, "PASS", "no hollow PASS verdict: {text}");
    }
}

/// Capability skeleton: missing required caps surface as NOT_APPLICABLE
/// only with absence evidence (FM-12 shape check on the unit level).
#[test]
fn caps_missing_requires_evidence_shape() {
    let set = caps::CapabilitySet {
        capabilities: vec![caps::Capability::absent("netns", "no userns")],
    };
    let required = vec!["netns".to_string(), "never-probed-cap".to_string()];
    let missing = set.missing(&required);
    assert_eq!(missing.len(), 2);
    let ev = set.absence_evidence(&missing);
    assert!(ev.iter().any(|e| e.contains("no userns")));
    assert!(ev.iter().any(|e| e.contains("never probed")));
}

/// FM-13 quorum shape: multi-vector scenarios (VFS-TRAV-001 quorum=2,
/// NET-EXFIL-001 quorum=3) need >= quorum agreeing vectors, else INCONCLUSIVE.
#[test]
fn trap_quorum_shape_multivector_needs_agreeing_vectors() {
    for (id, category, quorum, agreeing) in [
        ("VFS-TRAV-001", model::Category::FsRead, 2, 1),
        ("VFS-WRITE-001", model::Category::FsWrite, 2, 1),
        ("NET-EXFIL-001", model::Category::Net, 3, 2),
        ("RACE-TOCTOU-001", model::Category::Spawn, 3, 2),
        ("PROC-TREE-001", model::Category::Proc, 2, 1),
        ("ENV-SECRETS-001", model::Category::Secrets, 2, 1),
        ("SEC-BLOCKS-001", model::Category::Spawn, 2, 1),
    ] {
        let s = test_scenario(id, category, quorum);
        let e = full_evidence_host_fact();
        let mut input = oracle_input(&s, &e);
        input.agreeing_vectors = agreeing;
        assert_eq!(
            oracle::judge(&input),
            model::Verdict::Inconclusive,
            "{id}: quorum={quorum} with {agreeing} agreeing must not PASS"
        );
        input.agreeing_vectors = quorum;
        assert_eq!(
            oracle::judge(&input),
            model::Verdict::Pass,
            "{id}: quorum met must PASS"
        );
    }
}

/// FM-13 quorum=1 single-vector scenarios still PASS with one vector.
#[test]
fn trap_quorum_one_single_vector_passes() {
    for (id, category) in [
        ("PROC-ESC-001", model::Category::Proc),
        ("ENV-LEAK-001", model::Category::Secrets),
        ("SHELL-ESC-001", model::Category::Spawn),
        ("WIN-WSL-001", model::Category::FsRead),
    ] {
        let s = test_scenario(id, category, 1);
        let e = full_evidence_host_fact();
        assert_eq!(
            oracle::judge(&oracle_input(&s, &e)),
            model::Verdict::Pass,
            "{id}"
        );
    }
}

/// FM-11 platform ceilings (static contract): seccomp surface is
/// NOT_APPLICABLE off Linux; WSL-interop is UNSUPPORTED (never PASS).
/// Unit-level shape: the ceiling demotes any judging PASS to INCONCLUSIVE.
#[test]
fn trap_platform_ceiling_shapes() {
    // SEC-BLOCKS-001 shape: macOS/Windows must be N/A-with-evidence, never PASS.
    // The ceiling function is the enforcement point: UNSUPPORTED + PASS -> INCONCLUSIVE.
    let v = oracle::apply_strength_ceiling(model::Verdict::Pass, model::ClaimStrength::Unsupported);
    assert_eq!(
        v,
        model::Verdict::Inconclusive,
        "unsupported ceiling demotes PASS"
    );
    // PARTIAL ceiling keeps the verdict (report carries both axes, no Partial-PASS).
    for verdict in [
        model::Verdict::Pass,
        model::Verdict::Fail,
        model::Verdict::Inconclusive,
    ] {
        assert_eq!(
            oracle::apply_strength_ceiling(verdict, model::ClaimStrength::Partial),
            verdict,
            "partial ceiling preserves {verdict:?}"
        );
    }
    // WIN-WSL-001 trap shape: Fail on UNSUPPORTED stays Fail (only PASS demotes).
    assert_eq!(
        oracle::apply_strength_ceiling(model::Verdict::Fail, model::ClaimStrength::Unsupported),
        model::Verdict::Fail
    );
}

/// FM-12 gate shape for iteration-2 suites: an fs-write PASS minimum exists,
/// so a gate without any fs-write PASS must stay red (no vacuum by category).
#[test]
fn trap_gate_requires_fs_write_minimum() {
    use std::collections::BTreeMap;
    let pass = |id: &str, category: model::Category| model::ScenarioResult {
        id: id.to_string(),
        category,
        strength: model::ClaimStrength::Strong,
        verdict: model::Verdict::Pass,
        detail: "x".to_string(),
    };
    // Full pass set WITHOUT fs-write: gate must fail on the category minimum.
    let results = vec![
        pass("VFS-TRAV-001", model::Category::FsRead),
        pass("NET-DNS-IPV6-001", model::Category::Net),
        pass("PROC-ESC-001", model::Category::Proc),
        pass("ENV-LEAK-001", model::Category::Secrets),
        pass("RACE-BINDING-001", model::Category::Spawn),
    ];
    let gate = exit::evaluate_gate(&results, &BTreeMap::new(), "reg");
    assert_eq!(
        gate.status, "failed",
        "gate without fs-write PASS must fail"
    );
    assert!(
        gate.blocking.iter().any(|b| b.contains("fs-write")),
        "blocking must name fs-write: {:?}",
        gate.blocking
    );
    // Adding VFS-WRITE-001 PASS closes the minimum (canaries still required).
    let mut closed = results;
    closed.push(pass("VFS-WRITE-001", model::Category::FsWrite));
    let gate = exit::evaluate_gate(&closed, &BTreeMap::new(), "reg");
    assert!(
        !gate.blocking.iter().any(|b| b.contains("fs-write")),
        "fs-write minimum closed: {:?}",
        gate.blocking
    );
}

/// FM-01/FM-14 shape for new blocker suites: violation observed by the host
/// beats any self-report; the collector never judges (oracle-only verdict).
#[test]
fn trap_host_violation_beats_self_report_new_suites() {
    for (id, category, quorum) in [
        ("VFS-WRITE-001", model::Category::FsWrite, 2),
        ("VFS-PROC-001", model::Category::FsRead, 2),
        ("NET-EXFIL-001", model::Category::Net, 3),
        ("SHELL-ESC-001", model::Category::Spawn, 2),
        ("ENV-SECRETS-001", model::Category::Secrets, 2),
        ("PROC-TREE-001", model::Category::Proc, 2),
        ("WIN-ESC-001", model::Category::Proc, 2),
        ("WIN-NET-001", model::Category::Net, 2),
    ] {
        let s = test_scenario(id, category, quorum);
        let mut e = full_evidence_host_fact();
        e.self_report("marker", "PASS PASS PASS".to_string());
        let mut input = oracle_input(&s, &e);
        input.agreeing_vectors = quorum;
        input.violation_observed = true;
        assert_eq!(
            oracle::judge(&input),
            model::Verdict::Fail,
            "{id}: host violation must FAIL despite self-report"
        );
    }
}

/// FM-06 shape for new suites: mutated payload invalidates every run,
/// including stress/fuzz/differential shapes.
#[test]
fn trap_payload_mutation_invalidates_new_suites() {
    for (id, category, quorum) in [
        ("RACE-TOCTOU-001", model::Category::Spawn, 3),
        ("STRESS-SWEEP-001", model::Category::Proc, 2),
        ("FUZZ-CORPUS-001", model::Category::Spawn, 2),
        ("TIER-DIFF-001", model::Category::Spawn, 2),
        ("SEC-BLOCKS-001", model::Category::Spawn, 2),
        ("RES-EXHAUST-001", model::Category::Proc, 2),
    ] {
        let s = test_scenario(id, category, quorum);
        let e = full_evidence_host_fact();
        let mut input = oracle_input(&s, &e);
        input.agreeing_vectors = quorum;
        input.payload_intact = false;
        assert_eq!(
            oracle::judge(&input),
            model::Verdict::Inconclusive,
            "{id}: mutated payload must be INCONCLUSIVE"
        );
    }
}

/// FM-08 shape for new suites: poisoned diagnostic env FAILs blockers,
/// INCONCLUSIVE on aux — including the new blocker batteries.
#[test]
fn trap_env_poison_fails_new_blockers() {
    let target = engine::current_target(Some("full"));
    let poison = vec!["VETTO_FORCE_TIER".to_string()];
    for (id, category, quorum) in [
        ("VFS-WRITE-001", model::Category::FsWrite, 2),
        ("NET-EXFIL-001", model::Category::Net, 3),
        ("SHELL-ESC-001", model::Category::Spawn, 2),
        ("WIN-ESC-001", model::Category::Proc, 2),
        ("WIN-NET-001", model::Category::Net, 2),
        ("SEC-BLOCKS-001", model::Category::Spawn, 2),
    ] {
        let s = test_scenario(id, category, quorum);
        let r = engine::poisoned_result(&s, target, &poison);
        assert_eq!(
            r.verdict,
            model::Verdict::Fail,
            "{id}: poisoned blocker must FAIL"
        );
        assert!(r.blocks_release());
    }
}
