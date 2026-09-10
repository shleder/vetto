//! Stage 2 challenge-response host evidence: non-self-authorizing control.
//!
//! Non-self-authorization invariant: the attacker cannot obtain PASS merely
//! by replaying or echoing a verifier-issued capability. The host never
//! issues a PASS-capable value: it buffers a fresh per-execution challenge
//! into the host downlink pre-spawn, and only the exact rotated response
//! (`rotate(challenge + session_nonce)`) arriving on the host uplink
//! verifies. The child receives only FIFO paths plus the run-label nonce.
//!
//! Adversarial pair (same capabilities, different verdicts):
//!
//! - legitimate payload: reads the challenge, rotates, answers -> PASS;
//! - malicious payload: knows every env var/pathname/contract the verifier
//!   issues (it reads the challenge too) but only echoes/copies/forwards
//!   verifier material instead of rotating -> INCONCLUSIVE, never PASS.
//!
//! Unix-only: the FIFO channel has no non-Unix backend yet; there the runs
//! degrade to control-unobserved (INCONCLUSIVE, never PASS) by construction.

use std::collections::BTreeMap;
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::verify_ng::evidence::{self, Evidence, EvidenceTier, ExecutionIdentity};
use vetto::verify_ng::oracle::{self, OracleInput};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::{engine, model, runner};

fn aux_scenario(id: &str) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category: model::Category::Aux,
        severity: Severity::High,
        required_caps: vec!["spawn".to_string()],
        strength: BTreeMap::from([(target.label().to_string(), model::ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "host-control pipeline self-test only; proves no enforcement claim"
            .to_string(),
        residual_risk: String::new(),
    }
}

fn blocker_scenario(id: &str) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category: model::Category::FsRead,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string()],
        strength: BTreeMap::from([(target.label().to_string(), model::ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "direct-exec proves no containment; must stay INCONCLUSIVE".to_string(),
        residual_risk: String::new(),
    }
}

fn request_with_control<'a>(
    scenario: &'a Scenario,
    policy: &'a Policy,
    net: &'a NetMode,
    script: &str,
    deadline: Duration,
) -> runner::ExecutionRequest<'a> {
    runner::ExecutionRequest {
        scenario,
        policy,
        net_mode: net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels: Vec::new(),
        env_extra: BTreeMap::new(),
        deadline,
        enable_host_control: true,
    }
}

/// Legitimate positive behavior: read the fresh challenge from the host
/// downlink, rotate (`challenge` + run-label nonce, last 8 chars to front
/// via POSIX parameter expansion), answer on the host uplink.
const POSITIVE_SCRIPT: &str = concat!(
    "echo marker-stdout\n",
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "S=\"$C$VETTO_VNG_NONCE\"\n",
    "head=${S%????????}\n",
    "tail=${S#$head}\n",
    "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
    "exit 0\n",
);

/// Literal echo: read the challenge and copy it back unrotated. Must never
/// verify — echoing is not performing the behavior.
const ECHO_SCRIPT: &str = concat!(
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "printf %s \"$C\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
    "exit 0\n",
);

fn assert_single_spawn(log: &runner::SpawnLog, out: &runner::ExecutionOutcome) {
    assert_eq!(log.len(), 1, "one scenario must spawn exactly once");
    assert_eq!(log[0].run_id, out.nonce, "spawn event binds to the run");
    assert_eq!(out.spawn_pid, Some(log[0].pid));
}

fn host_fact_values(out: &runner::ExecutionOutcome) -> Vec<&str> {
    out.evidence
        .facts
        .iter()
        .filter(|f| f.tier == EvidenceTier::HostFact)
        .map(|f| f.value.as_str())
        .collect()
}

/// TEST-HOST-CONTROL-POSITIVE-001: the legitimate payload performs the
/// required behavior (read fresh challenge, rotate, answer); the host
/// observes the independent consequence (exact rotated response on its own
/// uplink end); identity correct; payload intact; stdio complete; quorum
/// met -> PASS. Proves pipeline liveness only, never containment (Aux).
#[test]
fn test_host_control_positive_001_legitimate_behavior_passes() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-POSITIVE-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario,
        &policy,
        &net,
        POSITIVE_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdio_complete, "clean run collects completely");
    assert!(out.payload_intact, "staged script untouched");
    assert!(!out.violation_observed);
    assert!(
        out.control_observed,
        "host must observe the rotated response"
    );

    // PASS invariants: verdict + strength + identity + quorum inputs.
    assert_eq!(out.result.verdict, model::Verdict::Pass);
    assert_ne!(out.result.strength, model::ClaimStrength::Unsupported);
    let id = &out.execution_identity;
    assert!(id.is_well_formed(), "identity fully bound");
    assert_eq!(id.scenario_id, scenario.id);
    assert_eq!(id.session_nonce, out.nonce);
    assert_eq!(
        id.registry_hash,
        vetto::verify_ng::registry::registry_hash_full(&vetto::verify_ng::registry::registry()),
        "registry identity matches the compiled registry"
    );
    assert!(!id.frozen_hash.is_empty(), "frozen spec bound");
    assert!(
        out.evidence.has_verified_control(id),
        "verified control fact stamped for this identity"
    );
    // Child stdout is collected but never leaks into HOST_FACT values.
    assert!(String::from_utf8_lossy(&out.stdout).contains("marker-stdout"));
    for v in host_fact_values(&out) {
        assert!(
            !v.contains("marker-stdout"),
            "child text must not leak into HOST_FACT: {v:?}"
        );
    }
    for f in &out.evidence.facts {
        if f.name == "stdout" || f.name == "stderr" {
            assert_eq!(f.tier, EvidenceTier::SelfReport, "stdio is never HOST_FACT");
        }
    }
}

/// CONTROL-SPLIT-001 part A: the nonce-binding contract over the real
/// challenge-response channel is PASS-capable for the legitimate answer.
/// (Part B — forged legacy control — stays in `verify_ng_execution.rs` and
/// must remain INCONCLUSIVE.)
#[test]
fn test_control_split_001_legitimate_host_control_passes() {
    let scenario = aux_scenario("CONTROL-SPLIT-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario,
        &policy,
        &net,
        POSITIVE_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert!(out.control_observed);
    assert!(out.evidence.has_verified_control(&out.execution_identity));
    assert_eq!(
        out.result.verdict,
        model::Verdict::Pass,
        "legitimate challenge-response must be PASS-capable"
    );
}

/// TEST-HOST-CONTROL-ECHO-001: literal echo of the challenge back to the
/// verifier. Expected: INCONCLUSIVE, never PASS.
#[test]
fn test_host_control_echo_001_challenge_echo_cannot_pass() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-ECHO-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario,
        &policy,
        &net,
        ECHO_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdio_complete, "echo attempt itself collects cleanly");
    assert!(
        !out.control_observed,
        "unrotated challenge echo must not verify"
    );
    assert!(
        !out.evidence.has_verified_control(&out.execution_identity),
        "no verified fact from echoed bytes"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "challenge echo must never PASS"
    );
}

/// TEST-HOST-CONTROL-SELF-AUTH-001: malicious payload with FULL knowledge
/// of every env capability the verifier issues (it even reads the fresh
/// challenge) that only echoes/copies/forwards verifier material and never
/// performs the rotation. Adversarial pair to POSITIVE-001: same
/// capabilities, must get a different verdict — INCONCLUSIVE, never PASS.
#[test]
fn test_host_control_self_auth_001_copy_without_behavior_cannot_pass() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-SELF-AUTH-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = concat!(
        "echo PASS\n",
        "echo HOST_FACT >&2\n",
        "echo VERIFIED\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_ROOT/control.txt\"\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_HOME/forge.txt\"\n",
        // Full-knowledge copy: read the fresh challenge, forward it
        // literally (twice), leak it to files and stdout — but never rotate.
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "printf %s \"$C\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "printf %s \"$C\" >> \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "printf %s \"$C\" > \"$VETTO_VNG_HOME/challenge.txt\"\n",
        "echo \"$C\"\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_HOME/uplink\"\n",
        "exit 0\n",
    );
    let req = request_with_control(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdio_complete, "copy attempt itself collects cleanly");
    assert!(
        !out.control_observed,
        "copy/forward without rotation must not verify"
    );
    assert!(
        !out.evidence.has_verified_control(&out.execution_identity),
        "no verified fact from copied material"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "self-authorizing copy must never PASS"
    );
    for v in host_fact_values(&out) {
        assert!(
            !v.contains("PASS") && !v.contains("VERIFIED"),
            "child markers must not leak into HOST_FACT: {v:?}"
        );
    }
}

/// TEST-HOST-CONTROL-FORGE-001: every child-controlled medium — stdout,
/// stderr, HOME files, fixture files, a hardcoded stale response, a write
/// to a wrong (host-unread) path — without reading the challenge at all.
/// Nothing here, alone or combined, may yield PASS.
#[test]
fn test_host_control_forge_001_child_media_cannot_pass() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-FORGE-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = concat!(
        "echo PASS\n",
        "echo HOST_FACT >&2\n",
        "echo VERIFIED\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_ROOT/control.txt\"\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_HOME/forge.txt\"\n",
        "printf 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_HOME/uplink\"\n",
        "exit 0\n",
    );
    let req = request_with_control(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdio_complete, "forge attempt itself collects cleanly");
    assert!(
        !out.control_observed,
        "stale/wrong-medium bytes must not verify"
    );
    assert!(
        !out.evidence.has_verified_control(&out.execution_identity),
        "no verified fact from forged bytes"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "forged control must never PASS"
    );
    for v in host_fact_values(&out) {
        assert!(
            !v.contains("PASS") && !v.contains("VERIFIED"),
            "child markers must not leak into HOST_FACT: {v:?}"
        );
    }
}

/// Correct response written twice: exact-match verification rejects the
/// 128-byte concatenation. Prefix/content acceptance would be a
/// self-authorization hole; only the exact rotation verifies.
#[test]
fn test_host_control_duplicate_response_rejected() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-DUPLICATE-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = concat!(
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "S=\"$C$VETTO_VNG_NONCE\"\n",
        "head=${S%????????}\n",
        "tail=${S#$head}\n",
        "R=\"$tail$head\"\n",
        "printf %s \"$R$R\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "exit 0\n",
    );
    let req = request_with_control(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert!(
        !out.control_observed,
        "duplicated correct response must not verify"
    );
    assert_ne!(
        out.result.verdict,
        model::Verdict::Pass,
        "duplicate write must never PASS"
    );
}

/// TEST-HOST-EVIDENCE-REPLAY-001 + TEST-HOST-CONTROL-REPLAY-001: valid
/// evidence from execution A used in execution B must be INCONCLUSIVE/FAIL,
/// never PASS — in both directions. The fresh per-execution challenge makes
/// cross-session responses mismatch even before the provenance gate.
#[test]
fn test_host_evidence_replay_001_cross_session_replay_rejected() {
    let run = || {
        let scenario = aux_scenario("TEST-HOST-EVIDENCE-REPLAY-001");
        let policy = Policy::default();
        let net = NetMode::Off;
        let req = request_with_control(
            &scenario,
            &policy,
            &net,
            POSITIVE_SCRIPT,
            Duration::from_secs(15),
        );
        let mut log = runner::SpawnLog::new();
        let out = runner::run_one(&req, &mut log);
        assert_single_spawn(&log, &out);
        assert_eq!(out.result.verdict, model::Verdict::Pass);
        (scenario, policy, net, out)
    };
    let (scenario_a, _, _, out_a) = run();
    let (_, _, _, out_b) = run();
    assert_ne!(out_a.nonce, out_b.nonce, "test needs two distinct sessions");

    // A-evidence judged under B-identity, and vice versa.
    for (ev, id, nonce, label) in [
        (
            &out_a.evidence,
            &out_b.execution_identity,
            out_b.nonce.as_str(),
            "A-in-B",
        ),
        (
            &out_b.evidence,
            &out_a.execution_identity,
            out_a.nonce.as_str(),
            "B-in-A",
        ),
    ] {
        assert!(
            !ev.has_verified_control(id),
            "{label}: foreign evidence must not match"
        );
        let input = OracleInput {
            scenario: &scenario_a,
            evidence: ev,
            nonce: Some(nonce),
            probe_nonce: Some(nonce),
            control_nonce: Some(nonce),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(id),
        };
        assert_ne!(
            oracle::judge(&input),
            model::Verdict::Pass,
            "{label}: replayed evidence must never PASS"
        );
        assert_eq!(
            oracle::judge(&input),
            model::Verdict::Inconclusive,
            "{label}: replay degrades to INCONCLUSIVE"
        );
    }
}

/// TEST-HOST-CONTROL-WRONG-SCENARIO-001: evidence for scenario A judged as
/// scenario B must be INCONCLUSIVE/FAIL, never PASS.
#[test]
fn test_host_control_wrong_scenario_001_rejected() {
    let scenario_a = aux_scenario("TEST-HOST-CONTROL-WRONG-SCENARIO-001-A");
    let scenario_b = aux_scenario("TEST-HOST-CONTROL-WRONG-SCENARIO-001-B");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario_a,
        &policy,
        &net,
        POSITIVE_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);
    assert_eq!(out.result.verdict, model::Verdict::Pass);

    let nonce = out.nonce.as_str();
    let input = OracleInput {
        scenario: &scenario_b,
        evidence: &out.evidence,
        nonce: Some(nonce),
        probe_nonce: Some(nonce),
        control_nonce: Some(nonce),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&out.execution_identity),
    };
    assert_ne!(
        oracle::judge(&input),
        model::Verdict::Pass,
        "wrong-scenario evidence must never PASS"
    );
}

/// TEST-HOST-CONTROL-WRONG-REGISTRY-001: evidence minted under registry A
/// judged under registry/frozen identity B must be INCONCLUSIVE/FAIL.
#[test]
fn test_host_control_wrong_registry_001_rejected() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-WRONG-REGISTRY-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario,
        &policy,
        &net,
        POSITIVE_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);
    assert_eq!(out.result.verdict, model::Verdict::Pass);

    let nonce = out.nonce.as_str();
    for (mut id, label) in [
        (out.execution_identity.clone(), "registry"),
        (out.execution_identity.clone(), "frozen"),
    ] {
        if label == "registry" {
            id.registry_hash = "deadbeef-wrong-registry".to_string();
        } else {
            id.frozen_hash = "deadbeef-wrong-frozen".to_string();
        }
        assert!(
            !out.evidence.has_verified_control(&id),
            "{label}: foreign identity must not match"
        );
        let input = OracleInput {
            scenario: &scenario,
            evidence: &out.evidence,
            nonce: Some(nonce),
            probe_nonce: Some(nonce),
            control_nonce: Some(nonce),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(&id),
        };
        assert_ne!(
            oracle::judge(&input),
            model::Verdict::Pass,
            "wrong-{label} evidence must never PASS"
        );
    }
}

/// Even a CORRECTLY performed behavior cannot turn a host-observed
/// violation into PASS: sentinel trip + valid rotated response must FAIL.
#[test]
fn test_host_control_valid_response_cannot_mask_violation() {
    let scenario = aux_scenario("TEST-HOST-CONTROL-VIOLATION-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = concat!(
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "S=\"$C$VETTO_VNG_NONCE\"\n",
        "head=${S%????????}\n",
        "tail=${S#$head}\n",
        "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "echo pwned > \"$VETTO_VNG_ROOT/canary.txt\"\n",
    );
    let mut req = request_with_control(&scenario, &policy, &net, script, Duration::from_secs(15));
    req.sentinels = vec![("canary.txt".to_string(), b"do-not-touch".to_vec())];
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert!(out.violation_observed);
    assert!(out.control_observed, "response was genuinely correct");
    assert_eq!(
        out.result.verdict,
        model::Verdict::Fail,
        "host-observed violation must FAIL despite correct behavior"
    );
}

/// Direct backend proves no containment: a blocker-category run with the
/// correct behavior and no violation must stay INCONCLUSIVE, never PASS.
#[test]
fn test_host_control_blocker_stays_inconclusive_on_direct() {
    let scenario = blocker_scenario("TEST-HOST-CONTROL-BLOCKER-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request_with_control(
        &scenario,
        &policy,
        &net,
        POSITIVE_SCRIPT,
        Duration::from_secs(15),
    );
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(!out.violation_observed);
    assert!(out.control_observed, "behavior observed even for blockers");
    assert_ne!(
        out.result.verdict,
        model::Verdict::Pass,
        "blocker property unprovable on direct-exec"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "blocker without enforcement proof degrades to INCONCLUSIVE"
    );
}

/// Unit shape of the attestation boundary through the public API: only the
/// exact rotated response mints; echoes of challenge/nonce/concatenation,
/// duplicates, and foreign identities never do.
#[test]
fn test_host_control_attest_boundary_shapes() {
    let id = ExecutionIdentity::new("S", "n", "r", "f");
    let challenge = "0123456789abcdef0123456789abcdef";
    let expected = evidence::derive_expected_response(challenge, "n");
    assert!(evidence::attest_control(&id, &expected, expected.as_bytes()).is_some());
    // Every echo/copy shape fails.
    assert!(evidence::attest_control(&id, &expected, challenge.as_bytes()).is_none());
    assert!(evidence::attest_control(&id, &expected, b"n").is_none());
    let plain = format!("{challenge}n");
    assert!(evidence::attest_control(&id, &expected, plain.as_bytes()).is_none());
    assert!(evidence::attest_control(&id, &expected, b"").is_none());
    let mut doubled = expected.as_bytes().to_vec();
    doubled.extend_from_slice(expected.as_bytes());
    assert!(evidence::attest_control(&id, &expected, doubled.as_slice()).is_none());

    let verified = evidence::attest_control(&id, &expected, expected.as_bytes()).expect("mint");
    let mut e = Evidence::default();
    assert!(!e.has_verified_control(&id));
    e.host_control_fact(&verified);
    assert!(e.has_verified_control(&id));
    let other = ExecutionIdentity::new("S", "other-nonce", "r", "f");
    assert!(!e.has_verified_control(&other));
}
