//! verify-ng execution layer (TEST-ENGINE-001..006 + Stage 1B, unix-only).
//!
//! Drives the real [`runner::run_one`] pipeline (Engine -> Killer ->
//! Collector -> Oracle) with POSIX shell payloads. Every test asserts the
//! one-spawn invariant through its own caller-owned [`SpawnLog`] (exact
//! under parallel threads) — never through child stdout.
//!
//! Stage 1B honesty rules baked into these tests: the direct backend has no
//! host-owned control source, so PASS is unreachable here by construction —
//! tests assert INCONCLUSIVE/FAIL outcomes, never a self-awarded PASS. HOME
//! tests prove per-run distinctness, never filesystem isolation (direct
//! execution provides no containment).
//!
//! Windows parity is out of scope for this stage: no HANDLE capture exists
//! in the backend yet (see docs/verify-ng.md), so these tests stay unix.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::verify_ng::evidence::{Evidence, EvidenceTier};
use vetto::verify_ng::killer::KillOutcome;
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
        known_limitation: "execution-plumbing self-test only; proves no enforcement claim"
            .to_string(),
        residual_risk: String::new(),
    }
}

fn request<'a>(
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
        // Stage 1B behavior by default: no host-owned control channel, so
        // PASS is unreachable here (INCONCLUSIVE/FAIL). Stage 2 tests opt
        // in explicitly via `request_with_control`.
        enable_host_control: false,
    }
}

fn assert_single_spawn(log: &runner::SpawnLog, out: &runner::ExecutionOutcome) {
    assert_eq!(log.len(), 1, "one scenario must spawn exactly once");
    assert_eq!(log[0].run_id, out.nonce, "spawn event binds to the run");
    assert_eq!(out.spawn_pid, Some(log[0].pid));
}

fn stdio_fact_values(out: &runner::ExecutionOutcome) -> Vec<&str> {
    out.evidence
        .facts
        .iter()
        .filter(|f| f.tier == EvidenceTier::HostFact)
        .map(|f| f.value.as_str())
        .collect()
}

/// TEST-ENGINE-001: successful child — spawn, exit status, stdio, no block.
/// Verdict is INCONCLUSIVE, not PASS: the direct backend has no host-owned
/// control source, so PASS is unreachable by construction (Blocker 1).
#[test]
fn test_engine_001_successful_child() {
    let scenario = aux_scenario("TEST-ENGINE-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "echo hello-stdout\necho hello-stderr >&2\nexit 0\n";
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(!out.timed_out);
    assert!(out.stdio_eof, "reaped child must EOF promptly");
    assert!(out.stdio_complete, "small clean output collects completely");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello-stdout"),
        "stdout collected"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hello-stderr"),
        "stderr collected"
    );
    assert!(!out.control_observed, "no control source on direct backend");
    assert!(out.payload_intact);
    for f in &out.evidence.facts {
        if f.name == "stdout" || f.name == "stderr" {
            assert_eq!(f.tier, EvidenceTier::SelfReport, "stdio is never HOST_FACT");
        }
        assert_ne!(
            f.name, "control",
            "no control HOST_FACT may exist on direct backend"
        );
    }
    assert!(
        !stdio_fact_values(&out)
            .iter()
            .any(|v| v.contains("hello-stdout")),
        "child text must not leak into HOST_FACT values"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "success without host control must not PASS"
    );
}

/// TEST-ENGINE-002: child exceeds deadline — killer path, prompt return.
#[test]
fn test_engine_002_deadline_kills() {
    let scenario = aux_scenario("TEST-ENGINE-002");
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = request(
        &scenario,
        &policy,
        &net,
        "sleep 30\n",
        Duration::from_secs(2),
    );
    let mut log = runner::SpawnLog::new();
    let started = Instant::now();
    let out = runner::run_one(&req, &mut log);
    let elapsed = started.elapsed();

    assert_single_spawn(&log, &out);
    assert!(out.timed_out, "deadline must be observed");
    assert_eq!(out.kill, Some(KillOutcome::KilledOnDeadline));
    assert!(out.exit_code.is_some(), "killer re-wait yields a status");
    assert_ne!(out.exit_code, Some(0));
    assert_ne!(
        out.result.verdict,
        model::Verdict::Pass,
        "timeout must never PASS"
    );
    assert_eq!(out.result.verdict, model::Verdict::Inconclusive);
    // Collection completeness is deliberately NOT asserted here: the killed
    // `sh` can leave an orphaned `sleep` grandchild holding the pipe past
    // the drain budget (documented direct-exec residual) — the verdict
    // still degrades to INCONCLUSIVE, never PASS, either way.
    assert!(
        elapsed < Duration::from_secs(25),
        "collector must not hang: took {elapsed:?}"
    );
}

/// TEST-ENGINE-003: attacker-controlled stdout cannot become HOST_FACT.
#[test]
fn test_engine_003_attacker_stdout_is_not_host_fact() {
    let scenario = aux_scenario("TEST-ENGINE-003");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "echo PASS\necho HOST_FACT\necho VERIFIED\nexit 0\n";
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("PASS"), "marker bytes are collected");
    let stdout_fact = out
        .evidence
        .facts
        .iter()
        .find(|f| f.name == "stdout")
        .expect("stdout evidence present");
    assert_eq!(stdout_fact.tier, EvidenceTier::SelfReport);
    for value in stdio_fact_values(&out) {
        assert!(
            !value.contains("PASS") && !value.contains("VERIFIED") && !value.contains("HOST_FACT"),
            "no HOST_FACT may carry child markers: {value:?}"
        );
    }
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "markers without host proof must not PASS"
    );
}

/// TEST-ENGINE-004: one scenario launches exactly once (ledger proof).
#[test]
fn test_engine_004_single_spawn_per_scenario() {
    let scenario = aux_scenario("TEST-ENGINE-004");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "exit 0\n";
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-ENGINE-005: fixture mutation surfaces so the oracle FAILs.
#[test]
fn test_engine_005_fixture_mutation_fails() {
    let scenario = aux_scenario("TEST-ENGINE-005");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "echo pwned > \"$VETTO_VNG_ROOT/canary.txt\"\n";
    let mut req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    req.sentinels = vec![("canary.txt".to_string(), b"do-not-touch".to_vec())];
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert!(out.violation_observed);
    assert_eq!(out.sentinel_mutated, vec!["canary.txt".to_string()]);
    assert!(out.payload_intact, "the staged script itself is untouched");
    assert_eq!(
        out.result.verdict,
        model::Verdict::Fail,
        "host-observed fixture tampering must FAIL"
    );
}

/// TEST-ENGINE-006: HOME distinctness (NOT isolation) — per-run fresh HOME,
/// never shared, never reused. Direct execution provides no containment;
/// this test proves plumbing distinctness only.
#[test]
fn test_engine_006_home_distinctness() {
    let script = "printf 'home-isolated' > \"$VETTO_VNG_HOME/marker.txt\"\n";
    let run = || {
        let scenario = aux_scenario("TEST-ENGINE-006");
        let policy = Policy::default();
        let net = NetMode::Off;
        // Ownership: keep scenario/policy/net alive for the request borrow
        // by leaking through the closure return (moved into the tuple).
        let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
        let mut log = runner::SpawnLog::new();
        let out = runner::run_one(&req, &mut log);
        assert_single_spawn(&log, &out);
        (scenario, policy, net, out)
    };
    let (_, _, _, first) = run();
    let (_, _, _, second) = run();

    for out in [&first, &second] {
        assert_eq!(
            out.home_marker.as_deref(),
            Some(b"home-isolated".as_slice()),
            "child saw its own per-run HOME"
        );
        assert!(
            out.home.to_string_lossy().contains("vetto-vng-exec"),
            "HOME lives under the run fixture: {}",
            out.home.display()
        );
    }
    assert_ne!(first.home, second.home, "HOME is never reused across runs");
    if let Ok(real_home) = std::env::var("HOME") {
        assert_ne!(
            first.home,
            std::path::PathBuf::from(&real_home),
            "scenario HOME must not be the shared writable HOME"
        );
        // A same-named file under the real HOME must not carry our bytes;
        // absence is the common case, inequality the collision-safe check.
        let leaked = std::path::PathBuf::from(&real_home).join("marker.txt");
        if let Ok(bytes) = std::fs::read(&leaked) {
            assert_ne!(
                bytes, b"home-isolated",
                "marker must not leak into the shared HOME"
            );
        }
    }
}

/// TEST-CONTROL-SPLIT-001: forging the legacy control condition cannot PASS.
///
/// The malicious payload reads the run-label nonce, writes it into the
/// legacy control path (whether or not the harness still advertises one),
/// and prints PASS-like markers. The runner honors none of it: no control
/// pathname is authoritative, so the verdict must stay INCONCLUSIVE (no
/// independent violation here) and no HOST_FACT "control" may exist.
#[test]
fn test_control_split_001_forged_control_cannot_pass() {
    let scenario = aux_scenario("TEST-CONTROL-SPLIT-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = concat!(
        "echo PASS\n",
        "echo HOST_FACT >&2\n",
        "echo VERIFIED\n",
        "ctl=\"${VETTO_VNG_CONTROL:-$VETTO_VNG_ROOT/control.txt}\"\n",
        "printf %s \"$VETTO_VNG_NONCE\" > \"$ctl\"\n",
        "exit 0\n",
    );
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(out.stdio_complete, "forge attempt itself collects cleanly");
    assert!(
        !out.control_observed,
        "no host-owned control source may be observed"
    );
    assert!(
        !out.evidence.facts.iter().any(|f| f.name == "control"),
        "forged control file must not appear in evidence at all"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "nonce reproduced in an attacker-controlled location must not PASS"
    );
}

/// TEST-COLLECTOR-COMPLETENESS-001: incomplete collection cannot PASS.
///
/// Runner part: a payload emitting far more than the capture cap (~13MB).
/// There is no concurrent drain — the collector only reads after the
/// killer stage — so the child blocks on the full pipe buffer and the
/// deadline killer fires: the exit is non-zero either way and collection
/// is incomplete either way (cap truncation if fully drained, short drain
/// otherwise). The verdict is INCONCLUSIVE, never PASS.
/// Oracle part: a fully PASS-shaped input with `stdio_complete=false`
/// judges INCONCLUSIVE at the decision boundary itself.
#[test]
fn test_collector_completeness_001_incomplete_cannot_pass() {
    // Runner path: ~13MB of stdout with no concurrent drain.
    let scenario = aux_scenario("TEST-COLLECTOR-COMPLETENESS-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "awk 'BEGIN{for(i=0;i<200000;i++) print \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}'\n";
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(20));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_ne!(
        out.exit_code,
        Some(0),
        "blocked oversized output never exits clean"
    );
    assert!(
        !out.stdio_complete,
        "oversized collection is incomplete either way"
    );
    assert_eq!(
        out.result.verdict,
        model::Verdict::Inconclusive,
        "incomplete collection must not PASS"
    );

    // Oracle boundary: everything for PASS except completeness — with a
    // genuine identity-bound verified control, so the refusal is the
    // completeness gate itself and not the identity gate.
    let identity = vetto::verify_ng::evidence::ExecutionIdentity::new(
        "TEST-COLLECTOR-COMPLETENESS-001",
        "nonce-1",
        "reg-test",
        "frozen-test",
    );
    let token = vetto::verify_ng::evidence::derive_control_token("test-secret", &identity);
    let verified = vetto::verify_ng::evidence::attest_control(&identity, &token, token.as_bytes())
        .expect("test attestation must mint");
    let mut evidence = Evidence::default();
    evidence.host_fact("wait-status", "exit=0".to_string());
    evidence.host_control_fact(&verified);
    let input = OracleInput {
        scenario: &scenario,
        evidence: &evidence,
        nonce: Some("nonce-1"),
        probe_nonce: Some("nonce-1"),
        control_nonce: Some("nonce-1"),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: false,
        execution_identity: Some(&identity),
    };
    assert_eq!(
        oracle::judge(&input),
        model::Verdict::Inconclusive,
        "oracle must refuse PASS on incomplete collection itself"
    );
}

/// TEST-SPAWN-LEDGER-001: suite-level one-spawn ownership.
///
/// The first execution of a scenario runs (here: FAIL via sentinel trip).
/// A second execution attempt of the same id is rejected BEFORE any
/// fixture/spawn work: no second spawn (ledger stays length 1), verdict
/// INCONCLUSIVE marked duplicate, earlier FAIL untouched — a retry can
/// never upgrade FAIL/INCONCLUSIVE into PASS. A different scenario still
/// runs (ledger grows to 2).
#[test]
fn test_spawn_ledger_001_duplicate_execution_rejected() {
    let policy = Policy::default();
    let net = NetMode::Off;
    let violator = aux_scenario("TEST-SPAWN-LEDGER-001");
    let mut req = request(
        &violator,
        &policy,
        &net,
        "echo pwned > \"$VETTO_VNG_ROOT/canary.txt\"\n",
        Duration::from_secs(15),
    );
    req.sentinels = vec![("canary.txt".to_string(), b"do-not-touch".to_vec())];

    let mut suite = runner::SuiteRunner::new();
    let first = suite.run(&req);
    assert_eq!(first.result.verdict, model::Verdict::Fail);
    assert!(!first.duplicate_rejected);
    assert_eq!(suite.ledger().len(), 1);

    let second = suite.run(&req);
    assert!(second.duplicate_rejected, "duplicate must be flagged");
    assert_eq!(second.spawn_pid, None, "rejected run spawns nothing");
    assert_eq!(
        second.result.verdict,
        model::Verdict::Inconclusive,
        "rejection degrades, never upgrades"
    );
    assert_eq!(suite.ledger().len(), 1, "ledger proves no second spawn");
    assert_eq!(
        suite.results().len(),
        2,
        "rejection is recorded fail-closed"
    );
    assert_eq!(suite.results()[0].verdict, model::Verdict::Fail);

    let other = aux_scenario("TEST-SPAWN-LEDGER-001-OTHER");
    let other_req = request(&other, &policy, &net, "exit 0\n", Duration::from_secs(15));
    let third = suite.run(&other_req);
    assert!(!third.duplicate_rejected);
    assert_eq!(suite.ledger().len(), 2);
    assert_ne!(suite.ledger()[0].run_id, suite.ledger()[1].run_id);
}
