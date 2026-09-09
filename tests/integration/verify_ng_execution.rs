//! verify-ng execution layer (TEST-ENGINE-001..006, unix-only).
//!
//! Drives the real [`runner::run_one`] pipeline (Engine -> Killer ->
//! Collector -> Oracle) with POSIX shell payloads. Every test asserts the
//! one-spawn invariant through its own caller-owned [`SpawnLog`] (exact
//! under parallel threads) — never through child stdout.
//!
//! Windows parity is out of scope for this stage: no HANDLE capture exists
//! in the backend yet (see docs/verify-ng.md), so these tests stay unix.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::verify_ng::evidence::EvidenceTier;
use vetto::verify_ng::killer::KillOutcome;
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
#[test]
fn test_engine_001_successful_child() {
    let scenario = aux_scenario("TEST-ENGINE-001");
    let policy = Policy::default();
    let net = NetMode::Off;
    let script = "echo hello-stdout\necho hello-stderr >&2\nprintf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_CONTROL\"\n";
    let req = request(&scenario, &policy, &net, script, Duration::from_secs(15));
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);

    assert_single_spawn(&log, &out);
    assert_eq!(out.exit_code, Some(0));
    assert!(!out.timed_out);
    assert!(out.stdio_eof, "reaped child must EOF promptly");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("hello-stdout"),
        "stdout collected"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("hello-stderr"),
        "stderr collected"
    );
    assert!(out.control_observed);
    assert!(out.payload_intact);
    for f in &out.evidence.facts {
        if f.name == "stdout" || f.name == "stderr" {
            assert_eq!(f.tier, EvidenceTier::SelfReport, "stdio is never HOST_FACT");
        }
    }
    assert!(
        !stdio_fact_values(&out)
            .iter()
            .any(|v| v.contains("hello-stdout")),
        "child text must not leak into HOST_FACT values"
    );
    assert_eq!(out.result.verdict, model::Verdict::Pass);
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
    let script = "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_CONTROL\"\nexit 0\n";
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
    let script = "printf %s \"$VETTO_VNG_NONCE\" > \"$VETTO_VNG_CONTROL\"\necho pwned > \"$VETTO_VNG_ROOT/canary.txt\"\n";
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

/// TEST-ENGINE-006: HOME isolation — scenario-specific, never shared.
#[test]
fn test_engine_006_home_isolation() {
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
            "child wrote into its own isolated HOME"
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
