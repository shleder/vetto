//! Phase 2 Process Containment Battery (Master Task Section 6).
//!
//! Covers:
//! 1. parent -> child -> grandchild deep nested hierarchy
//! 2. fork & spawn
//! 3. daemonize (double-fork, setsid, stdio detach)
//! 4. setsid process group / session leader detachment
//! 5. detach & survive parent exit (orphan adoption by subreaper)
//! 6. escape process group / session
//! 7. continue after supervised execution terminates (deadline kill + sweep)
//! 8. PROC-ESC-001 — canonical blocker canary
//! 9. PROC-TREE-001 — multi-vector quorum blocker
//! 10. Linux FS-ONLY: documented detached-grandchild gap — do NOT declare PASS;
//!     emit FAIL/INCONCLUSIVE with exact reason per existing verdict contract.
//! 11. Contract tampering before spawn: fail-closed with no execution.
//! 12. Inherited file descriptor handles holding pipes: bounded drain.
//! 13. Mathematical Process Tree Extinction Theorem (§12.1) convergence.
//!
//! Every test consumes the SAME sealed [`SecurityContract`] used by production
//! execution, verifies contract digest integrity (fail-closed on tampering),
//! and relies exclusively on independent runtime evidence (HOST_FACT via /proc
//! scan, kernel wait-status, subreaper sweep), never trusting child self-reports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::audit::verdict::{EvidenceStrength, VerdictEngine, VerdictStatus};
use vetto::config::NetMode;
use vetto::policy::{Policy, Tier};
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::SecurityContract;
use vetto::proctree::{
    ExtinctionVerifier, PlatformExtinctionTier, FAIL_CLOSED_EXTINCTION_EXIT_CODE,
    MAX_EXTINCTION_DEADLINE_MS,
};
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{registry, Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{EnforcementState, LinuxBackend, SecurityCapability};
use vetto::verify_ng::{engine, runner};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_id(prefix: &str) -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("vetto-proc-{prefix}-{}-{n}", std::process::id())
}

/// Create a test scenario.
fn test_scenario(id: &str, category: Category, quorum: usize) -> Scenario {
    let target = engine::current_target(Some("full"));
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string(), "tree-sweep".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Partial),
            ("macos".to_string(), ClaimStrength::Partial),
            ("windows".to_string(), ClaimStrength::Strong),
        ]),
        quorum,
        known_limitation: "Phase 2 process containment battery test".to_string(),
        residual_risk:
            "fs-only setsid orphans are a known residual; verdict is FAIL/INCONCLUSIVE, never PASS."
                .to_string(),
    }
}

/// Helper: creates a dedicated temp directory.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(next_test_id(name));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Helper: compile and seal an authoritative SecurityContract for the given
/// workspace, policy, and execution tier. Uses the EXACT production compiler path.
fn seal_contract_with_tier(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    tier: Option<Tier>,
    nonce: &str,
) -> SecurityContract {
    let argv_strings: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let env_vars = BTreeMap::new();
    let input = EffectivePolicyInput {
        policy,
        argv: &argv_strings,
        cwd: workspace,
        env: &env_vars,
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(30)),
        tier,
        backend: "linux-landlock".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    PolicyCompiler::compile_effective(input).expect("compile and seal contract")
}

/// Helper: compile and seal an authoritative SecurityContract with default tier (Full).
fn seal_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    nonce: &str,
) -> SecurityContract {
    seal_contract_with_tier(workspace, policy, argv, Some(Tier::Full), nonce)
}

/// Positive control challenge-response snippet (rotates token from downlink to uplink).
const POSITIVE_CONTROL_SNIPPET: &str = concat!(
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "S=\"$C$VETTO_VNG_NONCE\"\n",
    "head=${S%????????}\n",
    "tail=${S#$head}\n",
    "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
);

/// Run a scenario under LinuxBackend using a sealed SecurityContract.
fn run_linux_contract(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    enable_host_control: bool,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    run_linux_contract_deadline(
        scen,
        contract,
        script,
        sentinels,
        enable_host_control,
        Duration::from_secs(15),
    )
}

/// Run a scenario with explicit deadline.
fn run_linux_contract_deadline(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    enable_host_control: bool,
    deadline: Duration,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    let production = contract
        .production
        .as_ref()
        .expect("production contract in sealed contract");
    let policy = &production.installation_policy;
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy,
        net_mode: &production.net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels,
        env_extra: BTreeMap::new(),
        deadline,
        enable_host_control,
        contract: Some(contract),
        host_env_override: None,
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    (out, log)
}

// ---------------------------------------------------------------------------
// 1. Canonical Canary: PROC-ESC-001
// ---------------------------------------------------------------------------

/// PROC-ESC-001 under Tier::Full: setsid-detached process reaped by host
/// subreaper sweep, positive control verified, yields PASS with sealed contract.
#[test]
fn test_proc_esc_001_canonical_canary_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "PROC-ESC-001")
        .expect("PROC-ESC-001 must exist in registry");

    let ws = temp_dir("ws-proc-canary");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-canary-01");

    // Attack payload: detached setsid sleeper + valid positive control response
    let script = format!(
        "setsid sleep 30 >/dev/null 2>&1 &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    let start = std::time::Instant::now();
    let (out, log) = run_linux_contract(scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "run must complete promptly; escaper must not hang runner"
    );

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "tree must be verified clean: {}",
        report.render_deterministic()
    );
    assert!(out.control_observed, "host control must be verified");
    assert!(out.evidence.has_host_fact());
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "PROC-ESC-001 must PASS under Tier::Full with sealed contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

/// Linux FS-ONLY gap: documented detached-grandchild gap — do NOT declare PASS;
/// emit FAIL/INCONCLUSIVE with exact reason per existing verdict contract.
#[test]
fn test_proc_esc_001_linux_fsonly_detached_grandchild_gap_never_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "PROC-ESC-001")
        .expect("PROC-ESC-001 must exist in registry");

    let ws = temp_dir("ws-proc-fsonly");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    // Seal contract specifically with Tier::FsOnly
    let contract = seal_contract_with_tier(
        &ws,
        &policy,
        &["sh"],
        Some(Tier::FsOnly),
        "nonce-proc-fsonly-01",
    );

    let script = format!(
        "setsid sleep 30 >/dev/null 2>&1 &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    let (out, log) = run_linux_contract(scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);

    // CRITICAL: Master Task Section 6 invariant:
    // Linux FS-ONLY: documented detached-grandchild gap — НЕ объявлять PASS!
    assert_ne!(
        out.result.verdict,
        Verdict::Pass,
        "Linux FS-ONLY must NEVER declare PASS on detached-grandchild canary: {}",
        out.result.detail
    );
    assert_eq!(
        out.result.verdict,
        Verdict::Inconclusive,
        "Clean sweep under FS-ONLY degrades to INCONCLUSIVE per verdict contract"
    );

    // Capability record must honestly reflect that tree containment is Unsupported on FsOnly
    let report = out.backend_report.as_ref().expect("backend report present");
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Unsupported,
        "ProcessTreeContainment must be Unsupported on FsOnly"
    );
    assert!(
        !report.allows_pass(&[SecurityCapability::ProcessTreeContainment]),
        "allows_pass must be false for ProcessTreeContainment on FsOnly"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 2. Multi-generation Hierarchy: parent -> child -> grandchild
// ---------------------------------------------------------------------------

/// Deep nested process chain: parent spawns child, child forks grandchild,
/// intermediate shells exit, grandchild outlives them and is swept by nonce.
#[test]
fn test_process_containment_parent_child_grandchild() {
    let scen = test_scenario("TEST-PROC-CHAIN-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-chain");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-chain-01");

    let script = format!(
        "sh -c 'sh -c \"sleep 30\" &' &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    let start = std::time::Instant::now();
    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "multi-generation chain must not stall execution"
    );

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 3. Daemonization & Double-Fork Detach
// ---------------------------------------------------------------------------

/// Classical UNIX daemonization sequence: fork, setsid, second fork,
/// redirect descriptors, parent exit. Host subreaper sweep cleans daemon.
#[test]
fn test_process_containment_daemonize_double_fork() {
    let scen = test_scenario("TEST-PROC-DAEMON-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-daemon");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-daemon-01");

    // Double-fork daemonize in shell:
    let script = format!(
        concat!("( ( sleep 30 >/dev/null 2>&1 & ) & )\n", "{}\n", "exit 0\n"),
        POSITIVE_CONTROL_SNIPPET
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 4. Survive Parent Exit (Orphan Adoption)
// ---------------------------------------------------------------------------

/// Parent exits immediately with code 0 while background child runs.
/// Subreaper intercepts orphan adoption and sweeps it before session end.
#[test]
fn test_process_containment_survive_parent_exit() {
    let scen = test_scenario("TEST-PROC-ORPHAN-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-orphan");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-orphan-01");

    let script = format!("(sleep 30 &)\n{}\nexit 0\n", POSITIVE_CONTROL_SNIPPET);

    let start = std::time::Instant::now();
    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "orphan must not stall termination"
    );

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
    assert_eq!(out.exit_code, Some(0));
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 5. Escape Process Group / Session
// ---------------------------------------------------------------------------

/// Child detaches into a separate process group via setsid.
/// Group kill kill(-pgid) cannot reach it, but nonce sweep intercepts it.
#[test]
fn test_process_containment_group_escape_setsid() {
    let scen = test_scenario("TEST-PROC-PGROUP-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-pgroup");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-pgroup-01");

    let script = format!(
        "setsid sleep 30 >/dev/null 2>&1 &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), true);
    assert_eq!(log.len(), 1);

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "setsid group escaper must be reaped: {}",
        out.result.detail
    );
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 6. Continue After Supervised Execution Terminates
// ---------------------------------------------------------------------------

/// Adversarial workload attempts to continue after deadline:
/// root process sleeps past deadline while background child also sleeps.
/// Deadline kill + tree sweep extinguishes both.
#[test]
fn test_process_containment_continue_after_termination() {
    let scen = test_scenario("TEST-PROC-TIMEOUT-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-timeout");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-timeout-01");

    // Spawns detached child, then blocks in foreground sleep
    let script = "setsid sleep 30 >/dev/null 2>&1 &\nexec sleep 60\n";

    let (out, log) = run_linux_contract_deadline(
        &scen,
        &contract,
        script,
        Vec::new(),
        false,
        Duration::from_secs(3),
    );
    assert_eq!(log.len(), 1);
    assert!(out.timed_out, "deadline must fire on timeout");
    assert_ne!(out.exit_code, Some(0));

    // Timed out workload must NEVER pass
    assert_ne!(out.result.verdict, Verdict::Pass);

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) != EnforcementState::Unsupported {
        assert_eq!(
            report.state(SecurityCapability::ProcessTreeContainment),
            EnforcementState::Verified,
            "deadline tree kill must extinguish both leader and escaper: {}",
            out.result.detail
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 7. Surviving Process Lifecycle Breach Triggers FAIL
// ---------------------------------------------------------------------------

/// Invariant: any surviving descendant process is an authoritative FAIL (§18.1).
#[test]
fn test_process_containment_lifecycle_breach_fails() {
    let ws = temp_dir("ws-proc-breach");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-breach-01");

    // 1. VerdictEngine: surviving descendant process triggers FAIL [STRONG] with exit code 125
    let v_survivor = VerdictEngine::evaluate(&contract, 0, 0, 1, true, 0);
    assert_eq!(v_survivor.status, VerdictStatus::Fail);
    assert_eq!(v_survivor.strength, EvidenceStrength::Strong);
    assert_eq!(v_survivor.exit_code, 125);
    assert!(!v_survivor.is_success());
    assert!(v_survivor.reason.contains("Lifecycle breach"));

    // 2. ExtinctionVerifier: surviving processes trigger fail-closed breach (§12.1)
    let proof_err = ExtinctionVerifier::verify(
        PlatformExtinctionTier::LinuxTier1Proven,
        2, // 2 surviving processes
        0,
        150,
    )
    .unwrap_err();
    assert_eq!(proof_err.exit_code, FAIL_CLOSED_EXTINCTION_EXIT_CODE);
    assert_eq!(proof_err.exit_code, 125);
    assert!(proof_err.reason.contains("Lifecycle breach"));

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 8. Quorum Multi-Vector Scenario: PROC-TREE-001
// ---------------------------------------------------------------------------

/// PROC-TREE-001 (quorum 2 blocker): multi-vector scenario requires
/// >= 2 agreeing host facts (e.g. tree-intact + sentinel-intact) to PASS.
#[test]
fn test_proc_tree_001_multivector_quorum() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "PROC-TREE-001")
        .expect("PROC-TREE-001 must exist in registry");

    let ws = temp_dir("ws-proc-tree-pass");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-tree-01");

    let script = format!(
        "setsid sleep 30 >/dev/null 2>&1 &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    // Provide 1 sentinel so tree-intact + sentinel-intact = 2 agreeing vectors (quorum = 2)
    let sentinels = vec![(
        "sentinel_marker.txt".to_string(),
        b"marker-canary\n".to_vec(),
    )];

    let (out, log) = run_linux_contract(scen, &contract, &script, sentinels, true);
    assert_eq!(log.len(), 1);

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_ne!(out.result.verdict, Verdict::Pass);
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "PROC-TREE-001 must PASS when quorum 2 is met under Tier::Full"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

/// PROC-TREE-001 under Tier::FsOnly: even when quorum is met, the documented
/// detached-grandchild gap strictly blocks PASS -> INCONCLUSIVE.
#[test]
fn test_proc_tree_001_fsonly_gap_never_pass() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "PROC-TREE-001")
        .expect("PROC-TREE-001 must exist in registry");

    let ws = temp_dir("ws-proc-tree-fsonly");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract_with_tier(
        &ws,
        &policy,
        &["sh"],
        Some(Tier::FsOnly),
        "nonce-proc-tree-fsonly-01",
    );

    let script = format!(
        "setsid sleep 30 >/dev/null 2>&1 &\n{}\nexit 0\n",
        POSITIVE_CONTROL_SNIPPET
    );

    let sentinels = vec![(
        "sentinel_marker.txt".to_string(),
        b"marker-canary\n".to_vec(),
    )];
    let (out, log) = run_linux_contract(scen, &contract, &script, sentinels, true);
    assert_eq!(log.len(), 1);

    assert_ne!(
        out.result.verdict,
        Verdict::Pass,
        "PROC-TREE-001 must NEVER PASS under Linux FS-ONLY"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 9. Contract Tampering Rejection: No Spawn
// ---------------------------------------------------------------------------

/// Modifying process limits or security fields in contract after sealing
/// causes digest verification to fail: immediate fail-closed, no child spawned.
#[test]
fn test_process_containment_contract_tamper_rejected() {
    let scen = test_scenario("TEST-PROC-TAMPER-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-tamper");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let mut contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-tamper-01");
    assert!(contract.verify_digest());

    // Tamper with contract resources after sealing
    contract.resources.max_pids = 9999;
    assert!(!contract.verify_digest(), "digest verification must fail");

    let script = "exit 0\n";
    let (out, log) = run_linux_contract(&scen, &contract, script, Vec::new(), false);

    assert_eq!(log.len(), 0, "no child process must be spawned");
    assert_eq!(out.spawn_pid, None, "spawn_pid must be None on tamper");
    assert_ne!(out.result.verdict, Verdict::Pass);
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert!(
        out.result
            .detail
            .contains("invalid security contract digest"),
        "detail must indicate contract digest failure: {}",
        out.result.detail
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 10. Inherited Handles: Pipe Held Open Does Not Hang
// ---------------------------------------------------------------------------

/// Grandchild inherits and holds stdout/stderr pipe open in background.
/// Drain deadline bounds stdio collection; harness does not hang.
#[test]
fn test_process_containment_inherited_handles_timeout_bound() {
    let scen = test_scenario("TEST-PROC-HANDLES-001", Category::Proc, 1);
    let ws = temp_dir("ws-proc-handles");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-proc-handles-01");

    // Sleep in background inherits open stdout pipe
    let script = format!("sleep 30 &\n{}\nexit 0\n", POSITIVE_CONTROL_SNIPPET);

    let start = std::time::Instant::now();
    let (out, log) = run_linux_contract_deadline(
        &scen,
        &contract,
        &script,
        Vec::new(),
        true,
        Duration::from_secs(10),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "inherited handle must not hang execution past drain deadline"
    );

    let report = out.backend_report.as_ref().expect("backend report present");
    if report.state(SecurityCapability::ProcessTreeContainment) != EnforcementState::Unsupported {
        assert_eq!(
            report.state(SecurityCapability::ProcessTreeContainment),
            EnforcementState::Verified
        );
    }

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 11. Extinction Convergence Bound (§12.1)
// ---------------------------------------------------------------------------

/// Mathematical Process Tree Extinction Theorem (§12.1):
/// Sweep must converge to empty within Delta t_max <= 500ms.
/// Exceeding 500ms emits Exit 125 fail-closed ExtinctionBreach.
#[test]
fn test_process_containment_extinction_deadline_boundary() {
    // 1. Successful extinction within deadline (250ms <= 500ms)
    let proof = ExtinctionVerifier::verify(PlatformExtinctionTier::LinuxTier1Proven, 0, 0, 250)
        .expect("extinction within deadline must succeed");
    assert_eq!(proof.surviving_processes, 0);
    assert_eq!(proof.surviving_resources, 0);
    assert!(proof.mathematically_proven);

    // 2. Extinction deadline exceeded (501ms > 500ms) triggers breach
    let breach = ExtinctionVerifier::verify(
        PlatformExtinctionTier::LinuxTier1Proven,
        0,
        0,
        MAX_EXTINCTION_DEADLINE_MS + 1,
    )
    .unwrap_err();
    assert_eq!(breach.exit_code, FAIL_CLOSED_EXTINCTION_EXIT_CODE);
    assert_eq!(breach.exit_code, 125);
    assert!(breach.reason.contains("Extinction deadline exceeded"));
}
