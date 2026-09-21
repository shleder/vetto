//! Phase 2 authoritative verification tests: Contract Tampering (Section 10)
//! and Cross-Execution Identity Binding regressions (Section 3).
//!
//! Master Task Section 10:
//! After sealing: contract -> digest -> execution; mutate security-relevant fields:
//! filesystem, environment, network, limits, executable restrictions, secret masks,
//! tier/backend requirements.
//! Invariant: tamper -> digest/identity mismatch -> verification failure -> NO SPAWN.
//! Child MUST NOT run: verified via exit code/verdict, child marker file absence,
//! and global spawn ledger (PROD_SPAWN_COUNT) immutability.
//!
//! Master Task Section 3:
//! ExecutionIdentity {scenario_id, session_nonce, registry_hash, frozen_hash} bound to evidence.
//! Verifier never accepts evidence from another execution, stale run, other contract,
//! other nonce, other backend.
//! Regression: Contract A + Execution A + Evidence A vs Contract B + Execution B + Evidence B;
//! Evidence A never satisfies verification for B.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::config::NetMode;
use vetto::multi::DebugPortConfig;
use vetto::policy::{DenyEntry, Policy, Tier};
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::{NetworkMode, SecurityContract};
use vetto::sandbox::production::{
    UnpreparedProductionExecution, PROD_SCENARIO_ID, PROD_SPAWN_COUNT,
};
use vetto::sandbox::{Backend, StdioMode};
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::oracle::{self, OracleInput};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::sandbox_backend::LinuxBackend;
use vetto::verify_ng::{engine, runner};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_id(prefix: &str) -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("vetto-tamper-{prefix}-{}-{n}", std::process::id())
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(next_test_id(name));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn test_scenario(id: &str, category: Category, quorum: usize) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string(), "landlock".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Strong),
        ]),
        quorum,
        known_limitation: "Phase 2 contract tampering and identity binding regression".to_string(),
        residual_risk: String::new(),
    }
}

fn aux_scenario(id: &str) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category: Category::Aux,
        severity: Severity::High,
        required_caps: vec!["spawn".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Strong),
            ("linux-seccomp".to_string(), ClaimStrength::Strong),
            ("macos".to_string(), ClaimStrength::Strong),
            ("windows".to_string(), ClaimStrength::Strong),
        ]),
        quorum: 1,
        known_limitation: "host-control cross-session identity regression".to_string(),
        residual_risk: String::new(),
    }
}

fn functional_policy(tmp: &Path) -> Policy {
    let mut policy = Policy::default();
    for cand in ["/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc"] {
        let p = PathBuf::from(cand);
        if p.exists() && !policy.allow_read.contains(&p) {
            policy.allow_read.push(p);
        }
    }
    for cand in [tmp.to_path_buf(), PathBuf::from("/tmp")] {
        if cand.exists() && !policy.allow_write.contains(&cand) {
            policy.allow_write.push(cand);
        }
    }
    policy.environment.pass_through.push("PATH".to_string());
    policy
}

fn seal_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
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
        tier: None,
        backend: "linux-landlock".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    PolicyCompiler::compile_effective(input).expect("compile and seal contract")
}

fn run_linux_contract(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    enable_host_control: bool,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    let default_policy = Policy::default();
    let (policy, net_mode) = match &contract.production {
        Some(p) => (&p.installation_policy, &p.net),
        None => (&default_policy, &NetMode::Off),
    };
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy,
        net_mode,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels,
        env_extra: BTreeMap::new(),
        deadline: Duration::from_secs(15),
        enable_host_control,
        contract: Some(contract),
        host_env_override: None,
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    (out, log)
}

const POSITIVE_SCRIPT: &str = concat!(
    "echo marker-stdout\n",
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "S=\"$C$VETTO_VNG_NONCE\"\n",
    "head=${S%????????}\n",
    "tail=${S#$head}\n",
    "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
    "exit 0\n",
);

// ===========================================================================
// 1. CONTRACT TAMPERING BATTERY — ALL FIELD CLASSES (Master Task Section 10)
// ===========================================================================

#[test]
fn test_tamper_matrix_all_field_classes_rejected_no_spawn() {
    let _lock = crate::common::prod_spawn_test_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let ws = temp_dir("tamper-matrix-ws");
    let scen = test_scenario("TAMPER-MATRIX-001", Category::FsRead, 1);
    let policy = functional_policy(&ws);

    let cases = [
        // Filesystem
        "fs_allow_read",
        "fs_allow_write",
        "fs_deny_read",
        "fs_deny_write",
        "fs_cow_overlay",
        "fs_execution_root_ro",
        // Environment
        "env_explicit_vars",
        "env_redacted_patterns",
        "env_inject_session_nonce",
        // Network
        "net_mode",
        "net_allowed_domains",
        "net_allowed_ports",
        "net_allowed_ips",
        "net_debug_ports",
        // Limits
        "limits_max_memory_mb",
        "limits_max_pids",
        "limits_max_cpu_seconds",
        "limits_max_file_size_mb",
        // Executable restrictions
        "exec_allowed_executables",
        "exec_forbidden_executables",
        "exec_invoked_binary",
        "exec_invoked_args",
        // Secret masks
        "secrets_mask_paths",
        // Tier / Backend requirements
        "tier_requirement",
        "backend_requirement",
        // Missing installation contract
        "missing_production",
    ];

    let initial_spawn_count = PROD_SPAWN_COUNT.load(Ordering::SeqCst);

    for case in cases {
        let marker = ws.join(format!("child-marker-{}", case));
        let script = format!("printf executed > {}\nexit 0\n", marker.display());

        let mut contract = seal_contract(&ws, &policy, &["sh"], &format!("nonce-tamper-{}", case));
        assert!(
            contract.verify_digest(),
            "{case}: base contract must verify"
        );

        match case {
            "fs_allow_read" => contract
                .filesystem
                .allow_read
                .push(PathBuf::from("/etc/evil_read")),
            "fs_allow_write" => contract
                .filesystem
                .allow_write
                .push(PathBuf::from("/usr/bin/evil_write")),
            "fs_deny_read" => contract
                .production
                .as_mut()
                .unwrap()
                .installation_policy
                .deny_read
                .push(PathBuf::from("/tmp/deny_read")),
            "fs_deny_write" => contract
                .production
                .as_mut()
                .unwrap()
                .installation_policy
                .deny_write
                .push(PathBuf::from("/tmp/deny_write")),
            "fs_cow_overlay" => contract.filesystem.cow_overlay = true,
            "fs_execution_root_ro" => contract.filesystem.execution_root_ro = true,
            "env_explicit_vars" => {
                contract
                    .environment
                    .explicit_vars
                    .insert("EVIL_VAR".into(), "1".into());
            }
            "env_redacted_patterns" => contract
                .environment
                .redacted_patterns
                .push("SECRET_*".into()),
            "env_inject_session_nonce" => contract.environment.inject_session_nonce = false,
            "net_mode" => contract.network.mode = NetworkMode::Allowlist,
            "net_allowed_domains" => contract
                .network
                .allowed_domains
                .push("exfiltrate.corp".into()),
            "net_allowed_ports" => contract.network.allowed_ports.push(9090),
            "net_allowed_ips" => contract
                .production
                .as_mut()
                .unwrap()
                .installation_policy
                .allow_cidr
                .push("10.0.0.0/8".into()),
            "net_debug_ports" => {
                contract.production.as_mut().unwrap().debug_ports = Some(DebugPortConfig::default())
            }
            "limits_max_memory_mb" => contract.resources.max_memory_bytes ^= 0x10000,
            "limits_max_pids" => contract.resources.max_pids += 50,
            "limits_max_cpu_seconds" => contract.resources.max_wall_time_ms += 10000,
            "limits_max_file_size_mb" => contract.resources.max_file_size_bytes += 1024 * 1024,
            "exec_allowed_executables" => contract
                .filesystem
                .allow_execute
                .push(PathBuf::from("/bin/evil_sh")),
            "exec_forbidden_executables" => contract
                .production
                .as_mut()
                .unwrap()
                .installation_policy
                .deny_resolved
                .push(DenyEntry {
                    path: PathBuf::from("/bin/forbidden"),
                    is_dir: false,
                }),
            "exec_invoked_binary" => {
                contract.agent_identity.invoked_binary = PathBuf::from("/bin/evil_bin")
            }
            "exec_invoked_args" => contract
                .agent_identity
                .invoked_args
                .push("--malicious".into()),
            "secrets_mask_paths" => contract
                .filesystem
                .mask_paths
                .push(PathBuf::from("/root/.ssh/id_rsa")),
            "tier_requirement" => contract.production.as_mut().unwrap().tier = Some(Tier::FsOnly),
            "backend_requirement" => {
                contract.production.as_mut().unwrap().backend = "tampered-backend".into()
            }
            "missing_production" => contract.production = None,
            _ => unreachable!(),
        }

        // Direct unresealed tamper invalidates digest (or missing production)
        assert!(
            !contract.verify_digest() || case == "missing_production",
            "{case}: unresealed contract must fail digest verification"
        );

        let spawn_count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
        let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);

        assert_eq!(
            out.result.verdict,
            Verdict::Inconclusive,
            "{case}: verifier must fail-closed on tampered contract"
        );
        assert_eq!(
            log.len(),
            0,
            "{case}: SpawnLog must record 0 spawns on tamper"
        );
        assert!(
            out.spawn_pid.is_none(),
            "{case}: spawn_pid must be None on tamper"
        );
        assert!(
            !marker.exists(),
            "{case}: child marker must not exist — child process MUST NOT run"
        );
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            spawn_count_before,
            "{case}: PROD_SPAWN_COUNT must not increment on tampered contract"
        );
    }

    assert_eq!(
        PROD_SPAWN_COUNT.load(Ordering::SeqCst),
        initial_spawn_count,
        "spawn ledger must remain strictly unchanged across all tampering tests"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 2. RESEALED CONTRACT TAMPERING — PROJECTION CONSISTENCY
// ===========================================================================

#[test]
fn test_tamper_matrix_resealed_fails_closed_no_spawn() {
    let _lock = crate::common::prod_spawn_test_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let ws = temp_dir("tamper-resealed-ws");
    let scen = test_scenario("TAMPER-RESEAL-001", Category::FsRead, 1);
    let policy = functional_policy(&ws);

    let cases = [
        "fs_allow_read",
        "fs_allow_write",
        "fs_cow_overlay",
        "fs_execution_root_ro",
        "env_explicit_vars",
        "env_redacted_patterns",
        "env_inject_session_nonce",
        "net_mode",
        "net_allowed_domains",
        "net_allowed_ports",
        "limits_max_memory_mb",
        "limits_max_pids",
        "limits_max_cpu_seconds",
        "limits_max_file_size_mb",
        "exec_allowed_executables",
        "exec_invoked_binary",
        "exec_invoked_args",
        "secrets_mask_paths",
        "tier_requirement",
        "backend_requirement",
    ];

    let initial_spawn_count = PROD_SPAWN_COUNT.load(Ordering::SeqCst);

    for case in cases {
        let marker = ws.join(format!("resealed-marker-{}", case));
        let script = format!("printf executed > {}\nexit 0\n", marker.display());

        let mut contract = seal_contract(&ws, &policy, &["sh"], &format!("nonce-reseal-{}", case));
        assert!(contract.verify_digest());

        match case {
            "fs_allow_read" => contract
                .filesystem
                .allow_read
                .push(PathBuf::from("/etc/resealed_read")),
            "fs_allow_write" => contract
                .filesystem
                .allow_write
                .push(PathBuf::from("/usr/bin/resealed_write")),
            "fs_cow_overlay" => contract.filesystem.cow_overlay = true,
            "fs_execution_root_ro" => contract.filesystem.execution_root_ro = true,
            "env_explicit_vars" => {
                contract
                    .environment
                    .explicit_vars
                    .insert("RESEALED_VAR".into(), "1".into());
            }
            "env_redacted_patterns" => contract
                .environment
                .redacted_patterns
                .push("SECRET_*".into()),
            "env_inject_session_nonce" => contract.environment.inject_session_nonce = false,
            "net_mode" => contract.network.mode = NetworkMode::Allowlist,
            "net_allowed_domains" => contract
                .network
                .allowed_domains
                .push("resealed.corp".into()),
            "net_allowed_ports" => contract.network.allowed_ports.push(8443),
            "limits_max_memory_mb" => contract.resources.max_memory_bytes ^= 0x20000,
            "limits_max_pids" => contract.resources.max_pids += 10,
            "limits_max_cpu_seconds" => contract.resources.max_wall_time_ms += 5000,
            "limits_max_file_size_mb" => contract.resources.max_file_size_bytes += 2 * 1024 * 1024,
            "exec_allowed_executables" => contract
                .filesystem
                .allow_execute
                .push(PathBuf::from("/bin/resealed_sh")),
            "exec_invoked_binary" => {
                contract.agent_identity.invoked_binary = PathBuf::from("/bin/resealed_bin")
            }
            "exec_invoked_args" => contract
                .agent_identity
                .invoked_args
                .push("--resealed-flag".into()),
            "secrets_mask_paths" => contract
                .filesystem
                .mask_paths
                .push(PathBuf::from("/root/.ssh/id_rsa")),
            "tier_requirement" => contract.production.as_mut().unwrap().tier = Some(Tier::FsOnly),
            "backend_requirement" => {
                contract.production.as_mut().unwrap().backend = "resealed-rogue-backend".into()
            }
            _ => unreachable!(),
        }

        // Reseal the mutated contract: verify_digest is now true, but projection/backend is inconsistent
        contract = contract.unsealed().seal().expect("reseal mutated contract");
        assert!(
            contract.verify_digest(),
            "{case}: resealed contract must have valid digest"
        );

        let spawn_count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
        let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);

        assert_eq!(
            out.result.verdict,
            Verdict::Inconclusive,
            "{case}: resealed tampered projection must fail-closed"
        );
        assert_eq!(log.len(), 0, "{case}: resealed tamper must not spawn child");
        assert!(out.spawn_pid.is_none());
        assert!(
            !marker.exists(),
            "{case}: resealed tamper must not execute child"
        );
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            spawn_count_before,
            "{case}: PROD_SPAWN_COUNT must not increment on resealed tamper"
        );
    }

    assert_eq!(
        PROD_SPAWN_COUNT.load(Ordering::SeqCst),
        initial_spawn_count,
        "spawn ledger must remain strictly unchanged after all resealed tamper attempts"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 3. PRODUCTION SPAWN LEDGER & OBSERVABLE MARKER BARRIER
// ===========================================================================

#[test]
fn test_tamper_production_spawn_ledger_and_marker_guarantee() {
    let _lock = crate::common::prod_spawn_test_lock()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    let tmp = temp_dir("prod-spawn-ledger");
    let marker = tmp.join("child-started");

    let count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);

    // Prepare a real production execution
    let mut prepared = UnpreparedProductionExecution::new(
        Backend::detect(NetMode::Off, false).expect("detect mechanics"),
        functional_policy(&tmp),
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf started > child-started".into(),
        ],
        tmp.clone(),
        std::collections::HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(10)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.into(),
    )
    .prepare()
    .expect("prepare production execution");

    // Tamper with contract in-flight using contract_mut_for_test
    prepared
        .contract_mut_for_test()
        .filesystem
        .allow_write
        .push(PathBuf::from("/var/evil"));
    assert!(
        !prepared.contract().verify_digest(),
        "in-flight tamper must invalidate digest"
    );

    // Attempt spawn: must fail closed before mechanics.spawn
    let spawn_result = prepared.spawn();
    assert!(
        spawn_result.is_err(),
        "in-flight tampered contract must fail spawn"
    );

    // Assert on spawn ledger: PROD_SPAWN_COUNT MUST NOT INCREMENT
    assert_eq!(
        PROD_SPAWN_COUNT.load(Ordering::SeqCst),
        count_before,
        "PROD_SPAWN_COUNT must not increment on failed spawn"
    );

    // Assert on observable child marker: CHILD MUST NOT RUN
    assert!(!marker.exists(), "child process marker must not exist");

    // Positive control: untampered contract succeeds, creates marker, increments ledger by exactly 1
    let control_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
    let spawned = UnpreparedProductionExecution::new(
        Backend::detect(NetMode::Off, false).expect("detect mechanics"),
        functional_policy(&tmp),
        vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf started > child-started".into(),
        ],
        tmp.clone(),
        std::collections::HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(10)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.into(),
    )
    .prepare()
    .expect("prepare control")
    .spawn()
    .expect("spawn control");

    spawned.wait_collect();
    assert_eq!(
        std::fs::read_to_string(&marker).unwrap(),
        "started",
        "positive control must create marker"
    );
    assert_eq!(
        PROD_SPAWN_COUNT.load(Ordering::SeqCst),
        control_before + 1,
        "positive control must increment PROD_SPAWN_COUNT by exactly 1"
    );

    let _ = std::fs::remove_dir_all(tmp);
}

// ===========================================================================
// 4. CROSS-EXECUTION IDENTITY BINDING REGRESSIONS (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_identity_binding_evidence_rejected() {
    let ws_a = temp_dir("cross-id-a");
    let ws_b = temp_dir("cross-id-b");
    let scen_a = aux_scenario("TAMPER-CROSS-A");
    let scen_b = aux_scenario("TAMPER-CROSS-B");

    let policy_a = functional_policy(&ws_a);
    let policy_b = functional_policy(&ws_b);

    let contract_a = seal_contract(&ws_a, &policy_a, &["sh"], "nonce-cross-a");
    let contract_b = seal_contract(&ws_b, &policy_b, &["sh"], "nonce-cross-b");

    // Execution A with Contract A: produces valid evidence bound to Identity A
    let (out_a, log_a) =
        run_linux_contract(&scen_a, &contract_a, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_a.len(), 1);
    assert_eq!(out_a.result.verdict, Verdict::Pass, "control A must PASS");
    assert!(out_a
        .evidence
        .has_verified_control(&out_a.execution_identity));

    // Execution B with Contract B: produces valid evidence bound to Identity B
    let (out_b, log_b) =
        run_linux_contract(&scen_b, &contract_b, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_b.len(), 1);
    assert_eq!(out_b.result.verdict, Verdict::Pass, "control B must PASS");
    assert!(out_b
        .evidence
        .has_verified_control(&out_b.execution_identity));

    // Prove distinct identities
    assert_ne!(
        out_a.nonce, out_b.nonce,
        "sessions must have distinct nonces"
    );
    assert_ne!(
        out_a.execution_identity.frozen_hash, out_b.execution_identity.frozen_hash,
        "sessions must have distinct frozen hashes"
    );
    assert_ne!(
        out_a.execution_identity.scenario_id, out_b.execution_identity.scenario_id,
        "sessions must have distinct scenario IDs"
    );

    // Cross-execution test 1: Evidence A submitted to satisfy Verification B
    assert!(
        !out_a
            .evidence
            .has_verified_control(&out_b.execution_identity),
        "Evidence A must never have verified control for Identity B"
    );
    let oracle_input_a_in_b = OracleInput {
        scenario: &scen_b,
        evidence: &out_a.evidence,
        nonce: Some(out_b.nonce.as_str()),
        probe_nonce: Some(out_b.nonce.as_str()),
        control_nonce: Some(out_b.nonce.as_str()),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&out_b.execution_identity),
    };
    assert_eq!(
        oracle::judge(&oracle_input_a_in_b),
        Verdict::Inconclusive,
        "Evidence A used for B must be INCONCLUSIVE, never PASS"
    );

    // Cross-execution test 2 (bidirectional): Evidence B submitted to satisfy Verification A
    assert!(
        !out_b
            .evidence
            .has_verified_control(&out_a.execution_identity),
        "Evidence B must never have verified control for Identity A"
    );
    let oracle_input_b_in_a = OracleInput {
        scenario: &scen_a,
        evidence: &out_b.evidence,
        nonce: Some(out_a.nonce.as_str()),
        probe_nonce: Some(out_a.nonce.as_str()),
        control_nonce: Some(out_a.nonce.as_str()),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&out_a.execution_identity),
    };
    assert_eq!(
        oracle::judge(&oracle_input_b_in_a),
        Verdict::Inconclusive,
        "Evidence B used for A must be INCONCLUSIVE, never PASS"
    );

    let _ = std::fs::remove_dir_all(ws_a);
    let _ = std::fs::remove_dir_all(ws_b);
}

// ===========================================================================
// 5. STALE RUN REPLAY REGRESSION (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_stale_run_evidence_rejected() {
    let ws = temp_dir("stale-run-ws");
    let scen = aux_scenario("TAMPER-STALE-RUN");
    let policy = functional_policy(&ws);
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-stale-base");

    // Run 1 (stale run)
    let (out_1, log_1) = run_linux_contract(&scen, &contract, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_1.len(), 1);
    assert_eq!(out_1.result.verdict, Verdict::Pass);

    // Run 2 (fresh run with new session nonce)
    let (out_2, log_2) = run_linux_contract(&scen, &contract, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_2.len(), 1);
    assert_eq!(out_2.result.verdict, Verdict::Pass);

    assert_ne!(
        out_1.nonce, out_2.nonce,
        "fresh runs must receive distinct session nonces"
    );

    // Attempt to satisfy Run 2 using stale Evidence from Run 1
    assert!(
        !out_1
            .evidence
            .has_verified_control(&out_2.execution_identity),
        "Stale Evidence from Run 1 must not match Identity of Run 2"
    );

    let input_stale = OracleInput {
        scenario: &scen,
        evidence: &out_1.evidence,
        nonce: Some(out_2.nonce.as_str()),
        probe_nonce: Some(out_2.nonce.as_str()),
        control_nonce: Some(out_2.nonce.as_str()),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&out_2.execution_identity),
    };
    assert_eq!(
        oracle::judge(&input_stale),
        Verdict::Inconclusive,
        "Stale run replay must yield INCONCLUSIVE, never PASS"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 6. OTHER CONTRACT REPLAY REGRESSION (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_other_contract_evidence_rejected() {
    let ws = temp_dir("other-contract-ws");
    let scen = aux_scenario("TAMPER-OTHER-CONTRACT");

    // Contract A: base policy
    let policy_a = functional_policy(&ws);
    let contract_a = seal_contract(&ws, &policy_a, &["sh"], "nonce-contract-a");

    // Contract C: modified policy (different limits and allowed roots)
    let mut policy_c = functional_policy(&ws);
    policy_c.limits.processes = Some(64);
    policy_c.limits.address_space_bytes = Some(128 * 1024 * 1024);
    let contract_c = seal_contract(&ws, &policy_c, &["sh"], "nonce-contract-c");

    // Run Contract A
    let (out_a, log_a) = run_linux_contract(&scen, &contract_a, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_a.len(), 1);
    assert_eq!(out_a.result.verdict, Verdict::Pass);

    // Run Contract C
    let (out_c, log_c) = run_linux_contract(&scen, &contract_c, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log_c.len(), 1);
    assert_eq!(out_c.result.verdict, Verdict::Pass);

    assert_ne!(
        out_a.execution_identity.frozen_hash, out_c.execution_identity.frozen_hash,
        "different contracts must produce different frozen hashes"
    );

    // Evidence A presented for Contract C identity
    assert!(
        !out_a
            .evidence
            .has_verified_control(&out_c.execution_identity),
        "Evidence A must not match Contract C identity"
    );

    let input = OracleInput {
        scenario: &scen,
        evidence: &out_a.evidence,
        nonce: Some(out_c.nonce.as_str()),
        probe_nonce: Some(out_c.nonce.as_str()),
        control_nonce: Some(out_c.nonce.as_str()),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&out_c.execution_identity),
    };
    assert_eq!(
        oracle::judge(&input),
        Verdict::Inconclusive,
        "Evidence from another contract must be rejected as INCONCLUSIVE"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 7. OTHER NONCE / TAMPERED NONCE REGRESSION (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_other_nonce_rejected() {
    let ws = temp_dir("other-nonce-ws");
    let scen = aux_scenario("TAMPER-OTHER-NONCE");
    let policy = functional_policy(&ws);
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-original");

    let (out, log) = run_linux_contract(&scen, &contract, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log.len(), 1);
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Identity with foreign session nonce
    let mut foreign_identity = out.execution_identity.clone();
    foreign_identity.session_nonce = "deadbeef-foreign-nonce".to_string();

    assert!(
        !out.evidence.has_verified_control(&foreign_identity),
        "Evidence must reject foreign session nonce"
    );

    // Judge with mismatched session nonce
    let input = OracleInput {
        scenario: &scen,
        evidence: &out.evidence,
        nonce: Some("deadbeef-foreign-nonce"),
        probe_nonce: Some("deadbeef-foreign-nonce"),
        control_nonce: Some("deadbeef-foreign-nonce"),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&foreign_identity),
    };
    assert_eq!(
        oracle::judge(&input),
        Verdict::Inconclusive,
        "Mismatched nonce must yield INCONCLUSIVE, never PASS"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 8. OTHER BACKEND REGRESSION (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_other_backend_rejected() {
    let ws = temp_dir("other-backend-ws");
    let scen = aux_scenario("TAMPER-OTHER-BACKEND");
    let policy = functional_policy(&ws);
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-backend");

    let (out, log) = run_linux_contract(&scen, &contract, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(log.len(), 1);
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Identity minted for a foreign backend
    let mut foreign_backend_identity = out.execution_identity.clone();
    foreign_backend_identity.frozen_hash = "deadbeef-other-backend-hash".to_string();

    assert!(
        !out.evidence.has_verified_control(&foreign_backend_identity),
        "Evidence must reject foreign backend hash"
    );

    let input = OracleInput {
        scenario: &scen,
        evidence: &out.evidence,
        nonce: Some(out.nonce.as_str()),
        probe_nonce: Some(out.nonce.as_str()),
        control_nonce: Some(out.nonce.as_str()),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&foreign_backend_identity),
    };
    assert_eq!(
        oracle::judge(&input),
        Verdict::Inconclusive,
        "Foreign backend hash must yield INCONCLUSIVE, never PASS"
    );

    let _ = std::fs::remove_dir_all(ws);
}

// ===========================================================================
// 9. MALFORMED IDENTITY CAN NEVER PASS (Master Task Section 3)
// ===========================================================================

#[test]
fn test_cross_execution_malformed_identity_rejected() {
    let ws = temp_dir("malformed-id-ws");
    let scen = aux_scenario("TAMPER-MALFORMED-ID");
    let policy = functional_policy(&ws);
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-malformed");

    let (out, _) = run_linux_contract(&scen, &contract, POSITIVE_SCRIPT, Vec::new(), true);
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Any empty field makes identity malformed
    let malformed_cases = [
        ExecutionIdentity::new("", &out.nonce, "registry", "frozen"),
        ExecutionIdentity::new(&scen.id, "", "registry", "frozen"),
        ExecutionIdentity::new(&scen.id, &out.nonce, "", "frozen"),
        ExecutionIdentity::new(&scen.id, &out.nonce, "registry", ""),
    ];

    for (idx, malformed_id) in malformed_cases.iter().enumerate() {
        assert!(
            !malformed_id.is_well_formed(),
            "case {idx}: identity with empty field must not be well-formed"
        );
        let input = OracleInput {
            scenario: &scen,
            evidence: &out.evidence,
            nonce: Some(out.nonce.as_str()),
            probe_nonce: Some(out.nonce.as_str()),
            control_nonce: Some(out.nonce.as_str()),
            payload_intact: true,
            env_poisoned: false,
            agreeing_vectors: 1,
            violation_observed: false,
            control_observed: true,
            stdio_complete: true,
            execution_identity: Some(malformed_id),
        };
        assert_eq!(
            oracle::judge(&input),
            Verdict::Inconclusive,
            "case {idx}: malformed identity must yield INCONCLUSIVE"
        );
    }

    let _ = std::fs::remove_dir_all(ws);
}
