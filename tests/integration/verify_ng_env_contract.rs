//! Phase 2 Environment Isolation Battery (Master Task Section 5).
//!
//! Enforces and verifies that forbidden host environment values never enter execution:
//! 1. Arbitrary host variables (never passed unless explicitly permitted by contract)
//! 2. Sensitive-looking variables (API keys, secrets, tokens, credentials)
//! 3. PATH manipulation (hygiene against '.', empty, '~', and relative components)
//! 4. Inherited environment (scrubbed clean-room; execution receives only contract variables)
//! 5. Internal Vetto variables (e.g. VETTO_SEATBELT_MODE, unconfigured diagnostic flags)
//! 6. Variables explicitly denied by contract (contract.environment.redacted_patterns or policy.environment.deny)
//! 7. Environment mutation after start (host environment immutability before == after, child mutation contained)
//!
//! Consumes the SAME sealed [`SecurityContract`] used by production execution.
//! Verifier distinguishes "allowed by contract" from "present because host leaked"
//! without making any blanket prefix assumptions outside contract semantics.
//! Uses independent runtime evidence only (`HOST_FACT` via `/proc/<pid>/environ` and supervisor state).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::{EnvironmentPolicy, Policy};
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::SecurityContract;
use vetto::verify_ng::environment::{
    verify_execution_environment, EnvironmentViolation, HarnessEnvContext,
};
use vetto::verify_ng::model::{Category, ClaimStrength, EvidenceTier, Verdict};
use vetto::verify_ng::registry::{registry, Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{EnforcementState, LinuxBackend, SecurityCapability};
use vetto::verify_ng::{engine, runner};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_id(prefix: &str) -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("vetto-env-{prefix}-{}-{n}", std::process::id())
}

/// Create a test scenario with Blocker severity.
fn test_scenario(id: &str, category: Category, quorum: usize) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Strong),
        ]),
        quorum,
        known_limitation: "Phase 2 environment isolation battery test".to_string(),
        residual_risk: String::new(),
    }
}

/// Helper: creates a dedicated temp directory.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(next_test_id(name));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Helper: compile and seal an authoritative SecurityContract for the given workspace, policy, and explicit env.
fn seal_contract_with_env(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    env_vars: &BTreeMap<String, String>,
    nonce: &str,
) -> SecurityContract {
    let argv_strings: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let input = EffectivePolicyInput {
        policy,
        argv: &argv_strings,
        cwd: workspace,
        env: env_vars,
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

/// Helper: compile and seal an authoritative SecurityContract with empty explicit env.
fn seal_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    nonce: &str,
) -> SecurityContract {
    seal_contract_with_env(workspace, policy, argv, &BTreeMap::new(), nonce)
}

/// Run a scenario under LinuxBackend using a sealed SecurityContract.
fn run_linux_contract(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    env_extra: BTreeMap<String, String>,
    enable_host_control: bool,
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
        env_extra,
        deadline: Duration::from_secs(15),
        enable_host_control,
        contract: Some(contract),
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    (out, log)
}

fn assert_enforced_or_skip(out: &runner::ExecutionOutcome, cap: SecurityCapability) -> bool {
    if let Some(report) = &out.backend_report {
        if report.state(cap) == EnforcementState::Unsupported {
            assert_ne!(out.result.verdict, Verdict::Pass);
            return false;
        }
        assert!(
            report.state(cap).is_enforced(),
            "{cap:?} must be enforced: {}",
            report.render_deterministic()
        );
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// Positive control helper script (performs rotation challenge-response)
// ---------------------------------------------------------------------------
const CONTROL_ROTATION_SCRIPT: &str = concat!(
    "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
    "S=\"$C$VETTO_VNG_NONCE\"\n",
    "head=${S%????????}\n",
    "tail=${S#$head}\n",
    "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
    "exit 0\n"
);

// ---------------------------------------------------------------------------
// 1. Arbitrary Host Variable Isolation
// ---------------------------------------------------------------------------

#[test]
fn test_env_arbitrary_host_var_not_leaked() {
    let scen = test_scenario("ENV-ARBITRARY-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-arbitrary");

    // Set an arbitrary host variable in the supervisor process
    let arbitrary_key = "VETTO_TEST_HOST_ARBITRARY_VAR_987";
    let arbitrary_val = "secret_arbitrary_host_payload_42";
    std::env::set_var(arbitrary_key, arbitrary_val);

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-arb-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        std::env::remove_var(arbitrary_key);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(out.control_observed, "control must be observed");
    assert!(!out.violation_observed, "no env violation observed");

    // Check host facts: arbitrary host var must NOT have leaked
    let has_leak_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "env-violation"
            && f.detail.contains(arbitrary_key)
    });
    assert!(!has_leak_fact, "arbitrary host variable must not leak");

    let has_clean_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "env-isolated"
            && f.detail.contains("clean:contract-conforming")
    });
    assert!(has_clean_fact, "clean env fact must be stamped");
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
    std::env::remove_var(arbitrary_key);
}

// ---------------------------------------------------------------------------
// 2. Sensitive-Looking Variables Blocked
// ---------------------------------------------------------------------------

#[test]
fn test_env_sensitive_looking_variables_not_leaked() {
    let scen = test_scenario("ENV-SENSITIVE-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-sensitive");

    // Set sensitive variables in host process
    let sensitive_keys = [
        ("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE"),
        ("GITHUB_TOKEN", "ghp_supersecretgithubtoken1234567890"),
        ("ANTHROPIC_API_KEY", "sk-ant-api03-verysecretkey"),
        ("PRIVATE_KEY_DATA", "my_private_rsa_key_bytes"),
    ];
    for (k, v) in sensitive_keys {
        std::env::set_var(k, v);
    }

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-sens-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        for (k, _) in sensitive_keys {
            std::env::remove_var(k);
        }
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(out.control_observed);
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Verify none of the sensitive variables are recorded as present
    for (k, _) in sensitive_keys {
        let leaked = out
            .evidence
            .facts
            .iter()
            .any(|f| f.name == "env-violation" && f.detail.contains(k));
        assert!(!leaked, "sensitive var '{k}' must not leak");
        std::env::remove_var(k);
    }
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 3. PATH Manipulation & Hygiene Sanitization
// ---------------------------------------------------------------------------

#[test]
fn test_env_path_manipulation_sanitized() {
    let scen = test_scenario("ENV-PATH-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-path");

    // Dirty PATH with '.', empty components '::', and '~' relative entry
    let orig_path = std::env::var("PATH").unwrap_or_else(|_| "/usr/bin:/bin".to_string());
    let dirty_path = format!(".:/tmp/fake_evil_bin::{}:~/.malicious", orig_path);
    std::env::set_var("PATH", &dirty_path);

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-path-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        std::env::set_var("PATH", &orig_path);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(
        !out.violation_observed,
        "dirty PATH must be sanitized by runner before execution"
    );
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Verify hygiene host fact was stamped
    let hygiene_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "vector:env-hygiene"
            && f.detail.contains("clean:path-and-internal")
    });
    assert!(hygiene_fact, "path hygiene vector must be attested");

    std::env::set_var("PATH", &orig_path);
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 4. Inherited Environment Scrubbed (Clean-Room Execution)
// ---------------------------------------------------------------------------

#[test]
fn test_env_inherited_environment_scrubbed_clean_room() {
    let scen = test_scenario("ENV-INHERIT-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-inherit");

    let host_vars = [
        ("VETTO_HOST_PROBE_A", "val_a"),
        ("VETTO_HOST_PROBE_B", "val_b"),
        ("VETTO_HOST_PROBE_C", "val_c"),
    ];
    for (k, v) in host_vars {
        std::env::set_var(k, v);
    }

    // Clean-room policy: only PATH is passed through
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-inherit-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        for (k, _) in host_vars {
            std::env::remove_var(k);
        }
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    for (k, _) in host_vars {
        let leaked = out
            .evidence
            .facts
            .iter()
            .any(|f| f.name == "env-violation" && f.detail.contains(k));
        assert!(!leaked, "unallowed host variable '{k}' must not leak");
        std::env::remove_var(k);
    }
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 5. Internal Vetto Variables Blocked
// ---------------------------------------------------------------------------

#[test]
fn test_env_internal_vetto_variables_not_leaked() {
    let scen = test_scenario("ENV-INTERNAL-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-internal");

    // Internal diagnostic variables in host environment
    let internal_vars = [
        ("VETTO_SEATBELT_MODE", "permissive"),
        ("VETTO_INTERNAL_DEBUG_FLAG", "1"),
    ];
    for (k, v) in internal_vars {
        std::env::set_var(k, v);
    }

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-internal-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        for (k, _) in internal_vars {
            std::env::remove_var(k);
        }
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    for (k, _) in internal_vars {
        let leaked = out
            .evidence
            .facts
            .iter()
            .any(|f| f.name == "env-violation" && f.detail.contains(k));
        assert!(!leaked, "internal variable '{k}' must not leak");
        std::env::remove_var(k);
    }
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 6. Explicitly Denied Variables Blocked
// ---------------------------------------------------------------------------

#[test]
fn test_env_explicitly_denied_variables_blocked() {
    let scen = test_scenario("ENV-DENIED-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-denied");

    let denied_var = "DENIED_BY_CONTRACT_VAR";
    std::env::set_var(denied_var, "attempted_leak_val");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string(), denied_var.to_string()],
            deny: vec![denied_var.to_string()],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-denied-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        std::env::remove_var(denied_var);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    let leaked = out
        .evidence
        .facts
        .iter()
        .any(|f| f.name == "env-violation" && f.detail.contains(denied_var));
    assert!(!leaked, "explicitly denied variable must be stripped");

    std::env::remove_var(denied_var);
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 7. Post-Start Environment Mutation Immutability
// ---------------------------------------------------------------------------

#[test]
fn test_env_post_start_mutation_contained() {
    let scen = test_scenario("ENV-MUTATE-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-mutate");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-mutate-01");

    // Child attempts post-start environment mutation
    let script = concat!(
        "export ATTACK_POST_START_MUTATION=\"host_takeover\"\n",
        "export PATH=\"/fake_attacker_path:$PATH\"\n",
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "S=\"$C$VETTO_VNG_NONCE\"\n",
        "head=${S%????????}\n",
        "tail=${S#$head}\n",
        "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "exit 0\n"
    );

    let host_before: BTreeMap<String, String> = std::env::vars().collect();
    let (out, log) =
        run_linux_contract(&scen, &contract, script, Vec::new(), BTreeMap::new(), true);
    let host_after: BTreeMap<String, String> = std::env::vars().collect();

    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert_eq!(
        host_before, host_after,
        "host environment must remain strictly immutable across execution"
    );
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 8. Verifier Distinguishes "Allowed by Contract" from "Host Leaked"
// ---------------------------------------------------------------------------

#[test]
fn test_env_verifier_distinguishes_allowed_by_contract_from_host_leaked() {
    let scen = test_scenario("ENV-DISTINGUISH-001", Category::Secrets, 1);
    let ws = temp_dir("ws-env-distinguish");

    // Explicit contract variable specified in contract.environment.explicit_vars
    let mut explicit_env = BTreeMap::new();
    explicit_env.insert(
        "CONTRACT_AUTHORIZED_VAR".to_string(),
        "app_value_123".to_string(),
    );

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract =
        seal_contract_with_env(&ws, &policy, &["sh"], &explicit_env, "nonce-env-dist-01");

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(!out.violation_observed);
    assert_eq!(out.result.verdict, Verdict::Pass);

    // Verify explicit distinction in host facts
    let contract_var_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "env-item"
            && f.detail == "allowed_by_contract:CONTRACT_AUTHORIZED_VAR"
    });
    assert!(
        contract_var_fact,
        "contract-authorized var must be stamped allowed_by_contract"
    );

    let path_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "env-item"
            && f.detail == "allowed_by_contract:PATH"
    });
    assert!(path_fact, "PATH must be stamped allowed_by_contract");

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 9. No Blanket Prefix Assumptions
// ---------------------------------------------------------------------------

#[test]
fn test_env_no_blanket_prefix_assumption() {
    // Contract semantics alone dictate what is safe.
    // An arbitrary variable named "VETTO_CUSTOM" or "SAFE_LOOKING_KEY" must NOT
    // be assumed safe by prefix if not authorized in contract semantics.
    let ws = temp_dir("ws-env-no-blanket");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-nobp-01");

    // Unit check against verifier: an unallowed "VETTO_CUSTOM" must be flagged as violation
    let host_before = BTreeMap::from([
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("VETTO_CUSTOM".to_string(), "arbitrary_val".to_string()),
    ]);
    let host_after = host_before.clone();
    let observed = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("VETTO_CUSTOM".to_string(), "arbitrary_val".to_string()),
    ];

    let harness_ctx = HarnessEnvContext {
        isolated_home: ws.clone(),
        fixture_root: ws.clone(),
        session_nonce: "nonce-env-nobp-01".to_string(),
        has_control_channel: false,
        control_downlink_val: None,
        control_uplink_val: None,
    };

    let report = verify_execution_environment(
        &contract,
        &observed,
        &host_before,
        &host_after,
        Some(&harness_ctx),
    );

    assert!(
        !report.clean,
        "unauthorized variable must be rejected without prefix assumption"
    );
    assert!(report.violations.iter().any(|v| match v {
        EnvironmentViolation::InternalVettoVariableLeaked { key } => key == "VETTO_CUSTOM",
        _ => false,
    }));

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 10. ENV-LEAK-001 Canary Scenario PASS with Sealed Contract
// ---------------------------------------------------------------------------

#[test]
fn test_env_leak_001_pass_with_sealed_contract() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "ENV-LEAK-001")
        .expect("ENV-LEAK-001 must exist in registry");

    let ws = temp_dir("ws-env-leak-pass");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-env-leak-01");

    let (out, log) = run_linux_contract(
        scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        BTreeMap::new(),
        true,
    );
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(out.control_observed, "host control must be verified");
    assert!(out.evidence.has_host_fact(), "HOST_FACT must be present");
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "ENV-LEAK-001 must PASS with sealed contract"
    );

    // Assert vector facts stamped
    let scrub_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "vector:env-scrub"
            && f.detail == "clean:scrubbed"
    });
    assert!(scrub_fact, "env scrub vector must be stamped");

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 11. Negative Trap: Arbitrary Host Variable Leak Detected -> Verdict::Fail
// ---------------------------------------------------------------------------

#[test]
fn test_env_arbitrary_leak_detection_yields_fail() {
    let scen = test_scenario("ENV-TRAP-ARB-001", Category::Secrets, 1);
    let ws = temp_dir("ws-trap-arb");

    let leaked_key = "ROGUE_HOST_LEAKED_VAR";
    let leaked_val = "pwned_payload";
    std::env::set_var(leaked_key, leaked_val);

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trap-arb-01");

    // Inject leaked variable via test extra to simulate rogue leak reaching execution
    let mut env_extra = BTreeMap::new();
    env_extra.insert(leaked_key.to_string(), leaked_val.to_string());

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        env_extra,
        true,
    );
    assert_eq!(log.len(), 1);

    assert!(
        out.violation_observed,
        "verifier must observe host leak violation"
    );
    assert_eq!(
        out.result.verdict,
        Verdict::Fail,
        "leaked arbitrary host variable must fail closed to Verdict::Fail"
    );

    let has_leak_fact = out.evidence.facts.iter().any(|f| {
        f.tier == EvidenceTier::HostFact
            && f.name == "env-item"
            && f.detail == format!("leaked_from_host:{leaked_key}")
    });
    assert!(has_leak_fact, "verifier must record leaked_from_host fact");

    std::env::remove_var(leaked_key);
    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 12. Negative Trap: Sensitive Variable Leak Detected -> Verdict::Fail
// ---------------------------------------------------------------------------

#[test]
fn test_env_sensitive_leak_detection_yields_fail() {
    let scen = test_scenario("ENV-TRAP-SENS-001", Category::Secrets, 1);
    let ws = temp_dir("ws-trap-sens");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trap-sens-01");

    // Inject sensitive variable to test detector
    let mut env_extra = BTreeMap::new();
    env_extra.insert(
        "AWS_SECRET_ACCESS_KEY".to_string(),
        "supersecretkey".to_string(),
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        env_extra,
        true,
    );
    assert_eq!(log.len(), 1);

    assert!(out.violation_observed);
    assert_eq!(
        out.result.verdict,
        Verdict::Fail,
        "sensitive variable leak must fail closed to Verdict::Fail"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 13. Negative Trap: Explicitly Denied Variable Detected -> Verdict::Fail
// ---------------------------------------------------------------------------

#[test]
fn test_env_denied_var_detection_yields_fail() {
    let scen = test_scenario("ENV-TRAP-DENY-001", Category::Secrets, 1);
    let ws = temp_dir("ws-trap-deny");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec!["EXPLICITLY_DENIED_VAR".to_string()],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trap-deny-01");

    let mut env_extra = BTreeMap::new();
    env_extra.insert(
        "EXPLICITLY_DENIED_VAR".to_string(),
        "forbidden_value".to_string(),
    );

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        env_extra,
        true,
    );
    assert_eq!(log.len(), 1);

    assert!(out.violation_observed);
    assert_eq!(
        out.result.verdict,
        Verdict::Fail,
        "explicitly denied variable must fail closed to Verdict::Fail"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 14. Negative Trap: PATH Manipulation Detected -> Verdict::Fail
// ---------------------------------------------------------------------------

#[test]
fn test_env_path_manipulation_detection_yields_fail() {
    let scen = test_scenario("ENV-TRAP-PATH-001", Category::Secrets, 1);
    let ws = temp_dir("ws-trap-path");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string()],
            deny: vec![],
        },
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trap-path-01");

    // Inject unhygienic PATH with '.'
    let mut env_extra = BTreeMap::new();
    env_extra.insert("PATH".to_string(), ".:/usr/bin:/bin".to_string());

    let (out, log) = run_linux_contract(
        &scen,
        &contract,
        CONTROL_ROTATION_SCRIPT,
        Vec::new(),
        env_extra,
        true,
    );
    assert_eq!(log.len(), 1);

    assert!(out.violation_observed);
    assert_eq!(
        out.result.verdict,
        Verdict::Fail,
        "PATH manipulation with '.' must fail closed to Verdict::Fail"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 15. Unit Verification Matrix (Edge Cases & Policy Parity)
// ---------------------------------------------------------------------------

#[test]
fn test_env_unit_verification_battery_matrix() {
    let ws = temp_dir("ws-env-unit");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        environment: EnvironmentPolicy {
            pass_through: vec!["PATH".to_string(), "SAFE_APP_VAR".to_string()],
            deny: vec!["DENIED_KEY".to_string(), "BLOCK_*".to_string()],
        },
        ..Default::default()
    };
    let mut explicit = BTreeMap::new();
    explicit.insert("EXPLICIT_CONFIG".to_string(), "conf_val".to_string());
    let contract = seal_contract_with_env(&ws, &policy, &["sh"], &explicit, "nonce-unit-01");

    let harness_ctx = HarnessEnvContext {
        isolated_home: ws.clone(),
        fixture_root: ws.clone(),
        session_nonce: "nonce-unit-01".to_string(),
        has_control_channel: true,
        control_downlink_val: Some("/tmp/downlink".to_string()),
        control_uplink_val: Some("/tmp/uplink".to_string()),
    };

    // Test A: Clean conforming environment
    let host_before = BTreeMap::from([
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("SAFE_APP_VAR".to_string(), "safe".to_string()),
        ("HOST_VAR".to_string(), "host_only".to_string()),
    ]);
    let host_after = host_before.clone();

    let clean_observed = vec![
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("SAFE_APP_VAR".to_string(), "safe".to_string()),
        ("EXPLICIT_CONFIG".to_string(), "conf_val".to_string()),
        ("HOME".to_string(), ws.display().to_string()),
        ("VETTO_RUN_NONCE".to_string(), "nonce-unit-01".to_string()),
        ("VETTO_FIXTURE_ROOT".to_string(), ws.display().to_string()),
        (
            "VETTO_VNG_CONTROL_DOWNLINK".to_string(),
            "/tmp/downlink".to_string(),
        ),
        (
            "VETTO_VNG_CONTROL_UPLINK".to_string(),
            "/tmp/uplink".to_string(),
        ),
        ("VETTO_PROD_NONCE".to_string(), "nonce-unit-01".to_string()),
    ];

    let rep = verify_execution_environment(
        &contract,
        &clean_observed,
        &host_before,
        &host_after,
        Some(&harness_ctx),
    );
    assert!(
        rep.clean,
        "clean observed env must pass verification: {:?}",
        rep.violations
    );
    assert_eq!(rep.violations.len(), 0);

    // Test B: Host HOME leaked instead of isolated HOME
    let mut dirty_observed = clean_observed.clone();
    dirty_observed.retain(|(k, _)| k != "HOME");
    dirty_observed.push(("HOME".to_string(), "/home/victim_user".to_string()));
    let rep_dirty_home = verify_execution_environment(
        &contract,
        &dirty_observed,
        &host_before,
        &host_after,
        Some(&harness_ctx),
    );
    assert!(!rep_dirty_home.clean);
    assert!(rep_dirty_home.violations.iter().any(|v| match v {
        EnvironmentViolation::InheritedEnvironmentUnscrubbed { key } => key == "HOME",
        _ => false,
    }));

    // Test C: Post-start host mutation detected
    let mut host_after_mutated = host_before.clone();
    host_after_mutated.insert("MUTATED_IN_HOST".to_string(), "leaked".to_string());
    let rep_host_mut = verify_execution_environment(
        &contract,
        &clean_observed,
        &host_before,
        &host_after_mutated,
        Some(&harness_ctx),
    );
    assert!(!rep_host_mut.clean);
    assert!(rep_host_mut.violations.iter().any(|v| match v {
        EnvironmentViolation::HostEnvironmentMutated { diff } =>
            diff.iter().any(|d| d.contains("MUTATED_IN_HOST")),
        _ => false,
    }));

    // Test D: Wildcard deny pattern matching
    let mut dirty_wildcard = clean_observed.clone();
    dirty_wildcard.push(("BLOCK_DANGEROUS".to_string(), "evil".to_string()));
    let rep_wildcard = verify_execution_environment(
        &contract,
        &dirty_wildcard,
        &host_before,
        &host_after,
        Some(&harness_ctx),
    );
    assert!(!rep_wildcard.clean);
    assert!(rep_wildcard.violations.iter().any(|v| match v {
        EnvironmentViolation::ExplicitlyDeniedVariablePresent { key } => key == "BLOCK_DANGEROUS",
        _ => false,
    }));

    let _ = std::fs::remove_dir_all(&ws);
}
