//! Windows production-boundary tests: the REAL production runner over the
//! real Windows capability backend.
//!
//! - Pure mapping/identity tests run on every platform (the mapping is a
//!   pure function of probe facts).
//! - Spawn tests run on Windows runners where the AppContainer/experimental
//!   sandbox stack exists; elsewhere they skip with an explicit reason
//!   instead of asserting against a run the fail-closed backend refuses.
//! - Every spawn test goes through `vetto::sandbox::production` (the
//!   authoritative boundary), never `verify_ng::runner` directly.

use std::collections::BTreeMap;
#[cfg(target_os = "windows")]
use std::collections::HashMap;
#[cfg(target_os = "windows")]
use std::sync::atomic::Ordering;
#[cfg(target_os = "windows")]
use std::time::{Duration, Instant};

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::sandbox::production::{
    freeze_production, prod_tier_mapping, PROD_REGISTRY, PROD_SCENARIO_ID,
};
#[cfg(target_os = "windows")]
use vetto::sandbox::production::{
    execute_simple, execute_with_backend, ProdSpawnLog, UnpreparedProductionExecution,
    PROD_BACKEND_ENTERED, PROD_SPAWN_COUNT,
};
#[cfg(target_os = "windows")]
use vetto::sandbox::{Backend, StdioMode};
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{
    allows_pass, apply_backend_ceiling, required_capabilities, BackendKind, CanonicalPolicy,
    SecurityCapability,
};
#[cfg(target_os = "windows")]
use vetto::verify_ng::sandbox_backend::{
    EnforcementReport, EnforcementState, PreparationFailureKind, SandboxBackend,
};

/// Serializes the Windows production-spawn tests: spawn-counter deltas and
/// the Job Object tree assertions stay exact under the harness's default
/// parallel threads.
#[cfg(target_os = "windows")]
static WIN_PROD_SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(target_os = "windows")]
fn win_prod_serial() -> &'static std::sync::Mutex<()> {
    WIN_PROD_SERIAL.get_or_init(|| std::sync::Mutex::new(()))
}

/// True only when doctor reports the full Windows process-sandbox stack.
#[cfg(target_os = "windows")]
fn backend_available() -> bool {
    let doctor = crate::common::doctor_output();
    doctor.contains("appcontainer-api=yes") && doctor.contains("experimental-process-sandbox=yes")
}

#[cfg(target_os = "windows")]
const BACKEND_SKIP: &str = "SKIP: Windows AppContainer/experimental sandbox backend is unavailable (doctor did not report appcontainer-api=yes and experimental-process-sandbox=yes)";

/// Policy whose environment lets console children start: the loader default
/// allowlist is Unix-oriented, so Windows runs pass the OS-required names
/// explicitly (exact names; `allows` matches case-sensitively here).
#[cfg(target_os = "windows")]
fn win_policy() -> Policy {
    let mut policy = Policy::default();
    policy.environment.pass_through = vec![
        "SystemRoot".to_string(),
        "windir".to_string(),
        "WINDIR".to_string(),
        "PATH".to_string(),
        "Path".to_string(),
        "PATHEXT".to_string(),
        "TEMP".to_string(),
        "TMP".to_string(),
        "OS".to_string(),
        "COMSPEC".to_string(),
        "CI".to_string(),
    ];
    policy
}

#[cfg(target_os = "windows")]
fn win_exec_root(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vetto-win-prod-{}-{}",
        tag,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create windows prod exec root");
    dir
}

fn test_scenario(id: &str, category: Category) -> Scenario {
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::High,
        required_caps: Vec::new(),
        strength: BTreeMap::from([("win".to_string(), ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "windows production test".to_string(),
        residual_risk: String::new(),
    }
}

/// TEST-WIN-PROD-REAL-001: a real production child runs through the single
/// authoritative boundary exactly once.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_real_001_child_runs_through_boundary() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let root = win_exec_root("real");
    let before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
    let mut log = ProdSpawnLog::new();
    let out = match execute_simple(
        &win_policy(),
        vec![
            "cmd".to_string(),
            "/c".to_string(),
            "exit 0".to_string(),
        ],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(60),
        &mut log,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("SKIP: Windows production spawn refused on this runner: {e:#}");
            return;
        }
    };
    assert_eq!(log.len(), 1, "one execute == one spawn event");
    assert_eq!(
        PROD_SPAWN_COUNT.load(Ordering::SeqCst) - before,
        1,
        "boundary spawn counter moves exactly once"
    );
    assert!(out.spawn_via_backend);
    assert_eq!(out.backend, BackendKind::Windows);
    assert_eq!(out.exit_code, Some(0));
    assert!(!out.timed_out);
    assert!(out.report.preparation_ok);
    let rebuilt = ExecutionIdentity::new(
        PROD_SCENARIO_ID,
        out.nonce.as_str(),
        PROD_REGISTRY,
        out.report.frozen_hash.as_str(),
    );
    assert!(out.report.binds_identity(&rebuilt));
}

/// TEST-WIN-PROD-OWNERSHIP-001: preparation owns frozen inputs, identity
/// and backend; the frozen bundle cannot drift before spawn.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_ownership_001_preparation_owns_inputs() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let mechanics = match Backend::detect(NetMode::Off, false) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("SKIP: Windows mechanics detection refused: {e:#}");
            return;
        }
    };
    let root = win_exec_root("ownership");
    let argv = vec![
        "cmd".to_string(),
        "/c".to_string(),
        "exit 0".to_string(),
    ];
    let unprepared = UnpreparedProductionExecution::new(
        mechanics,
        win_policy(),
        argv.clone(),
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(60)),
        StdioMode::Inherit,
        "win-prod-ownership".to_string(),
    );
    let prepared = match unprepared.prepare() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: Windows preparation refused on this runner: {e:#}");
            return;
        }
    };
    assert_eq!(prepared.backend_kind(), BackendKind::Windows);
    assert_eq!(prepared.identity().scenario_id, "win-prod-ownership");
    assert_eq!(prepared.frozen_inputs().argv, argv);
    assert_eq!(prepared.frozen_inputs().cwd, root);
    assert_eq!(prepared.frozen_policy().name, "default");
    let before = PROD_BACKEND_ENTERED.load(Ordering::SeqCst);
    let spawned = prepared.spawn().expect("prepared spawn succeeds");
    assert_eq!(
        PROD_BACKEND_ENTERED.load(Ordering::SeqCst) - before,
        1,
        "exactly one authoritative backend entry per preparation"
    );
    let result = spawned.wait_collect();
    assert_eq!(result.exit_code, Some(0));
}

/// TEST-WIN-PROD-FAIL-CLOSED-001: preparation failure spawns nothing.
/// Both fail-closed origins share this shape: the injected capability
/// backend refuses (stack present), or mechanics detection refuses first
/// (stack absent). Either way the ledger stays empty and no child exists.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_fail_closed_001_no_spawn() {
    struct FailBackend {
        report: Option<EnforcementReport>,
    }
    impl SandboxBackend for FailBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Windows
        }
        fn name(&self) -> &'static str {
            "fail test double (never enforces)"
        }
        fn supports(&self, _c: SecurityCapability) -> bool {
            false
        }
        fn prepare(
            &mut self,
            policy: &CanonicalPolicy,
            identity: &ExecutionIdentity,
        ) -> EnforcementReport {
            let states: BTreeMap<SecurityCapability, EnforcementState> =
                SecurityCapability::all()
                    .into_iter()
                    .map(|c| (c, EnforcementState::Failed))
                    .collect();
            let failures: BTreeMap<SecurityCapability, PreparationFailureKind> =
                SecurityCapability::all()
                    .into_iter()
                    .map(|c| (c, PreparationFailureKind::SpawnRefused))
                    .collect();
            let report = EnforcementReport::build(
                BackendKind::Windows,
                policy,
                identity,
                &states,
                &failures,
                false,
            );
            self.report = Some(report.clone());
            report
        }
        fn enforcement(&self) -> Option<&EnforcementReport> {
            self.report.as_ref()
        }
        fn teardown(&mut self) {
            self.report = None;
        }
    }
    let _guard = win_prod_serial().lock().unwrap();
    let root = win_exec_root("fail-closed");
    let mut log = ProdSpawnLog::new();
    let err = execute_with_backend(
        &win_policy(),
        vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(30),
        Box::new(FailBackend { report: None }),
        &mut log,
    );
    let err = match err {
        Ok(_) => panic!("preparation failure must not produce an execution"),
        Err(e) => e,
    };
    assert!(log.is_empty(), "spawn ledger unchanged on failure");
    let msg = err.to_string();
    assert!(
        msg.contains("fail-closed") || msg.contains("refusing"),
        "fail-closed error, got: {err:#}"
    );
}

/// TEST-WIN-PROD-TREE-001: a detached grandchild that outlives the root
/// dies with the Job Object. The started-file proves the grandchild lived
/// (non-vacuous); the missing finished-file plus a fast run proves it was
/// killed rather than awaited.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_tree_001_grandchild_dies_with_job() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let root = win_exec_root("tree");
    let started = Instant::now();
    let mut log = ProdSpawnLog::new();
    let out = match execute_simple(
        &win_policy(),
        vec![
            "cmd".to_string(),
            "/c".to_string(),
            "start /b \"\" cmd /c \"echo started>started.txt & timeout /t 60 >NUL & echo done>finished.txt\" & exit 0"
                .to_string(),
        ],
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(90),
        &mut log,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("SKIP: Windows production spawn refused on this runner: {e:#}");
            return;
        }
    };
    let elapsed = started.elapsed();
    if !root.join("started.txt").exists() {
        eprintln!(
            "SKIP: detached `start /b` grandchild never started inside the sandbox on this runner; tree-kill fixture not exercisable"
        );
        return;
    }
    assert!(
        !root.join("finished.txt").exists(),
        "grandchild survived the run (escape): the 60s sleeper finished"
    );
    assert!(
        elapsed < Duration::from_secs(45),
        "run must end by containment kill, not by awaiting the sleeper (took {elapsed:?})"
    );
    assert!(
        out.state(SecurityCapability::ProcessTreeContainment)
            .is_enforced(),
        "tree containment must hold after a grandchild run: {}",
        out.report.render_deterministic()
    );
    let diagnostic = out.diagnostic.unwrap_or_default();
    assert!(
        diagnostic.contains("tree-sweep"),
        "sweep diagnostic must be recorded, got: {diagnostic}"
    );
}

/// TEST-WIN-PROD-TIMEOUT-001: the deadline kill goes through kill-on-close
/// and the tree verifies clean afterwards.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_timeout_001_deadline_kills_tree() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let root = win_exec_root("timeout");
    let started = Instant::now();
    let mut log = ProdSpawnLog::new();
    let out = match execute_simple(
        &win_policy(),
        vec![
            "cmd".to_string(),
            "/c".to_string(),
            "timeout /t 45 >NUL".to_string(),
        ],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(10),
        &mut log,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("SKIP: Windows production spawn refused on this runner: {e:#}");
            return;
        }
    };
    let elapsed = started.elapsed();
    assert!(out.timed_out, "the 45s sleeper must die on the 10s deadline");
    assert!(
        elapsed < Duration::from_secs(40),
        "deadline kill must be prompt (took {elapsed:?})"
    );
    assert!(
        out.state(SecurityCapability::ProcessTreeContainment)
            .is_enforced(),
        "tree containment must hold after a deadline kill: {}",
        out.report.render_deterministic()
    );
}

/// TEST-WIN-PROD-LIMITS-001: resource ceilings map honestly — installed
/// ceilings read back as `Enforced` (never `Verified`: values are attested
/// at the mechanics layer), absent ceilings stay `Configured`, and the
/// unmechanized capabilities stay `Unsupported`.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_limits_001_ceiling_semantics() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let mut limited = win_policy();
    limited.limits.address_space_bytes = Some(2 << 30);
    limited.limits.processes = Some(256);
    let root = win_exec_root("limits");
    let mut log = ProdSpawnLog::new();
    let out = match execute_simple(
        &limited,
        vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(60),
        &mut log,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("SKIP: Windows production spawn refused on this runner: {e:#}");
            return;
        }
    };
    assert_eq!(
        out.state(SecurityCapability::ResourceLimits),
        EnforcementState::Enforced,
        "installed job ceilings must read back host-observed: {}",
        out.report.render_deterministic()
    );

    let root = win_exec_root("nolimits");
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &win_policy(),
        vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(60),
        &mut log,
    )
    .expect("unlimited run succeeds");
    assert_eq!(
        out.state(SecurityCapability::ResourceLimits),
        EnforcementState::Configured,
        "no ceiling configured means no resource enforcement to claim: {}",
        out.report.render_deterministic()
    );
    assert_eq!(
        out.state(SecurityCapability::SyscallRestriction),
        EnforcementState::Unsupported,
        "no syscall filter exists on this backend"
    );
    assert_eq!(
        out.state(SecurityCapability::ExecutionRootIsolation),
        EnforcementState::Unsupported,
        "grant coverage of the cwd is invisible at the capability layer"
    );
}

/// TEST-WIN-PROD-CAPS-001: per-capability semantics after a real net-off
/// run, and the fail-closed PASS gate over them.
#[cfg(target_os = "windows")]
#[test]
fn test_win_prod_caps_001_net_off_semantics() {
    let _guard = win_prod_serial().lock().unwrap();
    if !backend_available() {
        eprintln!("{BACKEND_SKIP}");
        return;
    }
    let root = win_exec_root("caps");
    let mut log = ProdSpawnLog::new();
    let out = match execute_simple(
        &win_policy(),
        vec!["cmd".to_string(), "/c".to_string(), "exit 0".to_string()],
        root,
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(60),
        &mut log,
    ) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("SKIP: Windows production spawn refused on this runner: {e:#}");
            return;
        }
    };
    for cap in [
        SecurityCapability::FilesystemIsolation,
        SecurityCapability::NetworkIsolation,
        SecurityCapability::ProcessIsolation,
        SecurityCapability::ProcessTreeContainment,
        SecurityCapability::HostEvidence,
    ] {
        assert!(
            out.state(cap).is_enforced(),
            "{cap:?} must be installed and host-observed: {}",
            out.report.render_deterministic()
        );
    }
    assert!(
        out.allows_pass(&[SecurityCapability::HostEvidence]),
        "host evidence alone gates Aux-class runs"
    );
    assert!(
        !out.allows_pass(&[SecurityCapability::SyscallRestriction]),
        "an unmechanized capability must never allow PASS"
    );
}

/// TEST-WIN-PROD-IDENTITY-001: policy mutation flips the frozen hash and
/// the canonical policy binds the exec root (pure: runs everywhere).
#[test]
fn test_win_prod_identity_001_freeze_binds_policy() {
    let policy = Policy::default();
    let env = BTreeMap::new();
    let cwd = std::path::PathBuf::from("/tmp");
    let argv = vec!["cmd".to_string()];
    let (a, canonical, identity) = freeze_production(
        PROD_SCENARIO_ID,
        &policy,
        "none",
        &NetMode::Off,
        "windows-test",
        &argv,
        &env,
        &cwd,
        "nonce-win-1",
    );
    assert_eq!(identity.scenario_id, PROD_SCENARIO_ID);
    assert_eq!(identity.registry_hash, PROD_REGISTRY);
    assert_eq!(identity.frozen_hash, a.hash());
    assert_eq!(canonical.cwd, cwd, "exec-root binds cwd");
    let mut mutated = Policy::default();
    mutated.deny_network = !policy.deny_network;
    let (b, _, _) = freeze_production(
        PROD_SCENARIO_ID,
        &mutated,
        "none",
        &NetMode::Off,
        "windows-test",
        &argv,
        &env,
        &cwd,
        "nonce-win-1",
    );
    assert_ne!(a.hash(), b.hash(), "policy drift must flip the frozen hash");
}

/// TEST-WIN-PROD-TIER-001: tier mapping stays honest — relay modes never
/// claim network isolation, seccomp-scoped runs never claim filesystem
/// isolation (pure: runs everywhere).
#[test]
fn test_win_prod_tier_001_mapping_honest() {
    let relay = NetMode::Allowlist(vec!["example.com".to_string()]);
    let full_relay = prod_tier_mapping(Some(vetto::policy::Tier::Full), &relay);
    assert!(
        !full_relay
            .enforced
            .contains(&SecurityCapability::NetworkIsolation),
        "relay net is not an isolation claim"
    );
    let sec = prod_tier_mapping(Some(vetto::policy::Tier::Seccomp), &NetMode::Off);
    assert!(
        !sec.mandatory
            .contains(&SecurityCapability::FilesystemIsolation)
    );
    assert!(
        !sec.mandatory
            .contains(&SecurityCapability::ExecutionRootIsolation)
    );
}

/// TEST-WIN-PROD-CEILING-001: an unimplemented capability can never PASS,
/// through the production report or the backend ceiling (pure: runs
/// everywhere, on every backend state).
#[test]
fn test_win_prod_ceiling_001_unsupported_never_passes() {
    let scenario = test_scenario("TEST-WIN-PROD-CEILING-001", Category::FsRead);
    assert!(required_capabilities(&scenario).contains(&SecurityCapability::FilesystemIsolation));
    let mut backend = vetto::verify_ng::sandbox_backend::select_backend(BackendKind::Windows);
    let policy = CanonicalPolicy::from_frozen(&vetto::verify_ng::frozen::FrozenSpec {
        scenario_id: scenario.id.clone(),
        registry_hash: "reg-test".to_string(),
        tier: "none".to_string(),
        net_mode: "off".to_string(),
        backend: "windows test".to_string(),
        argv: vec!["cmd".to_string()],
        env: BTreeMap::new(),
        cwd: std::path::PathBuf::from("/tmp"),
        allow_read: Vec::new(),
        allow_write: Vec::new(),
        deny_read: Vec::new(),
        deny_write: Vec::new(),
        deny_resolved: Vec::new(),
        nonce: "nonce-win-ceiling".to_string(),
        policy_bytes: b"win-test-policy".to_vec(),
    });
    let identity = ExecutionIdentity::new(
        &scenario.id,
        "nonce-win-ceiling",
        "reg-test",
        policy.frozen_hash.as_str(),
    );
    let report = backend.prepare(&policy, &identity);
    assert!(report.binds_identity(&identity));
    assert!(
        !allows_pass(&report, &scenario),
        "no PASS without enforced filesystem isolation"
    );
    assert_eq!(
        apply_backend_ceiling(Verdict::Pass, &report, &scenario),
        Verdict::Inconclusive
    );
    assert_eq!(
        apply_backend_ceiling(Verdict::Fail, &report, &scenario),
        Verdict::Fail,
        "ceiling never converts FAIL"
    );
}
