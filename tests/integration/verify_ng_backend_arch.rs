//! Stage 3A backend architecture: enforcement is proven, never configured.
//!
//! These tests assert semantics, not type existence: unsupported backends
//! cannot PASS, preparation failure cannot spawn, identity stays bound, and
//! the oracle remains pure. Stage 3A is architecture only — Linux enforces
//! on Linux (Stage 3B), macOS enforces on macOS (Stage 3C-macOS: Seatbelt
//! write+net-off, no syscall filter, reads broad), Windows stays a
//! placeholder reporting `Unsupported` for containment.

use std::collections::BTreeMap;
use std::path::PathBuf;

use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::frozen::FrozenSpec;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{
    allows_pass, apply_backend_ceiling, required_capabilities, select_backend, BackendKind,
    CanonicalPolicy, EnforcementState, PlatformMatrix, SecurityCapability,
};

fn scenario(id: &str, category: Category) -> Scenario {
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::High,
        required_caps: Vec::new(),
        strength: BTreeMap::from([("linux-full".to_string(), ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "backend-arch integration self-test; proves no containment".to_string(),
        residual_risk: String::new(),
    }
}

fn frozen_fixture() -> FrozenSpec {
    FrozenSpec {
        scenario_id: "TEST-BACKEND-POLICY-001".to_string(),
        registry_hash: "reg-test".to_string(),
        tier: "direct".to_string(),
        net_mode: "off".to_string(),
        backend: "direct-exec (no sandbox; plumbing only)".to_string(),
        argv: vec!["sh".to_string()],
        env: BTreeMap::new(),
        cwd: PathBuf::from("/tmp"),
        allow_read: Vec::new(),
        allow_write: Vec::new(),
        deny_read: Vec::new(),
        deny_write: Vec::new(),
        deny_resolved: Vec::new(),
        nonce: "nonce-test".to_string(),
        policy_bytes: b"test-policy".to_vec(),
    }
}

/// TEST-BACKEND-CAPABILITY-001: backends report capabilities explicitly.
#[test]
fn test_backend_capability_001_reports_explicitly() {
    let matrix = PlatformMatrix::current();
    assert_eq!(matrix.entries.len(), 4 * 8);
    assert!(matrix.supports(BackendKind::Direct, SecurityCapability::HostEvidence));
    for cap in SecurityCapability::all() {
        if cap != SecurityCapability::HostEvidence {
            assert!(
                !matrix.supports(BackendKind::Direct, cap),
                "direct must not claim {cap:?}"
            );
        }
    }
    // Stage 3B: Linux really enforces (landlock+seccomp+rlimit+tree) on
    // Linux; Stage 3C-macOS really enforces (seatbelt write+net-off,
    // rlimit, pgroup) on macOS; Windows stays a placeholder with no
    // support anywhere. No syscall filter and no exec-root READ isolation
    // exist on macOS (SBPL reads are broad): both stay unsupported there.
    #[cfg(target_os = "linux")]
    for cap in SecurityCapability::all() {
        assert!(
            matrix.supports(BackendKind::Linux, cap),
            "Linux {cap:?} must be supported in Stage 3B"
        );
    }
    #[cfg(not(target_os = "linux"))]
    for cap in SecurityCapability::all() {
        assert!(
            !matrix.supports(BackendKind::Linux, cap),
            "Linux {cap:?} must be unsupported off Linux"
        );
    }
    #[cfg(target_os = "macos")]
    {
        for cap in [
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::HostEvidence,
        ] {
            assert!(
                matrix.supports(BackendKind::Macos, cap),
                "macOS {cap:?} must be supported in Stage 3C-macOS"
            );
        }
        for cap in [
            SecurityCapability::SyscallRestriction,
            SecurityCapability::ExecutionRootIsolation,
        ] {
            assert!(
                !matrix.supports(BackendKind::Macos, cap),
                "macOS {cap:?} must stay unsupported (no seccomp; reads broad)"
            );
        }
    }
    #[cfg(not(target_os = "macos"))]
    for cap in SecurityCapability::all() {
        assert!(
            !matrix.supports(BackendKind::Macos, cap),
            "macOS {cap:?} must be unsupported off macOS"
        );
    }
    for kind in [BackendKind::Windows] {
        for cap in SecurityCapability::all() {
            assert!(
                !matrix.supports(kind, cap),
                "{kind:?} {cap:?} must be unsupported"
            );
        }
    }
    let rendered = matrix.render();
    assert!(rendered.contains("direct host-evidence supported"));
    #[cfg(target_os = "linux")]
    assert!(rendered.contains("linux filesystem supported"));
    #[cfg(not(target_os = "linux"))]
    assert!(rendered.contains("linux filesystem unsupported"));
}

/// TEST-BACKEND-UNSUPPORTED-001: unsupported mandatory capability cannot PASS.
#[test]
fn test_backend_unsupported_001_cannot_pass() {
    let blocker = scenario("TEST-BACKEND-UNSUPPORTED-001", Category::FsRead);
    assert!(required_capabilities(&blocker).contains(&SecurityCapability::FilesystemIsolation));
    for kind in [BackendKind::Linux, BackendKind::Macos, BackendKind::Windows] {
        let mut backend = select_backend(kind);
        let spec = frozen_fixture();
        let policy = CanonicalPolicy::from_frozen(&spec);
        let identity = ExecutionIdentity::new(
            &blocker.id,
            "nonce-1",
            "reg-test",
            policy.frozen_hash.as_str(),
        );
        let report = backend.prepare(&policy, &identity);
        assert!(!allows_pass(&report, &blocker));
        assert_eq!(
            apply_backend_ceiling(Verdict::Pass, &report, &blocker),
            Verdict::Inconclusive
        );
        assert_eq!(
            apply_backend_ceiling(Verdict::Fail, &report, &blocker),
            Verdict::Fail
        );
    }
}

/// TEST-BACKEND-POLICY-001: canonical policy crosses the boundary unmutated.
#[test]
fn test_backend_policy_001_no_platform_mutation() {
    let spec = frozen_fixture();
    let first = CanonicalPolicy::from_frozen(&spec);
    let second = CanonicalPolicy::from_frozen(&spec);
    assert_eq!(first, second, "same frozen input must be stable");
    let before = first.clone();
    let identity = ExecutionIdentity::new(
        &first.scenario_id,
        first.session_nonce.as_str(),
        first.registry_hash.as_str(),
        first.frozen_hash.as_str(),
    );
    let mut backend = select_backend(BackendKind::Linux);
    let report = backend.prepare(&first, &identity);
    assert_eq!(first, before, "prepare must not mutate the policy");
    assert_eq!(report.policy_hash, first.policy_hash);
    assert_eq!(report.frozen_hash, first.frozen_hash);
    let mut drifted = spec.clone();
    drifted.net_mode = "allowlist".to_string();
    assert_ne!(
        CanonicalPolicy::from_frozen(&drifted),
        first,
        "enforcement-relevant drift must change the canonical policy"
    );
}

/// TEST-BACKEND-IDENTITY-001: runner execution state stays identity-bound.
#[cfg(unix)]
#[test]
fn test_backend_identity_001_runner_binds_execution() {
    use std::time::Duration;
    use vetto::config::NetMode;
    use vetto::policy::Policy;
    use vetto::verify_ng::runner;

    let scen = scenario("TEST-BACKEND-IDENTITY-001", Category::Aux);
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = runner::ExecutionRequest {
        scenario: &scen,
        policy: &policy,
        net_mode: &net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: b"exit 0\n".to_vec(),
        sentinels: Vec::new(),
        env_extra: BTreeMap::new(),
        deadline: Duration::from_secs(15),
        enable_host_control: false,
    };
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one(&req, &mut log);
    assert_eq!(log.len(), 1);
    let report = out.backend_report.as_ref().expect("prepared report");
    assert_eq!(out.backend_kind, BackendKind::Direct);
    assert!(out.execution_identity.is_well_formed() || out.result.verdict != Verdict::Pass);
    assert!(
        report.binds_identity(&out.execution_identity),
        "report must bind the runner identity"
    );
    let mut foreign = out.execution_identity.clone();
    foreign.session_nonce = "foreign-nonce".to_string();
    assert!(!report.binds_identity(&foreign));
}

/// TEST-BACKEND-FAIL-CLOSED-001: preparation failure cannot become execution.
#[cfg(unix)]
#[test]
fn test_backend_fail_closed_001_no_spawn_on_prepare_failure() {
    use std::time::Duration;
    use vetto::config::NetMode;
    use vetto::policy::Policy;
    use vetto::verify_ng::runner;
    use vetto::verify_ng::sandbox_backend::{
        EnforcementReport, PreparationFailureKind, SandboxBackend,
    };

    struct FailingBackend {
        report: Option<EnforcementReport>,
    }
    impl SandboxBackend for FailingBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Linux
        }
        fn name(&self) -> &'static str {
            "failing test double"
        }
        fn supports(&self, _capability: SecurityCapability) -> bool {
            false
        }
        fn prepare(
            &mut self,
            policy: &CanonicalPolicy,
            identity: &ExecutionIdentity,
        ) -> EnforcementReport {
            let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
                .into_iter()
                .map(|c| (c, EnforcementState::Failed))
                .collect();
            let failures: BTreeMap<SecurityCapability, PreparationFailureKind> =
                SecurityCapability::all()
                    .into_iter()
                    .map(|c| (c, PreparationFailureKind::SpawnRefused))
                    .collect();
            let report = EnforcementReport::build(
                BackendKind::Linux,
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

    let scen = scenario("TEST-BACKEND-FAIL-CLOSED-001", Category::Aux);
    let policy = Policy::default();
    let net = NetMode::Off;
    let req = runner::ExecutionRequest {
        scenario: &scen,
        policy: &policy,
        net_mode: &net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: b"exit 0\n".to_vec(),
        sentinels: Vec::new(),
        env_extra: BTreeMap::new(),
        deadline: Duration::from_secs(15),
        enable_host_control: false,
    };
    let mut log = runner::SpawnLog::new();
    let mut backend = FailingBackend { report: None };
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    assert!(log.is_empty(), "failed preparation must not spawn");
    assert_eq!(out.spawn_pid, None);
    assert_ne!(out.result.verdict, Verdict::Pass);
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let report = out.backend_report.as_ref().expect("failure report");
    assert!(!report.preparation_ok);
}

/// TEST-BACKEND-NO-FAKE-ENFORCEMENT-001: unsupported is never enforced.
#[test]
fn test_backend_no_fake_enforcement_001() {
    let spec = frozen_fixture();
    let policy = CanonicalPolicy::from_frozen(&spec);
    let identity = ExecutionIdentity::new(
        "TEST-BACKEND-POLICY-001",
        "nonce-test",
        "reg-test",
        policy.frozen_hash.as_str(),
    );
    // Stage 3B: Linux `prepare` reports at most `Configured` for
    // confinement (`HostEvidence` is `Enforced` at prepare, like Direct);
    // Stage 3C-macOS follows the same state machine on macOS (and reports
    // all-`Unsupported` off macOS); Windows stays fully `Unsupported`.
    for kind in [BackendKind::Windows] {
        let mut backend = select_backend(kind);
        let report = backend.prepare(&policy, &identity);
        assert!(
            report.enforced().is_empty(),
            "{kind:?} must enforce nothing"
        );
        for cap in SecurityCapability::all() {
            assert!(!report.is_enforced(cap));
            assert_ne!(report.state(cap), EnforcementState::Enforced);
            assert_ne!(report.state(cap), EnforcementState::Verified);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut backend = select_backend(BackendKind::Macos);
        let report = backend.prepare(&policy, &identity);
        assert!(report.enforced().is_empty(), "macOS must enforce nothing off macOS");
        for cap in SecurityCapability::all() {
            assert!(!report.is_enforced(cap));
            assert_ne!(report.state(cap), EnforcementState::Enforced);
            assert_ne!(report.state(cap), EnforcementState::Verified);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut backend = select_backend(BackendKind::Macos);
        let report = backend.prepare(&policy, &identity);
        // `prepare` installs nothing: only `HostEvidence` (observation by
        // construction) is `Enforced`; confinement is at most `Configured`.
        assert_eq!(report.enforced(), vec![SecurityCapability::HostEvidence]);
        for cap in SecurityCapability::all() {
            if cap == SecurityCapability::HostEvidence {
                continue;
            }
            assert!(!report.is_enforced(cap));
            assert_ne!(report.state(cap), EnforcementState::Enforced);
            assert_ne!(report.state(cap), EnforcementState::Verified);
        }
    }
    {
        let mut backend = select_backend(BackendKind::Linux);
        let report = backend.prepare(&policy, &identity);
        for cap in SecurityCapability::all() {
            if cap == SecurityCapability::HostEvidence {
                continue;
            }
            assert!(!report.is_enforced(cap));
            assert_ne!(report.state(cap), EnforcementState::Enforced);
            assert_ne!(report.state(cap), EnforcementState::Verified);
        }
    }
    let mut direct = select_backend(BackendKind::Direct);
    let report = direct.prepare(&policy, &identity);
    assert_eq!(report.enforced(), vec![SecurityCapability::HostEvidence]);
}

/// TEST-BACKEND-ORACLE-PURITY-001: oracle remains pure; backend gate is pure.
#[test]
fn test_backend_oracle_purity_001() {
    use vetto::verify_ng::evidence::Evidence;
    use vetto::verify_ng::oracle::{judge, OracleInput};

    let scen = scenario("TEST-BACKEND-ORACLE-PURITY-001", Category::Aux);
    let id = ExecutionIdentity::new(
        "TEST-BACKEND-ORACLE-PURITY-001",
        "nonce-1",
        "reg-test",
        "frozen-test",
    );
    let expected =
        vetto::verify_ng::evidence::derive_expected_response("test-challenge", "nonce-1");
    let verified = vetto::verify_ng::evidence::attest_control(&id, &expected, expected.as_bytes())
        .expect("mint");
    let mut evidence = Evidence::default();
    evidence.host_fact("wait-status", "exit=0".to_string());
    evidence.host_control_fact(&verified);
    let input = OracleInput {
        scenario: &scen,
        evidence: &evidence,
        nonce: Some("nonce-1"),
        probe_nonce: Some("nonce-1"),
        control_nonce: Some("nonce-1"),
        payload_intact: true,
        env_poisoned: false,
        agreeing_vectors: 1,
        violation_observed: false,
        control_observed: true,
        stdio_complete: true,
        execution_identity: Some(&id),
    };
    assert_eq!(judge(&input), judge(&input), "oracle must be deterministic");
    let backend_id = ExecutionIdentity::new(
        "TEST-BACKEND-ORACLE-PURITY-001",
        "nonce-1",
        "reg-test",
        "frozen-test",
    );
    let mut backend = select_backend(BackendKind::Direct);
    let report = backend.prepare(
        &CanonicalPolicy::from_frozen(&FrozenSpec {
            scenario_id: backend_id.scenario_id.clone(),
            registry_hash: backend_id.registry_hash.clone(),
            tier: "direct".to_string(),
            net_mode: "off".to_string(),
            backend: "direct-exec (no sandbox; plumbing only)".to_string(),
            argv: vec!["sh".to_string()],
            env: BTreeMap::new(),
            cwd: PathBuf::from("/tmp"),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            deny_resolved: Vec::new(),
            nonce: backend_id.session_nonce.clone(),
            policy_bytes: b"test-policy".to_vec(),
        }),
        &backend_id,
    );
    let gated = apply_backend_ceiling(judge(&input), &report, &scen);
    assert_eq!(gated, apply_backend_ceiling(judge(&input), &report, &scen));
}
