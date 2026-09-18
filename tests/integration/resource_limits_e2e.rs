//! Phase 4 End-to-End Resource Limits Integration Tests.
//!
//! Covers:
//! - Complete traversal: requested -> compiled -> sealed -> lowered -> enforced -> host-verified
//!   for every limit (CPU, memory, process count).
//! - Mandated cgroup v2 unavailable fail-closed (exit 125).
//! - Anti-tamper post-seal mutation detection and spawn abort.
//! - Platform unsupported honest status differentiation (no fake PASS).
//! - Rejection of child self-reporting in host evidence verification.

use std::collections::BTreeMap;
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::fsm::StateTransitionError;
use vetto::sandbox::SupervisorEngine;
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::frozen::freeze_spec;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{
    allows_pass, apply_backend_ceiling, select_backend, BackendKind, CanonicalPolicy,
    EnforcementState, PlatformMatrix, SecurityCapability,
};

#[cfg(target_os = "linux")]
use vetto::policy::CgroupConfig;
#[cfg(target_os = "linux")]
use vetto::sandbox::linux::cgroup::setup_cgroup;
#[cfg(target_os = "linux")]
use vetto::sandbox::linux::limits;
#[cfg(target_os = "linux")]
use vetto::verify_ng::sandbox_backend::{HostVerification, LinuxBackend, SandboxBackend};

#[test]
#[cfg(target_os = "linux")]
fn test_e2e_resource_limits_traversal_cpu() {
    // 1. Requested: CPU limits specified via Policy
    let mut policy = Policy::default();
    policy.name = "e2e-cpu-agent".into();
    policy.limits.cpu_seconds = Some(5);
    policy.cpu_max = Some("50%".into());
    policy.cgroup = Some(CgroupConfig {
        cpu_max: Some("50%".into()),
        ..Default::default()
    });

    let cwd = std::env::temp_dir();
    let argv = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let nonce = "nonce-e2e-cpu-test";

    // 2. Compiled: PolicyCompiler::compile_effective projects into SecurityContract
    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &cwd,
        env: &BTreeMap::new(),
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(10)),
        tier: None,
        backend: "linux-enforce".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract = PolicyCompiler::compile_effective(input).expect("compile effective contract");

    // Assert compiled projection
    assert_eq!(contract.resources.max_cpu_percent, 50);
    assert_eq!(contract.agent_identity.agent_name, "e2e-cpu-agent");

    // 3. Sealed: Immutable BLAKE3 signature over the contract
    assert!(!contract.contract_digest_blake3.is_empty());
    assert_eq!(contract.contract_digest_blake3.len(), 64);
    assert!(contract.verify_digest(), "sealed contract must verify");

    // 4. Lowered: Linux lowering sets unraisable setrlimit hard ceilings
    assert!(limits::apply_before_exec(&policy.limits).is_ok());

    // 5. Enforced: LinuxBackend prepares the enforcement plan
    let frozen = freeze_spec(
        "TEST-E2E-CPU",
        "reg-e2e",
        &policy,
        "full",
        &NetMode::Off,
        "linux-enforce",
        &argv,
        &BTreeMap::new(),
        &cwd,
        nonce,
    );
    let canonical = CanonicalPolicy::from_frozen(&frozen);
    let identity = ExecutionIdentity::new("TEST-E2E-CPU", nonce, "reg-e2e", &canonical.frozen_hash);

    let mut backend = LinuxBackend::new();
    let initial_report = backend.prepare(&canonical, &identity);
    assert!(
        initial_report.is_enforced(SecurityCapability::ResourceLimits)
            || initial_report
                .records
                .iter()
                .any(|r| r.capability == SecurityCapability::ResourceLimits)
    );
    backend.note_spawned(1001);

    // 6. Host-verified: Host verification proves CPU limits from host evidence
    let mut verification = HostVerification::none();
    verification.rlimit_cpu_ok = true;
    verification.cgroup_cpu_ok = true;

    backend.note_host_verified(&verification);
    let rep = backend.enforcement().expect("backend enforcement report");
    assert_eq!(
        rep.state_of(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "Host proof must promote ResourceLimits to Verified"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_e2e_resource_limits_traversal_memory() {
    // 1. Requested: Memory ceilings specified via Policy
    let mut policy = Policy::default();
    policy.name = "e2e-mem-agent".into();
    policy.limits.address_space_bytes = Some(268435456); // 256 MiB
    policy.cgroup = Some(CgroupConfig {
        memory_max: Some("256M".into()),
        ..Default::default()
    });

    let cwd = std::env::temp_dir();
    let argv = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let nonce = "nonce-e2e-mem-test";

    // 2. Compiled: Effective minimum of address_space_bytes and cgroup memory_max
    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &cwd,
        env: &BTreeMap::new(),
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(10)),
        tier: None,
        backend: "linux-enforce".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract = PolicyCompiler::compile_effective(input).expect("compile effective contract");
    assert_eq!(contract.resources.max_memory_bytes, 268435456);

    // 3. Sealed: BLAKE3 digest verification
    assert!(contract.verify_digest());

    // 4. Lowered: Linux setrlimit address space lowering
    assert!(limits::apply_before_exec(&policy.limits).is_ok());

    // 5. Enforced: LinuxBackend prepares
    let frozen = freeze_spec(
        "TEST-E2E-MEM",
        "reg-e2e",
        &policy,
        "full",
        &NetMode::Off,
        "linux-enforce",
        &argv,
        &BTreeMap::new(),
        &cwd,
        nonce,
    );
    let canonical = CanonicalPolicy::from_frozen(&frozen);
    let identity = ExecutionIdentity::new("TEST-E2E-MEM", nonce, "reg-e2e", &canonical.frozen_hash);

    let mut backend = LinuxBackend::new();
    backend.prepare(&canonical, &identity);
    backend.note_spawned(1002);

    // 6. Host-verified: Host verification proves memory limit from /proc or cgroup
    let mut verification = HostVerification::none();
    verification.rlimit_as_ok = true;
    verification.cgroup_memory_ok = true;

    backend.note_host_verified(&verification);
    let rep = backend.enforcement().expect("backend report");
    assert_eq!(
        rep.state_of(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "Verified host evidence must promote ResourceLimits to Verified"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_e2e_resource_limits_traversal_pids() {
    // 1. Requested: Process ceilings specified via Policy
    let mut policy = Policy::default();
    policy.name = "e2e-pids-agent".into();
    policy.limits.processes = Some(64);
    policy.cgroup = Some(CgroupConfig {
        pids_max: Some("64".into()),
        ..Default::default()
    });

    let cwd = std::env::temp_dir();
    let argv = vec!["sh".to_string(), "-c".to_string(), "true".to_string()];
    let nonce = "nonce-e2e-pids-test";

    // 2. Compiled: Effective minimum of processes and cgroup pids_max
    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &cwd,
        env: &BTreeMap::new(),
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(10)),
        tier: None,
        backend: "linux-enforce".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract = PolicyCompiler::compile_effective(input).expect("compile effective contract");
    assert_eq!(contract.resources.max_pids, 64);

    // 3. Sealed: BLAKE3 digest verification
    assert!(contract.verify_digest());

    // 4. Lowered: Linux setrlimit nproc lowering
    assert!(limits::apply_before_exec(&policy.limits).is_ok());

    // 5. Enforced: LinuxBackend prepares
    let frozen = freeze_spec(
        "TEST-E2E-PIDS",
        "reg-e2e",
        &policy,
        "full",
        &NetMode::Off,
        "linux-enforce",
        &argv,
        &BTreeMap::new(),
        &cwd,
        nonce,
    );
    let canonical = CanonicalPolicy::from_frozen(&frozen);
    let identity =
        ExecutionIdentity::new("TEST-E2E-PIDS", nonce, "reg-e2e", &canonical.frozen_hash);

    let mut backend = LinuxBackend::new();
    backend.prepare(&canonical, &identity);
    backend.note_spawned(1003);

    // 6. Host-verified: Host verification proves pids limit
    let mut verification = HostVerification::none();
    verification.rlimit_nproc_ok = true;
    verification.cgroup_pids_ok = true;

    backend.note_host_verified(&verification);
    let rep = backend.enforcement().expect("backend report");
    assert_eq!(
        rep.state_of(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "Verified host evidence must promote ResourceLimits to Verified"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_mandated_cgroup_unavailable_fails_closed_125() {
    std::env::set_var("VETTO_TEST_NO_CGROUP", "1");
    let cfg = CgroupConfig {
        memory_max: Some("512M".into()),
        pids_max: Some("128".into()),
        cpu_max: Some("50%".into()),
        ..CgroupConfig::default()
    };
    let res = setup_cgroup(Some(&cfg), None);
    assert!(
        res.is_err(),
        "mandated cgroup without cgroup root must return Err"
    );
    let err = res.err().unwrap();
    assert_eq!(
        err.exit_code(),
        125,
        "mandated cgroup unavailable must map to exit code 125"
    );
    assert!(
        err.to_string().contains("fail-closed exit 125"),
        "error message must cite fail-closed exit 125; got: {err}"
    );
    std::env::remove_var("VETTO_TEST_NO_CGROUP");
}

#[test]
fn test_anti_tamper_all_resource_fields_mutation_blocks_spawn() {
    let mut policy = Policy::default();
    policy.name = "tamper-agent".into();
    policy.limits.cpu_seconds = Some(10);
    policy.limits.address_space_bytes = Some(104857600);
    policy.limits.processes = Some(32);
    policy.limits.file_size_bytes = Some(1048576);

    let cwd = std::env::temp_dir();
    let argv = vec!["true".to_string()];
    let nonce = "nonce-tamper-test";

    let input = EffectivePolicyInput {
        policy: &policy,
        argv: &argv,
        cwd: &cwd,
        env: &BTreeMap::new(),
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(5)),
        tier: None,
        backend: "direct-exec".into(),
        observe_seccomp: false,
        debug_ports: None,
    };
    let contract = PolicyCompiler::compile_effective(input).expect("compile contract");
    assert!(
        contract.verify_digest(),
        "unmodified contract must pass digest verification"
    );

    // 1. Mutate max_cpu_percent
    {
        let mut tampered = contract.clone();
        tampered.resources.max_cpu_percent += 5;
        assert!(
            !tampered.verify_digest(),
            "mutated max_cpu_percent must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_cpu_percent must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }

    // 2. Mutate max_memory_bytes
    {
        let mut tampered = contract.clone();
        tampered.resources.max_memory_bytes ^= 4096;
        assert!(
            !tampered.verify_digest(),
            "mutated max_memory_bytes must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_memory_bytes must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }

    // 3. Mutate max_pids
    {
        let mut tampered = contract.clone();
        tampered.resources.max_pids += 1;
        assert!(
            !tampered.verify_digest(),
            "mutated max_pids must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_pids must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }

    // 4. Mutate max_wall_time_ms
    {
        let mut tampered = contract.clone();
        tampered.resources.max_wall_time_ms += 500;
        assert!(
            !tampered.verify_digest(),
            "mutated max_wall_time_ms must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_wall_time_ms must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }

    // 5. Mutate max_stdout_bytes
    {
        let mut tampered = contract.clone();
        tampered.resources.max_stdout_bytes ^= 1;
        assert!(
            !tampered.verify_digest(),
            "mutated max_stdout_bytes must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_stdout_bytes must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }

    // 6. Mutate max_file_size_bytes
    {
        let mut tampered = contract.clone();
        tampered.resources.max_file_size_bytes += 1024;
        assert!(
            !tampered.verify_digest(),
            "mutated max_file_size_bytes must break digest"
        );
        let sup = SupervisorEngine::new(tampered);
        assert!(
            sup.is_err(),
            "tampered max_file_size_bytes must abort SupervisorEngine::new"
        );
        assert!(matches!(
            sup.err().unwrap(),
            StateTransitionError::FailClosed { .. }
        ));
    }
}

#[test]
fn test_platform_unsupported_status_differentiation_no_fake_pass() {
    let matrix = PlatformMatrix::current();
    // Direct backend reports Unsupported for all enforcement capabilities
    assert!(!matrix.supports(BackendKind::Direct, SecurityCapability::ResourceLimits));
    assert!(!matrix.supports(BackendKind::Direct, SecurityCapability::FilesystemIsolation));
    assert!(!matrix.supports(BackendKind::Direct, SecurityCapability::SyscallRestriction));

    // Prepare a scenario that requires ResourceLimits
    let target = vetto::verify_ng::engine::current_target(None);
    let scen = Scenario {
        id: "TEST-UNSUPPORTED-RESOURCE-LIMITS".to_string(),
        category: Category::Proc,
        severity: Severity::High,
        required_caps: Vec::new(),
        strength: BTreeMap::from([(target.label().to_string(), ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "unsupported test".to_string(),
        residual_risk: String::new(),
    };

    let mut backend = select_backend(BackendKind::Direct);
    let policy_obj = Policy::default();
    let frozen = freeze_spec(
        "TEST-UNSUPPORTED-RESOURCE-LIMITS",
        "reg-test",
        &policy_obj,
        "direct",
        &NetMode::Off,
        "direct-exec",
        &["true".to_string()],
        &BTreeMap::new(),
        &std::env::temp_dir(),
        "nonce-unsup",
    );
    let canonical = CanonicalPolicy::from_frozen(&frozen);
    let identity = ExecutionIdentity::new(
        "TEST-UNSUPPORTED-RESOURCE-LIMITS",
        "nonce-unsup",
        "reg-test",
        &canonical.frozen_hash,
    );
    let report = backend.prepare(&canonical, &identity);

    // Honest reporting: capability state must be Unsupported
    assert_eq!(
        report.state_of(SecurityCapability::ResourceLimits),
        EnforcementState::Unsupported,
        "Direct backend must report Unsupported for ResourceLimits"
    );
    assert!(!report.is_enforced(SecurityCapability::ResourceLimits));
    assert!(report
        .unsupported()
        .contains(&SecurityCapability::ResourceLimits));
    assert!(
        !report.allows_pass(&[SecurityCapability::ResourceLimits]),
        "unsupported ResourceLimits capability must not allow pass"
    );

    // Crucial: allows_pass MUST be false, and Verdict::Pass demoted to Inconclusive (NEVER fake PASS)
    assert!(
        !allows_pass(&report, &scen),
        "unsupported capability must NEVER allow PASS"
    );
    assert_eq!(
        apply_backend_ceiling(Verdict::Pass, &report, &scen),
        Verdict::Inconclusive,
        "Verdict::Pass on unsupported backend must demote to Inconclusive"
    );
    assert_eq!(
        apply_backend_ceiling(Verdict::Fail, &report, &scen),
        Verdict::Fail,
        "Verdict::Fail must be preserved"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn test_reject_child_self_reporting() {
    let mut policy_obj = Policy::default();
    policy_obj.limits.processes = Some(32);

    let frozen = freeze_spec(
        "TEST-SELF-REPORT-REJECTED",
        "reg-test",
        &policy_obj,
        "full",
        &NetMode::Off,
        "linux-enforce",
        &["sh".to_string()],
        &BTreeMap::new(),
        &std::env::temp_dir(),
        "nonce-self-rep",
    );
    let policy = CanonicalPolicy::from_frozen(&frozen);
    let id = ExecutionIdentity::new(
        "TEST-SELF-REPORT-REJECTED",
        "nonce-self-rep",
        "reg-test",
        &policy.frozen_hash,
    );

    let mut backend = LinuxBackend::new();
    backend.prepare(&policy, &id);
    backend.note_spawned(1234);

    // Child reporting: even if child attempts to self-report, HostVerification::none()
    // indicates NO host-observed verification facts.
    let verification = HostVerification::none();
    backend.note_host_verified(&verification);

    let rep = backend.enforcement().expect("backend report");
    assert_ne!(
        rep.state_of(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "Child self-report without host proof must NEVER promote to Verified"
    );
}
