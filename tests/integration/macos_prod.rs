//! macOS production boundary tests (Stage 3C-macOS).
//!
//! Every test here drives the authoritative production boundary
//! (`UnpreparedProductionExecution → prepare → spawn → wait_collect /
//! finish`) with the real Seatbelt mechanics — never a placeholder, never
//! stdout-as-proof. Host-observed facts (wait status, canary integrity,
//! `getpgid`, group-death checks, typed enforcement reports) decide.
//!
//! macOS-gated tests run ONLY on macOS runners (via the `build-macos` CI
//! job); the structural and matrix tests below run on every platform with
//! real assertions on both sides (no empty-PASS placeholders anywhere).

use std::collections::BTreeMap;
#[cfg(target_os = "macos")]
use std::collections::HashMap;
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::time::Duration;

#[cfg(target_os = "macos")]
use vetto::config::NetMode;
#[cfg(target_os = "macos")]
use vetto::policy::{DenyEntry, Policy};
#[cfg(target_os = "macos")]
use vetto::sandbox::production::{
    execute_simple, prod_tier_mapping, ProdSpawnLog, PROD_REGISTRY, PROD_SCENARIO_ID,
};
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::frozen::FrozenSpec;
use vetto::verify_ng::sandbox_backend::{
    BackendKind, CanonicalPolicy, EnforcementState, PlatformMatrix, SecurityCapability,
};

#[cfg(target_os = "macos")]
static MACOS_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

#[cfg(target_os = "macos")]
fn scratch(tag: &str) -> PathBuf {
    let n = MACOS_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("vetto-macos-prod-{}-{tag}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create macOS prod scratch dir");
    // `/var` is a symlink to `/private/var`: SBPL subpath matching needs
    // the canonical path on both the policy and the spawn sides.
    std::fs::canonicalize(&dir).unwrap_or(dir)
}

fn canonical_policy(net_mode: &str) -> (CanonicalPolicy, ExecutionIdentity) {
    let spec = FrozenSpec {
        scenario_id: "TEST-MACOS-PROD-001".to_string(),
        registry_hash: "reg-test".to_string(),
        tier: "seatbelt".to_string(),
        net_mode: net_mode.to_string(),
        backend: "macos seatbelt".to_string(),
        argv: vec!["/bin/sh".to_string()],
        env: BTreeMap::new(),
        cwd: PathBuf::from("/tmp"),
        allow_read: Vec::new(),
        allow_write: Vec::new(),
        deny_read: Vec::new(),
        deny_write: Vec::new(),
        deny_resolved: Vec::new(),
        nonce: "nonce-macos-test".to_string(),
        policy_bytes: b"test-policy".to_vec(),
    };
    let policy = CanonicalPolicy::from_frozen(&spec);
    let identity = ExecutionIdentity::new(
        "TEST-MACOS-PROD-001",
        "nonce-macos-test",
        "reg-test",
        policy.frozen_hash.as_str(),
    );
    (policy, identity)
}

#[cfg(target_os = "macos")]
fn require_tool(name: &str) -> String {
    for candidate in [
        format!("/bin/{name}"),
        format!("/usr/bin/{name}"),
        format!("/usr/local/bin/{name}"),
        format!("/opt/homebrew/bin/{name}"),
    ] {
        if PathBuf::from(&candidate).is_file() {
            return candidate;
        }
    }
    panic!("CI must provide tool `{name}` for macOS prod tests");
}

// ---------------------------------------------------------------------------
// Cross-platform: backend honesty + matrix (real assertions on both sides)
// ---------------------------------------------------------------------------

/// TEST-MACOS-BACKEND-PREPARE-001: `prepare` reports at most `Configured`
/// (plus `HostEvidence`, enforced by construction) — never `Enforced` or
/// `Verified` for confinement. Off macOS the backend honestly reports
/// all-`Unsupported`.
#[test]
fn test_macos_backend_prepare_001() {
    use vetto::verify_ng::sandbox_backend::select_backend;
    let (policy, identity) = canonical_policy("off");
    let mut backend = select_backend(BackendKind::Macos);
    let report = backend.prepare(&policy, &identity);
    assert!(report.binds_identity(&identity));
    #[cfg(target_os = "macos")]
    {
        for cap in [
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
        ] {
            assert_eq!(
                report.state(cap),
                EnforcementState::Configured,
                "{cap:?} must be Configured at prepare, got {:?}",
                report.state(cap)
            );
        }
        assert_eq!(
            report.state(SecurityCapability::SyscallRestriction),
            EnforcementState::Unsupported
        );
        assert_eq!(
            report.state(SecurityCapability::ExecutionRootIsolation),
            EnforcementState::Unsupported
        );
        assert_eq!(
            report.state(SecurityCapability::HostEvidence),
            EnforcementState::Enforced
        );
        assert!(report.preparation_ok);
        assert_eq!(report.enforced(), vec![SecurityCapability::HostEvidence]);
        assert!(!report.allows_pass(&[
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::HostEvidence,
        ]));
    }
    #[cfg(not(target_os = "macos"))]
    {
        for cap in SecurityCapability::all() {
            assert_eq!(
                report.state(cap),
                EnforcementState::Unsupported,
                "{cap:?} must be Unsupported off macOS"
            );
        }
    }
}

/// TEST-MACOS-BACKEND-RELAY-FAIL-001: relay net modes fail preparation
/// closed (`preparation_ok == false`, network `Failed`) — never a silent
/// downgrade to `--net=off`.
#[test]
fn test_macos_backend_relay_fail_001() {
    use vetto::verify_ng::sandbox_backend::select_backend;
    let (policy, identity) = canonical_policy("allowlist:example.com");
    let mut backend = select_backend(BackendKind::Macos);
    let report = backend.prepare(&policy, &identity);
    #[cfg(target_os = "macos")]
    {
        use vetto::verify_ng::sandbox_backend::PreparationFailureKind;
        assert!(
            !report.preparation_ok,
            "relay net must fail preparation on macOS"
        );
        assert_eq!(
            report.state(SecurityCapability::NetworkIsolation),
            EnforcementState::Failed
        );
        assert!(!report.allows_pass(&[SecurityCapability::NetworkIsolation]));
        let failed: Vec<_> = report.failed();
        assert!(
            failed.contains(&(
                SecurityCapability::NetworkIsolation,
                Some(PreparationFailureKind::UnsupportedOnPlatform)
            )),
            "typed failure reason, got: {failed:?}"
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        for cap in SecurityCapability::all() {
            assert_eq!(report.state(cap), EnforcementState::Unsupported);
        }
    }
}

/// TEST-MACOS-TIER-MAPPING-001: the macOS tier mapping is honest — the
/// Seatbelt set is enforced, syscall/exec-root never are, and the
/// no-tier (normal macOS) gate mandates containment, not just observation.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_tier_mapping_001() {
    let mapping = prod_tier_mapping(None, &NetMode::Off);
    assert_eq!(mapping.tier_label, "seatbelt");
    for cap in [
        SecurityCapability::FilesystemIsolation,
        SecurityCapability::NetworkIsolation,
        SecurityCapability::ProcessIsolation,
        SecurityCapability::ProcessTreeContainment,
        SecurityCapability::ResourceLimits,
        SecurityCapability::HostEvidence,
    ] {
        assert!(
            mapping.enforced.contains(&cap),
            "{cap:?} must be in the macOS enforced set: {:?}",
            mapping.enforced
        );
    }
    assert!(!mapping
        .enforced
        .contains(&SecurityCapability::SyscallRestriction));
    assert!(!mapping
        .enforced
        .contains(&SecurityCapability::ExecutionRootIsolation));
    for cap in [
        SecurityCapability::FilesystemIsolation,
        SecurityCapability::NetworkIsolation,
        SecurityCapability::ProcessIsolation,
        SecurityCapability::ProcessTreeContainment,
        SecurityCapability::HostEvidence,
    ] {
        assert!(
            mapping.mandatory.contains(&cap),
            "{cap:?} must gate a macOS PASS"
        );
    }
    // Best-effort rlimits stay out of the PASS gate (partial, documented).
    assert!(!mapping
        .mandatory
        .contains(&SecurityCapability::ResourceLimits));
    let relay = NetMode::Allowlist(vec!["example.com".to_string()]);
    let relay_mapping = prod_tier_mapping(None, &relay);
    assert!(
        !relay_mapping
            .enforced
            .contains(&SecurityCapability::NetworkIsolation),
        "relay net is never enforced on macOS"
    );
    assert!(!relay_mapping.allows_pass_possible);
}

/// TEST-MACOS-MATRIX-001: the platform matrix reflects the real macOS
/// mechanism set (and stays all-unsupported off macOS).
#[test]
fn test_macos_matrix_001() {
    let matrix = PlatformMatrix::current();
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
            assert!(matrix.supports(BackendKind::Macos, cap), "{cap:?}");
        }
        assert!(!matrix.supports(BackendKind::Macos, SecurityCapability::SyscallRestriction));
        assert!(!matrix.supports(
            BackendKind::Macos,
            SecurityCapability::ExecutionRootIsolation
        ));
        assert!(matrix.render().contains("macos filesystem supported"));
    }
    #[cfg(not(target_os = "macos"))]
    {
        for cap in SecurityCapability::all() {
            assert!(
                !matrix.supports(BackendKind::Macos, cap),
                "{cap:?} must be unsupported off macOS"
            );
        }
    }
    // Windows is never our claim to change.
    for cap in SecurityCapability::all() {
        assert!(
            !matrix.supports(BackendKind::Windows, cap),
            "windows {cap:?} must stay unsupported"
        );
    }
}

/// TEST-MACOS-NO-DIRECT-BYPASS-001 (structural, all platforms): every
/// production route goes through the single typestate boundary; the legacy
/// mechanics spawn exists only inside `production.rs`; the verify-ng
/// harness spawn stays plan-controlled (`pre_exec`).
#[test]
fn test_macos_no_direct_bypass_001() {
    for (file, src) in [
        ("src/main.rs", include_str!("../../src/main.rs")),
        (
            "src/multi/runtime.rs",
            include_str!("../../src/multi/runtime.rs"),
        ),
        ("src/mcp/wrap.rs", include_str!("../../src/mcp/wrap.rs")),
    ] {
        for required in [
            "UnpreparedProductionExecution::new",
            ".prepare()",
            ".spawn()",
        ] {
            assert!(
                src.contains(required),
                "{file} must use the shared boundary step `{required}`"
            );
        }
        for banned in ["Backend::spawn", "Command::spawn", "Command::new"] {
            assert!(
                !src.contains(banned),
                "{file} must not contain its own spawn path: found `{banned}`"
            );
        }
    }
    let production = include_str!("../../src/sandbox/production.rs");
    assert!(
        production.contains("self.mechanics.spawn"),
        "the single production spawn boundary must live in production.rs"
    );
    // Documented harness exception: verify-ng `run_one` spawns directly but
    // ONLY under the backend child-side plan installed via `pre_exec`, so
    // `Enforced` is unreachable for a child that bypassed setup.
    let runner = include_str!("../../src/verify_ng/runner.rs");
    assert!(
        runner.contains("std::process::Command::new"),
        "harness spawn site must stay visible to this audit"
    );
    assert!(
        runner.contains("pre_exec"),
        "harness spawn must stay plan-controlled via pre_exec"
    );
    // macOS mechanics installs Seatbelt in the forked child before exec.
    let macos = include_str!("../../src/sandbox/macos/mod.rs");
    assert!(
        macos.contains("apply_seatbelt"),
        "macOS mechanics must apply Seatbelt in the child"
    );
    assert!(
        !macos.contains("Backend::spawn"),
        "macOS mechanics must not re-enter the backend selector"
    );
}

// ---------------------------------------------------------------------------
// macOS-only: real production children through the Seatbelt boundary
// ---------------------------------------------------------------------------

/// TEST-MACOS-PROD-CHILD-001: a real production child runs through the
/// macOS backend with the frozen identity bound to its PID and nonce.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_child_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::{Backend, StdioMode};
    let root = scratch("child");
    let staged = root.join("run.sh");
    std::fs::write(&staged, "exit 0\n").expect("stage child script");
    let backend = Backend::detect(NetMode::Off, false).expect("detect macOS mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        Policy::default(),
        vec!["/bin/sh".to_string(), staged.display().to_string()],
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(15)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare().expect("prepare macOS child");
    assert_eq!(prepared.backend_kind(), BackendKind::Macos);
    // Preparation installs nothing yet: confinement at most Configured.
    let pre = prepared
        .enforcement_report()
        .expect("prepare report")
        .clone();
    assert!(pre.preparation_ok);
    assert!(!pre.is_enforced(SecurityCapability::FilesystemIsolation));
    let nonce = prepared.nonce().to_string();
    let identity = prepared.identity().clone();
    let spawned = prepared.spawn().expect("spawn macOS child");
    let pid = spawned.pid();
    assert!(pid > 0, "real child PID observed");
    // Host-observed: the real child leads its own process group.
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert_eq!(pgid, pid as libc::pid_t, "child leads its own pgroup");
    let result = spawned.wait_collect();
    assert_eq!(result.backend, BackendKind::Macos);
    assert!(result.spawn_via_backend);
    assert_eq!(result.pid, Some(pid));
    assert_eq!(result.nonce, nonce);
    assert!(result.report.binds_identity(&identity));
    assert_eq!(result.exit_code, Some(0));
    // Seatbelt write+net isolation installed; syscall/exec-root honestly out.
    for cap in [
        SecurityCapability::FilesystemIsolation,
        SecurityCapability::NetworkIsolation,
        SecurityCapability::ProcessIsolation,
        SecurityCapability::HostEvidence,
    ] {
        assert!(
            result.report.is_enforced(cap),
            "{cap:?} must be enforced: {}",
            result.render_deterministic()
        );
    }
    assert_eq!(
        result.report.state(SecurityCapability::SyscallRestriction),
        EnforcementState::Unsupported
    );
    assert_eq!(
        result
            .report
            .state(SecurityCapability::ExecutionRootIsolation),
        EnforcementState::Unsupported
    );
    // The macOS PASS gate holds for the containment set, never for fakes.
    assert!(result.allows_pass(&[
        SecurityCapability::FilesystemIsolation,
        SecurityCapability::NetworkIsolation,
        SecurityCapability::ProcessIsolation,
        SecurityCapability::HostEvidence,
    ]));
    assert!(!result.allows_pass(&[SecurityCapability::SyscallRestriction]));
    assert!(!result.allows_pass(&[SecurityCapability::ExecutionRootIsolation]));
    assert!(result.render_deterministic().contains("backend=macos"));
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-FS-DENY-001: writes outside the allow-write roots fail
/// inside the Seatbelt child (direct + symlink escape); the host canary
/// stays intact. Reads are broad by platform necessity and are NOT asserted
/// here (pinned `Unsupported`, see the seatbelt suite).
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_fs_deny_001() {
    let root = scratch("fs-deny");
    let forbid_dir = scratch("fs-forbid");
    let forbid = forbid_dir.join("top-secret");
    std::fs::write(&forbid, "top-secret-macos\n").expect("write canary");
    let before = std::fs::read(&forbid).expect("canary");
    let staged = root.join("run.sh");
    std::fs::write(
        &staged,
        "target=\"$VETTO_PROD_TEST_FORBID\"\n\
         if echo pwned > \"$target\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         ln -sf \"$target\" \"$VETTO_PROD_TEST_ROOT/link\" 2>\"$VETTO_PROD_TEST_ROOT/e\"\n\
         if echo pwned > \"$VETTO_PROD_TEST_ROOT/link\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         exit 0\n",
    )
    .expect("stage fs probe");
    let policy = Policy {
        name: "macos-fs-test".to_string(),
        allow_write: vec![root.clone()],
        deny_resolved: vec![DenyEntry {
            path: forbid.clone(),
            is_dir: false,
        }],
        ..Policy::default()
    };
    let mut extra = HashMap::new();
    extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    extra.insert(
        "VETTO_PROD_TEST_FORBID".to_string(),
        forbid.display().to_string(),
    );
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &policy,
        vec!["/bin/sh".to_string(), staged.display().to_string()],
        root.clone(),
        extra,
        NetMode::Off,
        None,
        Duration::from_secs(15),
        &mut log,
    )
    .expect("macOS fs-deny run");
    assert_eq!(log.len(), 1);
    assert_eq!(out.backend, BackendKind::Macos);
    assert!(
        out.state(SecurityCapability::FilesystemIsolation)
            .is_enforced(),
        "write isolation must be enforced: {}",
        out.render_deterministic()
    );
    assert_eq!(
        out.exit_code,
        Some(0),
        "write escapes must fail inside the child, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        std::fs::read(&forbid).expect("canary"),
        before,
        "host canary intact"
    );
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&forbid_dir);
}

/// TEST-MACOS-PROD-NET-DENY-001: TCP connect fails under `--net=off`.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_net_deny_001() {
    let python = require_tool("python3");
    let root = scratch("net-deny");
    let staged = root.join("connect.py");
    std::fs::write(
        &staged,
        "import socket, os\n\
         port = int(os.environ[\"VETTO_PROD_TEST_PORT\"])\n\
         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         s.settimeout(3)\n\
         try:\n\
         \ts.connect((\"127.0.0.1\", port))\n\
         except OSError:\n\
         \tos._exit(0)\n\
         os._exit(10)\n",
    )
    .expect("stage net probe");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut extra = HashMap::new();
    extra.insert("VETTO_PROD_TEST_PORT".to_string(), port.to_string());
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &Policy::default(),
        vec![python, staged.display().to_string()],
        root.clone(),
        extra,
        NetMode::Off,
        None,
        Duration::from_secs(15),
        &mut log,
    )
    .expect("macOS net-deny run");
    assert_eq!(log.len(), 1);
    assert!(
        out.state(SecurityCapability::NetworkIsolation)
            .is_enforced(),
        "network isolation must be enforced: {}",
        out.render_deterministic()
    );
    assert_eq!(
        out.exit_code,
        Some(0),
        "TCP connect must fail inside the child, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-PGROUP-001: the live child is host-observed in its own
/// process group; process isolation promotes to `Verified`.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_pgroup_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::{Backend, StdioMode};
    let root = scratch("pgroup");
    let backend = Backend::detect(NetMode::Off, false).expect("detect macOS mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        Policy::default(),
        vec!["/bin/sleep".to_string(), "30".to_string()],
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(8)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare().expect("prepare pgroup child");
    let spawned = prepared.spawn().expect("spawn pgroup child");
    let pid = spawned.pid();
    // SAFETY: scalar-only getpgid on our own child.
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert_eq!(pgid, pid as libc::pid_t, "live child leads its own pgroup");
    let result = spawned.wait_collect();
    assert!(result.timed_out, "deadline must kill the sleeper");
    assert_eq!(
        result.state(SecurityCapability::ProcessIsolation),
        EnforcementState::Verified,
        "host-observed pgroup promotes process isolation: {}",
        result.render_deterministic()
    );
    assert_eq!(
        result.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "clean post-deadline sweep: {}",
        result.render_deterministic()
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-TIMEOUT-001: the deadline kills through the boundary and
/// the tree sweep reports clean (no group survivors).
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_timeout_001() {
    let root = scratch("timeout");
    let start = std::time::Instant::now();
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &Policy::default(),
        vec!["/bin/sleep".to_string(), "60".to_string()],
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(2),
        &mut log,
    )
    .expect("macOS timeout run");
    assert_eq!(log.len(), 1);
    assert!(out.timed_out, "deadline must kill");
    assert!(start.elapsed() < Duration::from_secs(20));
    assert_eq!(
        out.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "clean post-deadline sweep: {}",
        out.render_deterministic()
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-PREPARE-FAIL-NO-SPAWN-001: a relay-mode preparation
/// through the REAL production object yields `Err` with zero spawn — spawn
/// counters unchanged, no child, no fallback.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_prepare_fail_no_spawn_001() {
    use vetto::sandbox::production::{
        UnpreparedProductionExecution, PROD_BACKEND_ENTERED, PROD_SPAWN_COUNT,
    };
    use vetto::sandbox::{Backend, StdioMode};
    let entered_before = PROD_BACKEND_ENTERED.load(std::sync::atomic::Ordering::SeqCst);
    let spawned_before = PROD_SPAWN_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let root = scratch("prepare-fail");
    let net = NetMode::Allowlist(vec!["example.com".to_string()]);
    let backend = Backend::detect(net.clone(), false).expect("detect macOS mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        Policy::default(),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ],
        root.clone(),
        HashMap::new(),
        net,
        Some(Duration::from_secs(5)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    let err = match unprepared.prepare() {
        Ok(_) => panic!("relay on macOS must fail closed with no spawn"),
        Err(e) => e,
    };
    assert!(
        err.to_string().contains("fail-closed") || err.to_string().contains("refusing"),
        "fail-closed error, got: {err:#}"
    );
    assert_eq!(
        PROD_BACKEND_ENTERED.load(std::sync::atomic::Ordering::SeqCst),
        entered_before,
        "no backend entry on preparation failure"
    );
    assert_eq!(
        PROD_SPAWN_COUNT.load(std::sync::atomic::Ordering::SeqCst),
        spawned_before,
        "spawn count unchanged: zero spawn"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-DRIFT-001: frozen inputs are immutable — caller-side
/// mutations after construction never reach the child.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_drift_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::{Backend, StdioMode};
    let root = scratch("drift");
    let staged = root.join("run.sh");
    std::fs::write(
        &staged,
        "echo \"marker=${VETTO_PROD_TEST_MARKER:-absent}\" >\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         echo \"cwd=$(pwd)\" >>\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         exit 0\n",
    )
    .expect("stage drift script");
    let mut argv = vec!["/bin/sh".to_string(), staged.display().to_string()];
    let mut extra = HashMap::new();
    extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    extra.insert("VETTO_PROD_TEST_MARKER".to_string(), "frozen".to_string());
    let policy = Policy::default();
    let backend = Backend::detect(NetMode::Off, false).expect("detect macOS mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        policy.clone(),
        argv.clone(),
        root.clone(),
        extra.clone(),
        NetMode::Off,
        Some(Duration::from_secs(15)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    argv.push("MUTATED".to_string());
    extra.insert("VETTO_PROD_TEST_MARKER".to_string(), "mutated".to_string());
    let prepared = unprepared.prepare().expect("prepare drift run");
    let frozen = prepared.frozen_inputs();
    assert!(
        !frozen.argv.iter().any(|a| a == "MUTATED"),
        "frozen argv has no post-freeze mutation: {frozen:?}"
    );
    assert_eq!(
        frozen.env.get("VETTO_PROD_TEST_MARKER").map(String::as_str),
        Some("frozen")
    );
    assert_eq!(frozen.cwd, root);
    assert_eq!(frozen.net_label, NetMode::Off.label());
    assert_eq!(prepared.frozen_policy().name, policy.name);
    let result = prepared.spawn().expect("spawn drift run").wait_collect();
    assert_eq!(result.exit_code, Some(0));
    assert!(
        result.report.binds_identity(result.identity()),
        "report bound to the frozen identity"
    );
    let obs = std::fs::read_to_string(root.join("obs")).expect("drift obs");
    assert!(
        obs.contains("marker=frozen"),
        "child saw only frozen env: {obs}"
    );
    let _ = std::fs::remove_dir_all(&root);
}

/// TEST-MACOS-PROD-IDENTITY-001: scenario/nonce/registry binding on macOS.
#[cfg(target_os = "macos")]
#[test]
fn test_macos_prod_identity_001() {
    let root = scratch("identity");
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &Policy::default(),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ],
        root.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(15),
        &mut log,
    )
    .expect("macOS identity run");
    assert_eq!(log.len(), 1);
    assert_eq!(out.nonce, log[0].run_id);
    assert_eq!(out.pid, Some(log[0].pid));
    assert!(out
        .report
        .binds_identity(&vetto::verify_ng::evidence::ExecutionIdentity::new(
            PROD_SCENARIO_ID,
            out.nonce.as_str(),
            PROD_REGISTRY,
            out.report.frozen_hash.as_str(),
        )));
    assert!(!out.nonce.is_empty());
    assert!(out.exec_root.is_absolute());
    let _ = std::fs::remove_dir_all(&root);
}
