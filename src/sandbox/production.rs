//! Stage 3C: one authoritative production execution path over Stage 3B.
//!
//! ```text
//! real vetto command -> policy -> FrozenSpec -> CanonicalPolicy
//!   -> SandboxBackend::prepare (LinuxBackend owns preparation)
//!   -> backend-controlled spawn (pre_exec plan, single site)
//!   -> kill/collect via proven killer path
//!   -> host verification (/proc) + nonce tree sweep (3B reuse)
//!   -> teardown -> typed ProductionResult
//! ```
//!
//! No duplication: child enforcement, host verification and tree sweep call
//! `verify_ng::linux_enforce` directly. No second production-only sandbox.
//! Tier mapping is honest: FS-only never silently becomes network-off,
//! relay modes keep the existing relay architecture and report
//! `network=unsupported` through the 3B boundary (no parity claimed).
//! `oracle::judge` stays pure: nothing here infers security from stdout.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::NetMode;
use crate::policy::{Policy, Tier};
use crate::verify_ng::engine;
use crate::verify_ng::evidence::ExecutionIdentity;
use crate::verify_ng::frozen::{self, FrozenSpec};
use crate::verify_ng::killer::{self, KillOutcome, WaitKill};
use crate::verify_ng::sandbox_backend::{
    BackendKind, CanonicalPolicy, EnforcementReport, EnforcementState, PrepareContext,
    SandboxBackend, SecurityCapability,
};

/// Production scenario id: real runs are not registry scenarios.
pub const PROD_SCENARIO_ID: &str = "PROD-LINUX";
/// Nonce env label: run label for the nonce-targeted sweep, not a secret.
pub const PROD_NONCE_ENV: &str = "VETTO_PROD_NONCE";
/// Registry binding for production runs (not a scenario-registry hash).
pub const PROD_REGISTRY: &str = "production";
/// Stdio drain budget after termination.
pub const PROD_DRAIN_BUDGET: Duration = Duration::from_secs(5);
/// Per-stream capture cap.
pub const PROD_MAX_STDIO: usize = 1 << 20;
/// Exit poll interval for the deadline loop.
pub const PROD_EXIT_POLL: Duration = Duration::from_millis(10);

/// Host-observed count of authoritative backend entries in this process.
pub static PROD_BACKEND_ENTERED: AtomicU64 = AtomicU64::new(0);
/// Host-observed count of authoritative production spawns in this process.
pub static PROD_SPAWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// One authoritative spawn event. `run_id` equals the run nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProdSpawnEvent {
    pub run_id: String,
    pub pid: u32,
}

/// Caller-owned spawn ledger: exactly one entry per execute call.
pub type ProdSpawnLog = Vec<ProdSpawnEvent>;

/// Explicit per-tier capability mapping. `enforced` lists caps the 3B
/// boundary can install on this kernel; `mandatory` lists caps required
/// for PASS on this tier+net; `allows_pass_possible` is their conjunction.
#[derive(Debug, Clone)]
pub struct TierMapping {
    pub tier_label: String,
    pub net_label: String,
    pub mandatory: Vec<SecurityCapability>,
    pub enforced: Vec<SecurityCapability>,
    pub unsupported: Vec<SecurityCapability>,
    pub allows_pass_possible: bool,
    pub notes: String,
}

/// Honest tier mapping. Probes the kernel on Linux; off Linux everything
/// containment-related is unsupported. Never forces the strongest config.
pub fn prod_tier_mapping(tier: Option<Tier>, net: &NetMode) -> TierMapping {
    #[cfg(target_os = "linux")]
    let (landlock_ok, seccomp_ok) = (
        crate::sandbox::linux::landlock::abi_version().is_some(),
        crate::sandbox::linux::seccomp_netblock::probe_available(),
    );
    #[cfg(not(target_os = "linux"))]
    let (landlock_ok, seccomp_ok) = (false, false);
    let net_off = matches!(net, NetMode::Off);

    let mut enforced = Vec::new();
    if landlock_ok {
        enforced.push(SecurityCapability::FilesystemIsolation);
        enforced.push(SecurityCapability::ExecutionRootIsolation);
    }
    if net_off && seccomp_ok {
        enforced.push(SecurityCapability::NetworkIsolation);
    }
    if seccomp_ok {
        enforced.push(SecurityCapability::SyscallRestriction);
    }
    #[cfg(target_os = "linux")]
    {
        enforced.push(SecurityCapability::ProcessIsolation);
        enforced.push(SecurityCapability::ProcessTreeContainment);
        enforced.push(SecurityCapability::ResourceLimits);
        enforced.push(SecurityCapability::HostEvidence);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Placeholders enforce nothing, including host evidence via 3B.
    }
    let unsupported: Vec<SecurityCapability> = SecurityCapability::all()
        .into_iter()
        .filter(|c| !enforced.contains(c))
        .collect();

    let tier_label = tier.map(|t| t.label().to_string()).unwrap_or_else(|| {
        #[cfg(target_os = "linux")]
        return "seccomp".to_string();
        #[cfg(not(target_os = "linux"))]
        return "unsupported".to_string();
    });
    let mandatory: Vec<SecurityCapability> = match tier {
        Some(Tier::Full) if net_off => SecurityCapability::all().to_vec(),
        Some(Tier::Full) => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::HostEvidence,
        ],
        Some(Tier::FsOnly) if net_off => SecurityCapability::all().to_vec(),
        Some(Tier::FsOnly) => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::HostEvidence,
        ],
        Some(Tier::Seccomp) if net_off => vec![
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::HostEvidence,
        ],
        Some(Tier::Seccomp) => vec![
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::HostEvidence,
        ],
        None => vec![SecurityCapability::HostEvidence],
    };
    let allows_pass_possible = mandatory.iter().all(|c| enforced.contains(c));
    let notes = "fs-only never silently becomes network=off; relay modes keep the \
        existing relay architecture and report network=unsupported through the 3B \
        boundary (UnixOnly is not an allowlist relay, no 3C parity claimed there); \
        seccomp tier has no filesystem/exec-root isolation."
        .to_string();
    TierMapping {
        tier_label,
        net_label: net.label(),
        mandatory,
        enforced,
        unsupported,
        allows_pass_possible,
        notes,
    }
}

/// Production environment: explicit pass-through only (policy allows),
/// PATH sanitized, NUL/`=` rejected, proxy secrets stripped, and env_extra
/// re-stripped so the backend can never reintroduce a removed secret.
pub fn build_production_env(
    policy: &Policy,
    env_extra: &HashMap<String, String>,
) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for (k, v) in std::env::vars() {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue;
        }
        if !policy.environment.allows(std::ffi::OsStr::new(&k)) {
            continue;
        }
        if k.eq_ignore_ascii_case("PATH") {
            out.insert(k, crate::sandbox::envfilter::sanitize_path(&v));
        } else {
            out.insert(k, v);
        }
    }
    for (k, v) in env_extra {
        if k.is_empty() || k.contains('=') || k.contains('\0') || v.contains('\0') {
            continue;
        }
        // env_extra is internal (VETTO_* + nonce): never let it smuggle a
        // secret the policy layer removed.
        if crate::sandbox::envfilter::is_hard_denied(k)
            && !policy.environment.allows(std::ffi::OsStr::new(k))
        {
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    for proxy in &policy.secret_proxies {
        out.remove(proxy);
    }
    out
}

/// Freeze production identity: policy cwd == FrozenSpec cwd == backend
/// exec_root == actual child cwd by construction (all from `cwd`).
#[allow(clippy::too_many_arguments)]
pub fn freeze_production(
    policy: &Policy,
    tier_label: &str,
    net: &NetMode,
    backend_describe: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: &std::path::Path,
    nonce: &str,
) -> (FrozenSpec, CanonicalPolicy, ExecutionIdentity) {
    let spec = frozen::freeze_spec(
        PROD_SCENARIO_ID,
        PROD_REGISTRY,
        policy,
        tier_label,
        net,
        backend_describe,
        argv,
        env,
        cwd,
        nonce,
    );
    let canonical = CanonicalPolicy::from_frozen(&spec);
    let identity =
        ExecutionIdentity::new(PROD_SCENARIO_ID, nonce, PROD_REGISTRY, spec.hash().as_str());
    (spec, canonical, identity)
}

/// Authoritative wrapper for the existing tier-aware `Backend::spawn`
/// (Full namespaces/relay/PTY paths). Every production `Backend::spawn`
/// call must go through here; the counters prove it in tests.
pub fn spawn_authoritative(
    backend: crate::sandbox::Backend,
    policy: &Policy,
    opts: crate::sandbox::SpawnOptions,
) -> anyhow::Result<crate::sandbox::Spawned> {
    PROD_BACKEND_ENTERED.fetch_add(1, Ordering::SeqCst);
    let spawned = backend.spawn(policy, opts)?;
    PROD_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    Ok(spawned)
}

/// Authoritative wait: proven killer deadline loop (never a bare blocking
/// wait), then the nonce-targeted 3B tree sweep. No arbitrary killing,
/// no PID-only global cleanup.
pub fn wait_authoritative(
    handle: &mut crate::sandbox::SandboxHandle,
    timeout: Option<Duration>,
    nonce: &str,
    backend: &mut dyn SandboxBackend,
) -> (i32, bool) {
    let deadline = Instant::now() + timeout.unwrap_or(Duration::from_secs(3600));
    let (outcome, code) = killer::kill_on_deadline_with(handle, deadline, PROD_EXIT_POLL);
    let timed_out = outcome == KillOutcome::KilledOnDeadline;
    #[cfg(target_os = "linux")]
    {
        if let Some(sweep) =
            crate::verify_ng::linux_enforce::sweep_tree_by_nonce(nonce, handle.root_pid)
        {
            backend.note_tree_clean(sweep.clean);
            backend.note_diagnostic(format!(
                "tree-sweep clean={} killed={} residual={:?} subreaper={} blind={}",
                sweep.clean, sweep.killed, sweep.residual, sweep.subreaper, sweep.blind
            ));
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (nonce, backend);
    }
    (code, timed_out)
}

/// Typed production execution result. All security state is typed
/// (`EnforcementReport`); stdout/stderr are never security proof.
#[derive(Debug)]
pub struct ProductionResult {
    pub backend: BackendKind,
    pub report: EnforcementReport,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub pid: Option<u32>,
    pub nonce: String,
    pub scenario_id: String,
    pub exec_root: PathBuf,
    pub cwd: PathBuf,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub spawn_via_backend: bool,
    pub diagnostic: Option<String>,
}

impl ProductionResult {
    pub fn state(&self, cap: SecurityCapability) -> EnforcementState {
        self.report.state(cap)
    }
    pub fn filesystem(&self) -> EnforcementState {
        self.state(SecurityCapability::FilesystemIsolation)
    }
    pub fn network(&self) -> EnforcementState {
        self.state(SecurityCapability::NetworkIsolation)
    }
    pub fn process(&self) -> EnforcementState {
        self.state(SecurityCapability::ProcessIsolation)
    }
    pub fn tree(&self) -> EnforcementState {
        self.state(SecurityCapability::ProcessTreeContainment)
    }
    pub fn resources(&self) -> EnforcementState {
        self.state(SecurityCapability::ResourceLimits)
    }
    pub fn syscalls(&self) -> EnforcementState {
        self.state(SecurityCapability::SyscallRestriction)
    }
    pub fn exec_root_state(&self) -> EnforcementState {
        self.state(SecurityCapability::ExecutionRootIsolation)
    }
    pub fn host_evidence(&self) -> EnforcementState {
        self.state(SecurityCapability::HostEvidence)
    }
    /// Fail-closed gate for production: preparation ok + mandatory enforced.
    /// `Configured` never counts (only Enforced/Verified via is_enforced).
    pub fn allows_pass(&self, required: &[SecurityCapability]) -> bool {
        self.report.allows_pass(required)
    }
    /// Deterministic typed rendering. No vague marketing words.
    pub fn render_deterministic(&self) -> String {
        let mut parts = vec![format!("backend={}", self.backend.label())];
        for cap in SecurityCapability::all() {
            parts.push(format!("{}={}", cap.label(), self.state(cap).label()));
        }
        parts.push(format!("preparation_ok={}", self.report.preparation_ok));
        parts.join("|")
    }
}

struct ProdChild {
    child: std::process::Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    pgid: Option<i32>,
}

impl WaitKill for ProdChild {
    fn try_wait(&mut self) -> Option<i32> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(decode_exit(status)),
            Ok(None) => None,
            Err(_) => None,
        }
    }
    fn terminate(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid {
            // SAFETY: SIGKILL to the sandbox process group we spawned.
            unsafe {
                libc::kill(-pgid, libc::SIGKILL);
            }
        }
        let _ = self.child.kill();
    }
}

#[cfg(unix)]
fn decode_exit(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| status.signal().map(|s| -s).unwrap_or(-1))
}

#[cfg(not(unix))]
fn decode_exit(status: std::process::ExitStatus) -> i32 {
    status.code().unwrap_or(-1)
}

fn fail_result(
    backend: &dyn SandboxBackend,
    report: EnforcementReport,
    nonce: String,
    cwd: PathBuf,
) -> ProductionResult {
    ProductionResult {
        backend: backend.kind(),
        report,
        exit_code: None,
        timed_out: false,
        pid: None,
        nonce,
        scenario_id: PROD_SCENARIO_ID.to_string(),
        exec_root: cwd.clone(),
        cwd,
        stdout: Vec::new(),
        stderr: Vec::new(),
        spawn_via_backend: false,
        diagnostic: backend.diagnostic(),
    }
}

/// Headless production execution through the injected backend boundary.
/// Real spawns `/bin/true`-class payloads via `Command` + the backend
/// `pre_exec` plan; a failing preparation never spawns (`spawn_count==0`).
/// A fake backend can never claim real Linux security: its report stays
/// honestly Unsupported/Failed and `allows_pass` is false.
#[allow(clippy::too_many_arguments)]
pub fn execute_with_backend(
    policy: &Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env_extra: HashMap<String, String>,
    net: NetMode,
    tier: Option<Tier>,
    timeout: Duration,
    backend: &mut dyn SandboxBackend,
    spawn_log: &mut ProdSpawnLog,
) -> anyhow::Result<ProductionResult> {
    if argv.is_empty() {
        anyhow::bail!("no production command provided");
    }
    // Preserve the existing fail-closed relay rule: FS-only/seccomp tiers
    // cannot serve relay modes.
    #[cfg(target_os = "linux")]
    if net.uses_relay() && matches!(tier, Some(Tier::FsOnly) | Some(Tier::Seccomp)) {
        anyhow::bail!("network relay modes require Tier FULL; refusing to run (fail-closed)");
    }
    let tier_label = tier
        .map(|t| t.label().to_string())
        .unwrap_or_else(|| prod_tier_mapping(tier, &net).tier_label.clone());

    let nonce = engine::new_nonce();
    let mut env_extra = env_extra;
    env_extra.insert(PROD_NONCE_ENV.to_string(), nonce.clone());
    let env = build_production_env(policy, &env_extra);

    let (_spec, canonical, identity) = freeze_production(
        policy,
        &tier_label,
        &net,
        backend.name(),
        &argv,
        &env,
        &cwd,
        &nonce,
    );
    let ctx = PrepareContext::default();
    backend.prepare_with_context(&canonical, &identity, &ctx);
    let prepared_ok = backend
        .enforcement()
        .map(|r| r.preparation_ok && r.binds_identity(&identity))
        .unwrap_or(false);
    let kind = backend.kind();
    if !prepared_ok {
        let report = backend.enforcement().cloned().unwrap_or_else(|| {
            EnforcementReport::build(
                kind,
                &canonical,
                &identity,
                &BTreeMap::new(),
                &BTreeMap::new(),
                false,
            )
        });
        return Ok(fail_result(backend, report, nonce, cwd));
    }
    let plan = backend.pre_exec_plan();
    #[cfg(not(unix))]
    if plan.is_some() {
        backend
            .note_failed(crate::verify_ng::sandbox_backend::PreparationFailureKind::SpawnRefused);
        let report = backend.enforcement().cloned().unwrap();
        return Ok(fail_result(backend, report, nonce, cwd));
    }

    let mut cmd = std::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .current_dir(&cwd)
        .env_clear()
        .envs(&env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        if let Some(plan) = plan.clone() {
            // SAFETY: child-side syscalls only; errors abort spawn fail-closed.
            unsafe {
                cmd.pre_exec(move || crate::verify_ng::linux_enforce::apply_child_plan(&plan));
            }
        }
    }
    let mut child = {
        let _serial = engine::spawn_serial().lock().unwrap();
        match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                backend.note_failed(
                    crate::verify_ng::sandbox_backend::PreparationFailureKind::SpawnRefused,
                );
                let report = backend.enforcement().cloned().unwrap();
                let mut out = fail_result(backend, report, nonce, cwd);
                out.stderr = format!("production spawn failed (no retry): {e}").into_bytes();
                return Ok(out);
            }
        }
    };
    let pid = child.id();
    spawn_log.push(ProdSpawnEvent {
        run_id: nonce.clone(),
        pid,
    });
    PROD_BACKEND_ENTERED.fetch_add(1, Ordering::SeqCst);
    PROD_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    backend.note_spawned(pid);
    let verification = crate::verify_ng::linux_enforce::verify_child_host(pid);
    backend.note_host_verified(&verification);

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let confined = backend.pre_exec_plan().is_some();
    let mut prod_child = ProdChild {
        child,
        stdout,
        stderr,
        pgid: if confined { Some(pid as i32) } else { None },
    };
    let deadline = Instant::now() + timeout;
    let (kill, code) = killer::kill_on_deadline_with(&mut prod_child, deadline, PROD_EXIT_POLL);
    let timed_out = kill == KillOutcome::KilledOnDeadline;
    if prod_child.pgid.is_some() {
        prod_child.terminate();
    }
    let drain_deadline = Instant::now() + PROD_DRAIN_BUDGET;
    let collected = match (prod_child.stdout.take(), prod_child.stderr.take()) {
        (Some(o), Some(e)) => {
            crate::verify_ng::collector::collect_child_stdio(o, e, drain_deadline, PROD_MAX_STDIO)
        }
        _ => crate::verify_ng::collector::CollectedStdio {
            stdout: Vec::new(),
            stderr: Vec::new(),
            eof: false,
            truncated: false,
        },
    };
    let exit_code = prod_child.try_wait().or(Some(code));
    #[cfg(target_os = "linux")]
    if prod_child.pgid.is_some() {
        if let Some(sweep) =
            crate::verify_ng::linux_enforce::sweep_tree_by_nonce(nonce.as_str(), pid)
        {
            backend.note_tree_clean(sweep.clean);
            backend.note_diagnostic(format!(
                "tree-sweep clean={} killed={} residual={:?} subreaper={} blind={}",
                sweep.clean, sweep.killed, sweep.residual, sweep.subreaper, sweep.blind
            ));
        }
    }
    let report = backend.enforcement().cloned().unwrap();
    let diagnostic = backend.diagnostic();
    backend.teardown();
    Ok(ProductionResult {
        backend: kind,
        report,
        exit_code,
        timed_out,
        pid: Some(pid),
        nonce,
        scenario_id: PROD_SCENARIO_ID.to_string(),
        exec_root: cwd.clone(),
        cwd,
        stdout: collected.stdout,
        stderr: collected.stderr,
        spawn_via_backend: true,
        diagnostic,
    })
}

/// Real headless production execution: fresh `LinuxBackend` per run, no
/// shared backend state, one spawn per call, no retry FAIL->PASS.
#[allow(clippy::too_many_arguments)]
pub fn execute_simple(
    policy: &Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env_extra: HashMap<String, String>,
    net: NetMode,
    tier: Option<Tier>,
    timeout: Duration,
    spawn_log: &mut ProdSpawnLog,
) -> anyhow::Result<ProductionResult> {
    #[cfg(target_os = "linux")]
    {
        let mut backend = crate::verify_ng::sandbox_backend::LinuxBackend::new();
        execute_with_backend(
            policy,
            argv,
            cwd,
            env_extra,
            net,
            tier,
            timeout,
            &mut backend,
            spawn_log,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut backend: Box<dyn SandboxBackend> =
            crate::verify_ng::sandbox_backend::select_backend(BackendKind::current_platform());
        execute_with_backend(
            policy,
            argv,
            cwd,
            env_extra,
            net,
            tier,
            timeout,
            &mut *backend,
            spawn_log,
        )
    }
}

#[cfg(test)]
mod production_unit_tests {
    use super::*;

    fn test_policy() -> Policy {
        Policy::default()
    }

    /// TEST-PROD-TIER-MAPPING-001: tiers map honestly, no forced strongest.
    #[test]
    fn test_prod_tier_mapping_001_honest() {
        let off = NetMode::Off;
        let relay = NetMode::Allowlist(vec!["example.com".to_string()]);
        let full_off = prod_tier_mapping(Some(Tier::Full), &off);
        assert!(full_off
            .mandatory
            .contains(&SecurityCapability::FilesystemIsolation));
        let full_relay = prod_tier_mapping(Some(Tier::Full), &relay);
        assert!(!full_relay
            .enforced
            .contains(&SecurityCapability::NetworkIsolation));
        assert!(
            !full_relay
                .mandatory
                .contains(&SecurityCapability::NetworkIsolation),
            "relay net is not a 3B UnixOnly claim"
        );
        let sec = prod_tier_mapping(Some(Tier::Seccomp), &off);
        assert!(!sec
            .mandatory
            .contains(&SecurityCapability::FilesystemIsolation));
        assert!(!sec
            .mandatory
            .contains(&SecurityCapability::ExecutionRootIsolation));
        let fs_off = prod_tier_mapping(Some(Tier::FsOnly), &off);
        assert_ne!(fs_off.net_label, "allowlist:example.com");
        assert!(fs_off.notes.contains("relay"));
    }

    /// TEST-PROD-POLICY-FROZEN-001: policy mutation flips the frozen hash.
    #[test]
    fn test_prod_policy_frozen_001_flips_hash() {
        let pol = test_policy();
        let env = BTreeMap::new();
        let cwd = PathBuf::from("/tmp");
        let argv = vec!["sh".to_string()];
        let (a, _, id_a) = freeze_production(
            &pol,
            "fs-only",
            &NetMode::Off,
            "prod",
            &argv,
            &env,
            &cwd,
            "n1",
        );
        let mut pol2 = test_policy();
        pol2.deny_network = !pol.deny_network;
        let (b, _, _) = freeze_production(
            &pol2,
            "fs-only",
            &NetMode::Off,
            "prod",
            &argv,
            &env,
            &cwd,
            "n1",
        );
        assert_ne!(a.hash(), b.hash());
        let (_, can, _) = freeze_production(
            &pol,
            "fs-only",
            &NetMode::Off,
            "prod",
            &argv,
            &env,
            &cwd,
            "n1",
        );
        assert_eq!(can.cwd, cwd, "exec-root binds cwd");
        assert_eq!(id_a.scenario_id, PROD_SCENARIO_ID);
        assert_eq!(id_a.registry_hash, PROD_REGISTRY);
    }

    /// TEST-PROD-IDENTITY-BINDING-001: cwd == frozen == exec-root.
    #[test]
    fn test_prod_identity_binding_001_cwd_equals_exec_root() {
        let pol = test_policy();
        let cwd = PathBuf::from("/tmp/vetto-prod-ident");
        let env = BTreeMap::new();
        let argv = vec!["sh".to_string()];
        let (spec, can, id) = freeze_production(
            &pol,
            "full",
            &NetMode::Off,
            "prod",
            &argv,
            &env,
            &cwd,
            "nonce-x",
        );
        assert_eq!(spec.cwd, cwd);
        assert_eq!(can.cwd, cwd);
        assert_eq!(can.cwd, spec.cwd);
        assert_eq!(id.frozen_hash, spec.hash());
    }

    /// TEST-PROD-BACKEND-FAIL-CLOSED-001: preparation failure spawns nothing.
    #[test]
    fn test_prod_backend_fail_closed_001_no_spawn() {
        struct FailBackend {
            report: Option<EnforcementReport>,
        }
        impl SandboxBackend for FailBackend {
            fn kind(&self) -> BackendKind {
                BackendKind::Linux
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
                let report = EnforcementReport::build(
                    BackendKind::Linux,
                    policy,
                    identity,
                    &states,
                    &BTreeMap::new(),
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
        let mut backend = FailBackend { report: None };
        let mut log = ProdSpawnLog::new();
        let out = execute_with_backend(
            &test_policy(),
            vec!["sh".to_string()],
            PathBuf::from("/tmp"),
            HashMap::new(),
            NetMode::Off,
            Some(Tier::FsOnly),
            Duration::from_secs(5),
            &mut backend,
            &mut log,
        )
        .expect("fail-closed returns a result, not an error");
        assert!(log.is_empty(), "spawn_count == 0 on preparation failure");
        assert!(!out.spawn_via_backend);
        assert!(out.pid.is_none());
        assert!(!out.allows_pass(&[SecurityCapability::HostEvidence]));
    }

    /// TEST-PROD-BACKEND-CALLED-001: production runner calls the backend.
    #[test]
    fn test_prod_backend_called_001_runner_calls_backend() {
        struct CountBackend {
            prepares: usize,
            spawned: usize,
            report: Option<EnforcementReport>,
        }
        impl SandboxBackend for CountBackend {
            fn kind(&self) -> BackendKind {
                BackendKind::Linux
            }
            fn name(&self) -> &'static str {
                "count test double"
            }
            fn supports(&self, _c: SecurityCapability) -> bool {
                false
            }
            fn prepare(
                &mut self,
                policy: &CanonicalPolicy,
                identity: &ExecutionIdentity,
            ) -> EnforcementReport {
                self.prepares += 1;
                let mut states = BTreeMap::new();
                for cap in SecurityCapability::all() {
                    states.insert(cap, EnforcementState::Unsupported);
                }
                states.insert(SecurityCapability::HostEvidence, EnforcementState::Enforced);
                let report = EnforcementReport::build(
                    BackendKind::Linux,
                    policy,
                    identity,
                    &states,
                    &BTreeMap::new(),
                    true,
                );
                self.report = Some(report.clone());
                report
            }
            fn note_spawned(&mut self, _pid: u32) {
                self.spawned += 1;
            }
            fn enforcement(&self) -> Option<&EnforcementReport> {
                self.report.as_ref()
            }
            fn teardown(&mut self) {
                self.report = None;
            }
        }
        let mut backend = CountBackend {
            prepares: 0,
            spawned: 0,
            report: None,
        };
        let tmp = std::env::temp_dir().join(format!("vetto-prod-called-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        // No /bin/true on macOS/Windows: use the platform shell.
        #[cfg(unix)]
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ];
        #[cfg(windows)]
        let argv = vec!["cmd".to_string(), "/C".to_string(), "exit 0".to_string()];
        let mut log = ProdSpawnLog::new();
        let out = execute_with_backend(
            &test_policy(),
            argv,
            tmp.clone(),
            HashMap::new(),
            NetMode::Off,
            None,
            Duration::from_secs(10),
            &mut backend,
            &mut log,
        )
        .expect("count backend run");
        assert_eq!(backend.prepares, 1, "backend entered exactly once");
        assert_eq!(log.len(), 1, "one spawn == one scenario");
        assert!(out.spawn_via_backend);
        assert!(!out.allows_pass(&[SecurityCapability::FilesystemIsolation]));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
