//! Stage 3C correction: one authoritative production execution boundary.
//!
//! ```text
//! main / multi / mcp
//!         ↓
//! UnpreparedProductionExecution (owned frozen inputs, NO spawn method)
//!         ↓ prepare()
//! PreparedProductionExecution (backend prepared + plan + frozen bundle)
//!         ↓ spawn() — exactly one real spawn, consumes self
//! SpawnedProductionExecution (handle + fds + backend + identity + nonce)
//!         ↓ wait_collect() / finish()
//! host verification + killer + drain + nonce sweep + typed result
//! ```
//!
//! Invariants (compile-time where possible):
//! - `UnpreparedProductionExecution` has NO spawn method: preparation and
//!   spawn cannot be separated, and one backend cannot be prepared while
//!   another is spawned — the SAME `PreparedProductionExecution` object owns
//!   the capability backend, the enforcement plan, and the frozen bundle the
//!   child installs.
//! - All spawn inputs are OWNED at construction (argv/cwd/env/policy/net/
//!   stdio): nothing can drift between freeze and spawn. `Prepared` exposes
//!   no setters and no re-freeze.
//! - The child installs enforcement through the pre-existing shared
//!   primitives only (`sandbox::linux::{landlock,seccomp_netblock,limits}`,
//!   `verify_ng::linux_enforce` for host verify/sweep). No second
//!   Landlock/seccomp implementation exists here.
//! - Tier mapping is honest: FS-only never silently becomes network-off,
//!   relay modes keep the existing relay architecture and report
//!   `network=unsupported` through the 3B boundary (no parity claimed).
//! - `oracle::judge` stays pure: nothing here infers security from stdout.

use std::collections::{BTreeMap, HashMap};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crate::config::NetMode;
use crate::policy::{Policy, Tier};
use crate::sandbox::{Backend, SandboxHandle, SpawnOptions, StdioMode};
use crate::verify_ng::engine;
use crate::verify_ng::evidence::ExecutionIdentity;
use crate::verify_ng::frozen::{self, FrozenSpec};
use crate::verify_ng::killer::{self, KillOutcome};
use crate::verify_ng::sandbox_backend::{
    BackendKind, CanonicalPolicy, EnforcementReport, EnforcementState, PrepareContext,
    SandboxBackend, SecurityCapability,
};

/// Production scenario id: real runs are not registry scenarios.
/// Platform-neutral: the backend binding carries the OS, not this string.
pub const PROD_SCENARIO_ID: &str = "PROD";
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
    #[cfg(target_os = "macos")]
    {
        // Seatbelt write + net-off isolation, process-group containment,
        // best-effort rlimits and host evidence — only where the Seatbelt
        // primitive actually exists (fail-closed `Backend::detect` refuses
        // the session otherwise). No syscall filter and no exec-root READ
        // isolation exist on this platform: both stay unsupported, never
        // emulated.
        if crate::sandbox::macos::MacosSandbox::seatbelt_available() {
            enforced.push(SecurityCapability::FilesystemIsolation);
            if net_off {
                enforced.push(SecurityCapability::NetworkIsolation);
            }
            enforced.push(SecurityCapability::ProcessIsolation);
            enforced.push(SecurityCapability::ProcessTreeContainment);
            enforced.push(SecurityCapability::ResourceLimits);
            enforced.push(SecurityCapability::HostEvidence);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        // Placeholders enforce nothing, including host evidence via 3B.
    }
    // Windows installs Job Object tree containment, the AppContainer
    // process/filesystem boundary and default-deny network (net=off only)
    // through the production spawn path; syscall filtering and
    // execution-root scoping stay unsupported, and resource ceilings are
    // policy-conditional (per-run report only, never static).
    // NEEDS-COORDINATOR: convergent placeholder above keeps macOS/Windows
    // cells disjoint; Linux block above stays byte-identical to bd0e242.
    #[cfg(target_os = "windows")]
    {
        let probe = crate::sandbox::windows::probe();
        if probe.experimental_create_process_in_sandbox {
            enforced.push(SecurityCapability::FilesystemIsolation);
            enforced.push(SecurityCapability::ProcessIsolation);
            if net_off {
                enforced.push(SecurityCapability::NetworkIsolation);
            }
        }
        if probe.job_object_kill_on_close {
            enforced.push(SecurityCapability::ProcessTreeContainment);
        }
        enforced.push(SecurityCapability::HostEvidence);
    }
    let unsupported: Vec<SecurityCapability> = SecurityCapability::all()
        .into_iter()
        .filter(|c| !enforced.contains(c))
        .collect();

    let tier_label = tier.map(|t| t.label().to_string()).unwrap_or_else(|| {
        #[cfg(target_os = "linux")]
        return "seccomp".to_string();
        #[cfg(target_os = "macos")]
        return "seatbelt".to_string();
        #[cfg(target_os = "windows")]
        return "job".to_string();
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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
        // No tier on macOS (`Backend::tier()` is `None` there): the normal
        // macOS case mandates the Seatbelt containment set. Best-effort
        // rlimits stay out of the gate (partial, documented); syscall and
        // exec-root READ isolation are unsupported and can never gate a PASS.
        // Off macOS (Linux/Windows/other) the gate stays HostEvidence-only.
        None => {
            #[cfg(target_os = "macos")]
            {
                vec![
                    SecurityCapability::FilesystemIsolation,
                    SecurityCapability::NetworkIsolation,
                    SecurityCapability::ProcessIsolation,
                    SecurityCapability::ProcessTreeContainment,
                    SecurityCapability::HostEvidence,
                ]
            }
            #[cfg(not(target_os = "macos"))]
            {
                vec![SecurityCapability::HostEvidence]
            }
        }
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
/// `scenario` names the production route (`PROD_SCENARIO_ID`, `multi:<agent>`,
/// `mcp`); the registry binding stays [`PROD_REGISTRY`].
#[allow(clippy::too_many_arguments)]
pub fn freeze_production(
    scenario: &str,
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
        scenario,
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
    let identity = ExecutionIdentity::new(scenario, nonce, PROD_REGISTRY, spec.hash().as_str());
    (spec, canonical, identity)
}

/// Unprepared production execution: OWNED frozen inputs, NO spawn method.
///
/// Construction snapshots everything the child will install
/// (argv/cwd/env/policy/net/stdio/mechanics); all fields are private with no
/// setters, so nothing can drift between construction, preparation and
/// spawn. The ONLY way forward is [`prepare`](Self::prepare), which binds
/// the Stage 3B capability backend to these exact inputs.
pub struct UnpreparedProductionExecution {
    mechanics: Backend,
    policy: Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env_extra: HashMap<String, String>,
    net: NetMode,
    timeout: Option<Duration>,
    stdio: StdioMode,
    scenario: String,
}

impl UnpreparedProductionExecution {
    /// Snapshot every spawn input. `backend` is the already-detected legacy
    /// mechanics (probe+tier+net); it is MOVED here and never exposed again,
    /// so the prepared plan and the spawned child necessarily share it.
    /// `net` MUST be the mode `backend` was detected with; any mismatch
    /// fails closed at spawn time.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: Backend,
        policy: Policy,
        argv: Vec<String>,
        cwd: PathBuf,
        env_extra: HashMap<String, String>,
        net: NetMode,
        timeout: Option<Duration>,
        stdio: StdioMode,
        scenario: String,
    ) -> Self {
        UnpreparedProductionExecution {
            mechanics: backend,
            policy,
            argv,
            cwd,
            env_extra,
            net,
            timeout,
            stdio,
            scenario,
        }
    }

    /// Prepare with the platform capability backend (real Linux enforcement
    /// on Linux; honest placeholders elsewhere).
    pub fn prepare(self) -> anyhow::Result<PreparedProductionExecution> {
        #[cfg(target_os = "linux")]
        {
            let mut concrete = crate::verify_ng::sandbox_backend::LinuxBackend::new();
            let mut prepared = self.prepare_with_backend_inner(&mut concrete)?;
            // Tier honesty for forced configurations: the Seccomp tier
            // installs no filesystem isolation even where the kernel offers
            // Landlock (release tier selection never picks it there).
            if prepared.tier == Some(Tier::Seccomp) {
                concrete.restrict_to_seccomp_tier();
            }
            prepared.capability = Box::new(concrete);
            Ok(prepared)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let capability: Box<dyn SandboxBackend> =
                crate::verify_ng::sandbox_backend::select_backend(BackendKind::current_platform());
            self.prepare_with_backend(capability)
        }
    }

    /// Prepare with an explicitly injected capability backend. TEST-ONLY
    /// seam (fail-closed and bypass tests): production routes always use
    /// [`prepare`](Self::prepare). An injected backend owns its own honesty:
    /// it must never report `Enforced` containment it does not install (the
    /// fail-closed test proves fakes stay non-enforcing).
    pub fn prepare_with_backend(
        self,
        mut capability: Box<dyn SandboxBackend>,
    ) -> anyhow::Result<PreparedProductionExecution> {
        let mut prepared = self.prepare_with_backend_inner(&mut *capability)?;
        prepared.capability = capability;
        Ok(prepared)
    }

    /// Shared freeze + prepare core: snapshot identity, build the frozen
    /// environment, freeze the spec, and prepare the given capability
    /// backend against it. Fail-closed: any preparation failure returns
    /// `Err` with no spawn possible (this type has no spawn method).
    fn prepare_with_backend_inner(
        self,
        capability: &mut dyn SandboxBackend,
    ) -> anyhow::Result<PreparedProductionExecution> {
        if self.argv.is_empty() {
            anyhow::bail!("no production command provided");
        }
        #[cfg(target_os = "linux")]
        if self.net.uses_relay()
            && matches!(
                self.mechanics.tier(),
                Some(Tier::FsOnly) | Some(Tier::Seccomp)
            )
        {
            anyhow::bail!("network relay modes require Tier FULL; refusing to run (fail-closed)");
        }
        let tier = self.mechanics.tier();
        let tier_label = tier
            .map(|t| t.label().to_string())
            .unwrap_or_else(|| "none".to_string());

        let nonce = engine::new_nonce();
        let mut env_extra = self.env_extra;
        env_extra.insert(PROD_NONCE_ENV.to_string(), nonce.clone());
        let env = build_production_env(&self.policy, &env_extra);

        let (_spec, canonical, identity) = freeze_production(
            &self.scenario,
            &self.policy,
            &tier_label,
            &self.net,
            &self.mechanics.describe(),
            &self.argv,
            &env,
            &self.cwd,
            &nonce,
        );
        capability.prepare_with_context(&canonical, &identity, &PrepareContext::default());
        let prepared_ok = capability
            .enforcement()
            .map(|r| r.preparation_ok && r.binds_identity(&identity))
            .unwrap_or(false);
        if !prepared_ok {
            anyhow::bail!(
                "production backend preparation failed (fail-closed, no agent execution)"
            );
        }
        Ok(PreparedProductionExecution {
            mechanics: self.mechanics,
            policy: self.policy,
            argv: self.argv,
            cwd: self.cwd,
            env,
            net: self.net,
            tier,
            timeout: self.timeout,
            stdio: self.stdio,
            scenario: self.scenario,
            nonce,
            identity,
            // Overwritten by the caller with the prepared backend object.
            capability: crate::verify_ng::sandbox_backend::select_backend(BackendKind::Direct),
        })
    }
}

/// Prepared production execution: the Stage 3B capability backend is
/// prepared against the frozen bundle, and the legacy mechanics object that
/// will perform the spawn is owned here. The ONLY way forward is
/// [`spawn`](Self::spawn), which consumes `self`: preparation and spawn are
/// inseparable, and one backend cannot be prepared while another is spawned.
/// No setters, no re-freeze, no policy mutation.
pub struct PreparedProductionExecution {
    mechanics: Backend,
    policy: Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env: BTreeMap<String, String>,
    net: NetMode,
    tier: Option<Tier>,
    timeout: Option<Duration>,
    stdio: StdioMode,
    scenario: String,
    nonce: String,
    identity: ExecutionIdentity,
    capability: Box<dyn SandboxBackend>,
}

/// Frozen snapshot of every spawn input, for the policy-drift test: the
/// boundary exposes the frozen bundle (argv/cwd/env/policy/net/stdio) so a
/// test can attempt a mutation and prove the spawn still uses ONLY these
/// values (the execution object has no setters and never re-reads callers).
#[derive(Debug, Clone)]
pub struct FrozenProductionInputs {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub tier: Option<Tier>,
    pub net_label: String,
    pub stdio_captured: bool,
}

impl PreparedProductionExecution {
    /// Frozen execution identity bound to this run.
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }
    /// Per-run nonce (also present in the child environment for the sweep).
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    /// Which capability backend prepared this run.
    pub fn backend_kind(&self) -> BackendKind {
        self.capability.kind()
    }
    /// Current enforcement report (post-prepare: at most `Configured`).
    pub fn enforcement_report(&self) -> Option<&EnforcementReport> {
        self.capability.enforcement()
    }
    /// Frozen spawn inputs: the ONLY values `spawn` may use.
    pub fn frozen_inputs(&self) -> FrozenProductionInputs {
        FrozenProductionInputs {
            argv: self.argv.clone(),
            cwd: self.cwd.clone(),
            env: self.env.clone(),
            tier: self.tier,
            net_label: self.net.label(),
            stdio_captured: !matches!(self.stdio, StdioMode::Inherit),
        }
    }
    /// Frozen policy: the ONLY policy `spawn` and host verification use.
    /// No mutation path exists after `prepare` (fields are private, no
    /// setters, `spawn` consumes `self`). Compared by name in tests
    /// (`Policy` has no `PartialEq`); the frozen hash binding in the
    /// `EnforcementReport` is the authoritative identity check.
    pub fn frozen_policy(&self) -> &Policy {
        &self.policy
    }

    /// Perform exactly one real production spawn. Consumes `self`: no retry
    /// can convert FAIL into PASS, and no second child can be spawned from
    /// this preparation.
    ///
    /// The child installs enforcement from the FROZEN bundle
    /// (frozen policy + frozen tier/net + frozen argv/cwd/env/stdio) through
    /// the legacy mechanics owned here (Full namespaces/mounts/relay, PTY
    /// wiring, existing tier selection, all preserved untouched).
    /// Fail-closed: any preparation/freeze mismatch bails with the spawn
    /// ledger untouched and no fallback execution.
    pub fn spawn(mut self) -> anyhow::Result<SpawnedProductionExecution> {
        // Tripwire: the mechanics object must agree with the frozen net.
        // Both originate from the detection-mode value moved in at
        // construction; any divergence fails closed with no spawn.
        if self.mechanics.net_label() != self.net.label() {
            anyhow::bail!("production net drift (fail-closed, no agent execution)");
        }
        // The prepared plan must agree with the frozen inputs it was built
        // from: `net_deny` mirrors frozen net-off, and a new process group
        // is always required on Linux. A mismatch means preparation and
        // spawn disagree — fail closed instead of spawning unenforced.
        #[cfg(target_os = "linux")]
        if let Some(plan) = self.capability.pre_exec_plan() {
            if plan.net_deny != matches!(self.net, NetMode::Off) {
                anyhow::bail!("production plan/net drift (fail-closed, no agent execution)");
            }
            if !plan.new_pgroup {
                anyhow::bail!("production plan lost process-group containment (fail-closed)");
            }
        }
        let env_extra: HashMap<String, String> = self
            .env
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let opts = SpawnOptions {
            agent_cmd: self.argv.clone(),
            cwd: self.cwd.clone(),
            env_extra,
            stdio: self.stdio,
        };
        PROD_BACKEND_ENTERED.fetch_add(1, Ordering::SeqCst);
        // THE single production spawn boundary: the moved mechanics object
        // applies the frozen bundle to the real child. No other production
        // call site may spawn an agent child. Serialized against the
        // verify-ng harness spawns (fork-safety).
        let spawned = {
            let _serial = engine::spawn_serial().lock().unwrap();
            self.mechanics.spawn(&self.policy, opts)?
        };
        PROD_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
        let pid = spawned.handle.root_pid;
        self.capability.note_spawned(pid);
        // Windows host verification observes THIS child through the
        // retained handles: Job Object membership, the kill-on-close flag,
        // installed ceilings and the child token integrity level. Anything
        // unobserved stays `Configured`, never `Enforced` (NEEDS-COORDINATOR:
        // Windows promotion lives here, not in `note_spawned`, which the
        // unenforced harness path shares).
        #[cfg(target_os = "windows")]
        {
            let verification = match spawned.handle.windows_raw_handles() {
                Some((process, job)) => unsafe {
                    crate::verify_ng::windows_enforce::verify_production_child(process, job)
                },
                None => crate::verify_ng::sandbox_backend::HostVerification::none(),
            };
            self.capability.note_host_verified(&verification);
        }
        // Host verification observes THIS child (its real PID): seccomp
        // filter, NO_NEW_PRIVS and process-group presence come from the
        // shared 3B verifier; resource ceilings are checked against the
        // FROZEN POLICY values with the shared limit parser (never the
        // harness defaults). Unobserved stays `Enforced`, never `Verified`.
        #[cfg(target_os = "linux")]
        {
            use crate::verify_ng::linux_enforce as le;
            let mut verification = le::verify_child_host(pid);
            if let Ok(limits_body) = std::fs::read_to_string(format!("/proc/{pid}/limits")) {
                let lim = &self.policy.limits;
                let expect = |row: &str, v: Option<u64>| match v {
                    Some(x) => le::limits_field_is(&limits_body, row, x),
                    // No ceiling configured: nothing installed, nothing to
                    // verify (stays Enforced, honestly unverified).
                    None => false,
                };
                verification.rlimit_as_ok = expect("Max address space", lim.address_space_bytes);
                verification.rlimit_nproc_ok = expect("Max processes", lim.processes);
                verification.rlimit_cpu_ok = expect("Max cpu time", lim.cpu_seconds);
                verification.rlimit_fsize_ok = expect("Max file size", lim.file_size_bytes);
            }
            self.capability.note_host_verified(&verification);
        }
        Ok(SpawnedProductionExecution {
            handle: spawned.handle,
            #[cfg(unix)]
            broker_ctrl_fd: spawned.broker_ctrl_fd,
            #[cfg(unix)]
            relay_port: spawned.relay_port,
            #[cfg(unix)]
            notif_listener: spawned.notif_listener,
            pid,
            nonce: self.nonce.clone(),
            identity: self.identity.clone(),
            exec_root: self.cwd.clone(),
            scenario: self.scenario.clone(),
            timeout: self.timeout,
            capability: self.capability,
        })
    }
}

/// Spawned production execution: the real agent child plus everything needed
/// to wait for it, verify it, clean up its tree, and report it. The handle
/// is exposed mutably so interactive supervisors (PTY dashboards) can drive
/// it; the typed result is only obtainable through [`wait_collect`](Self::wait_collect)
/// or [`finish`](Self::finish), both of which run the nonce-targeted tree
/// sweep and the backend teardown.
pub struct SpawnedProductionExecution {
    pub handle: SandboxHandle,
    /// Broker end of the relay control socketpair (allowlist modes).
    #[cfg(unix)]
    pub broker_ctrl_fd: Option<OwnedFd>,
    /// Loopback port the in-netns relay listens on (allowlist mode).
    #[cfg(unix)]
    pub relay_port: Option<u16>,
    /// seccomp user-notify listener fd (`--observe-seccomp`).
    #[cfg(unix)]
    pub notif_listener: Option<OwnedFd>,
    pid: u32,
    nonce: String,
    identity: ExecutionIdentity,
    exec_root: PathBuf,
    scenario: String,
    timeout: Option<Duration>,
    capability: Box<dyn SandboxBackend>,
}

impl SpawnedProductionExecution {
    /// Actual agent root PID (host-observed, used for verification/sweep).
    pub fn pid(&self) -> u32 {
        self.pid
    }
    /// Per-run nonce binding spec, report and child environment.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    /// Frozen execution identity of this run.
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }
    /// Spawn event for caller-owned ledgers (exact under threads).
    pub fn event(&self) -> ProdSpawnEvent {
        ProdSpawnEvent {
            run_id: self.nonce.clone(),
            pid: self.pid,
        }
    }
    /// Current enforcement report.
    pub fn enforcement_report(&self) -> Option<&EnforcementReport> {
        self.capability.enforcement()
    }
    /// Broker end of the relay control socketpair (allowlist modes).
    /// Taken by the supervisor to spawn the broker; `None` afterwards.
    #[cfg(unix)]
    pub fn take_broker_ctrl_fd(&mut self) -> Option<OwnedFd> {
        self.broker_ctrl_fd.take()
    }
    /// Loopback port the in-netns relay listens on (allowlist mode).
    #[cfg(unix)]
    pub fn relay_port(&self) -> Option<u16> {
        self.relay_port
    }
    /// seccomp user-notify listener fd (`--observe-seccomp`).
    /// Taken by the supervisor to spawn the notifier; `None` afterwards.
    #[cfg(unix)]
    pub fn take_notif_listener(&mut self) -> Option<OwnedFd> {
        self.notif_listener.take()
    }

    /// Wait with the proven killer path (frozen timeout), then finish.
    /// Never a bare blocking wait.
    pub fn wait_collect(mut self) -> ProductionResult {
        let timeout = self.timeout;
        let (exit_code, timed_out) = wait_for_exit(&mut self.handle, timeout);
        self.finish(Some(exit_code), timed_out)
    }

    /// Finish after an externally driven wait (interactive TUI dashboards
    /// own their wait loops): runs the nonce-targeted tree sweep for THIS
    /// run, records it on the backend, tears down, and returns the typed
    /// result. The sweep cannot be skipped: there is no other way to obtain
    /// a `ProductionResult`.
    pub fn finish(mut self, exit_code: Option<i32>, timed_out: bool) -> ProductionResult {
        // Windows tree sweep (NEEDS-COORDINATOR: additive, cfg-gated): read
        // the host-observed job membership, terminate through kill-on-close
        // (the kernel kills the whole tree — no PID-group signals, no
        // best-effort sweep), then prove every observed member dead by
        // handle. Residual survivors fail the tree claim closed.
        #[cfg(target_os = "windows")]
        {
            use crate::verify_ng::windows_enforce as we;
            let members = match self.handle.windows_raw_handles() {
                Some((_, job)) => unsafe { we::job_assigned_pids(job) },
                None => Vec::new(),
            };
            let observed = members.len();
            // Kill-on-close termination: dropping the job handle kills every
            // assigned process. This is the containment kill, not cleanup.
            self.handle.terminate();
            let residual = we::pids_still_alive(&members, Duration::from_secs(5));
            let clean = residual.is_empty();
            self.capability.note_tree_clean(clean);
            self.capability.note_diagnostic(format!(
                "tree-sweep clean={clean} observed={observed} residual={residual:?} job-kill-on-close"
            ));
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(sweep) =
                crate::verify_ng::linux_enforce::sweep_tree_by_nonce(self.nonce.as_str(), self.pid)
            {
                self.capability.note_tree_clean(sweep.clean);
                self.capability.note_diagnostic(format!(
                    "tree-sweep clean={} killed={} residual={:?} subreaper={} blind={}",
                    sweep.clean, sweep.killed, sweep.residual, sweep.subreaper, sweep.blind
                ));
            }
        }
        let report = self
            .capability
            .enforcement()
            .cloned()
            .expect("prepared backend always holds a report");
        let diagnostic = self.capability.diagnostic();
        let backend_kind = self.capability.kind();
        self.capability.teardown();
        ProductionResult {
            backend: backend_kind,
            report,
            exit_code,
            timed_out,
            pid: Some(self.pid),
            nonce: self.nonce.clone(),
            scenario_id: self.scenario.clone(),
            exec_root: self.exec_root.clone(),
            cwd: self.exec_root.clone(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            spawn_via_backend: true,
            diagnostic,
        }
    }
}

/// Proven wait for ANY production handle: deadline → try_wait polling →
/// terminate once → bounded re-wait. `None` polls until exit (interactive
/// sessions whose deadline is the user's quit action). Never a bare
/// blocking `wait()` that bypasses tree cleanup (the caller must still
/// [`SpawnedProductionExecution::finish`] for the sweep).
pub fn wait_for_exit(handle: &mut SandboxHandle, timeout: Option<Duration>) -> (i32, bool) {
    match timeout {
        Some(limit) => {
            let deadline = Instant::now() + limit;
            let (outcome, code) = killer::kill_on_deadline_with(handle, deadline, PROD_EXIT_POLL);
            (code, outcome == KillOutcome::KilledOnDeadline)
        }
        None => loop {
            if let Some(code) = handle.try_wait() {
                return (code, false);
            }
            std::thread::sleep(PROD_EXIT_POLL);
        },
    }
}

/// Drain two caller-held pipe read ends with the production budget/cap
/// (shared harness collector, no second implementation).
#[cfg(unix)]
pub fn collect_piped(stdout_r: OwnedFd, stderr_r: OwnedFd, budget: Duration) -> (Vec<u8>, Vec<u8>) {
    // `ChildStdout/Stderr` are thin fd wrappers with `From<OwnedFd>` (there
    // is no `From<File>`): hand the owned pipe read ends over directly.
    let stdout_child: std::process::ChildStdout = stdout_r.into();
    let stderr_child: std::process::ChildStderr = stderr_r.into();
    let collected = crate::verify_ng::collector::collect_child_stdio(
        stdout_child,
        stderr_child,
        Instant::now() + budget,
        PROD_MAX_STDIO,
    );
    (collected.stdout, collected.stderr)
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

/// Headless production execution through an injected capability backend.
/// The legacy mechanics are always real-detected (fail-closed); only the
/// capability backend is injected, and only the frozen bundle is spawned.
/// A failing preparation never spawns (`spawn ledger` unchanged, `Err`
/// return, no fallback). A fake backend can never claim real Linux
/// security: its report stays honestly Unsupported/Failed.
/// TEST-ONLY seam; production routes use [`execute_simple`].
#[allow(clippy::too_many_arguments)]
pub fn execute_with_backend(
    policy: &Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env_extra: HashMap<String, String>,
    net: NetMode,
    tier: Option<Tier>,
    timeout: Duration,
    capability: Box<dyn SandboxBackend>,
    spawn_log: &mut ProdSpawnLog,
) -> anyhow::Result<ProductionResult> {
    execute_inner(
        policy,
        argv,
        cwd,
        env_extra,
        net,
        tier,
        timeout,
        Some(capability),
        spawn_log,
    )
}

/// Shared headless core: real-detected mechanics + typestate boundary.
/// `capability=None` prepares the platform backend; `Some` injects a test
/// double for the capability side only.
#[allow(clippy::too_many_arguments)]
fn execute_inner(
    policy: &Policy,
    argv: Vec<String>,
    cwd: PathBuf,
    env_extra: HashMap<String, String>,
    net: NetMode,
    tier: Option<Tier>,
    timeout: Duration,
    capability: Option<Box<dyn SandboxBackend>>,
    spawn_log: &mut ProdSpawnLog,
) -> anyhow::Result<ProductionResult> {
    // Mechanics are real-detected (fail-closed, honors VETTO_FORCE_TIER in
    // debug builds like every production route). Detection forks probes:
    // production callers run it single-threaded; tests accept the same
    // harness-grade fork class the 3B probes already use.
    let mechanics = crate::sandbox::Backend::detect(net.clone(), false)?;
    if let Some(t) = tier {
        if mechanics.tier() != Some(t) {
            anyhow::bail!("explicit tier does not match detected tier (fail-closed)");
        }
    }
    #[cfg(unix)]
    let (stdout_r, stdout_w, stderr_r, stderr_w) = piped_stdio_fds()?;
    #[cfg(unix)]
    let stdio = StdioMode::Captured {
        stdout_w: stdout_w.as_raw_fd(),
        stderr_w: stderr_w.as_raw_fd(),
    };
    #[cfg(not(unix))]
    let stdio = StdioMode::Inherit;
    let unprepared = UnpreparedProductionExecution::new(
        mechanics,
        policy.clone(),
        argv,
        cwd,
        env_extra,
        net,
        Some(timeout),
        stdio,
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = match capability {
        Some(capability) => unprepared.prepare_with_backend(capability)?,
        None => unprepared.prepare()?,
    };
    let spawned = prepared.spawn()?;
    spawn_log.push(spawned.event());
    #[cfg(unix)]
    {
        // Drop our copies of the child-side write ends so EOF works.
        drop(stdout_w);
        drop(stderr_w);
    }
    // `mut` is unconditional: the unix branch below assigns stdout/stderr,
    // and `cfg`-gated `mut` would diverge between platforms.
    #[allow(unused_mut)]
    let mut result = spawned.wait_collect();
    #[cfg(unix)]
    {
        let (out, err) = collect_piped(stdout_r, stderr_r, PROD_DRAIN_BUDGET);
        result.stdout = out;
        result.stderr = err;
    }
    Ok(result)
}

/// Create two cloexec pipes for boundary-owned captured stdio.
/// Returns `((stdout_r, stdout_w), (stderr_r, stderr_w))`.
#[cfg(unix)]
fn piped_stdio_fds() -> anyhow::Result<(OwnedFd, OwnedFd, OwnedFd, OwnedFd)> {
    use std::os::fd::FromRawFd;
    let make = || -> anyhow::Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: valid out-array for pipe(2).
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            anyhow::bail!("pipe: {}", std::io::Error::last_os_error());
        }
        for fd in fds {
            // SAFETY: fd came from the successful pipe call.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
            {
                let error = std::io::Error::last_os_error();
                // SAFETY: both descriptors came from the successful pipe call.
                unsafe {
                    libc::close(fds[0]);
                    libc::close(fds[1]);
                }
                anyhow::bail!("fcntl CLOEXEC: {error}");
            }
        }
        // SAFETY: fresh descriptors from a successful pipe+CLOEXEC setup.
        Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        }))
    };
    let (out_r, out_w) = make()?;
    let (err_r, err_w) = make()?;
    Ok((out_r, out_w, err_r, err_w))
}

/// Real headless production execution through the authoritative boundary:
/// real-detected mechanics, fresh capability backend per run, no shared
/// backend state, one spawn per call, no retry FAIL->PASS.
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
    execute_inner(
        policy, argv, cwd, env_extra, net, tier, timeout, None, spawn_log,
    )
}

#[cfg(test)]
mod production_unit_tests {
    use super::*;

    fn test_policy() -> Policy {
        Policy::default()
    }

    /// Minimal functional policy for real-spawn unit tests: system read
    /// roots + tmp write root so the child passes stdio setup (`/dev/null`)
    /// and `execve` under real Landlock-enforcing mechanics (Full/FsOnly).
    /// Bare `Policy::default()` denies `/dev/null` at stdio setup (child
    /// exit 124) wherever Landlock is active. Capability assertions below
    /// still target the injected backend's report, never the mechanics.
    fn functional_test_policy(tmp: &std::path::Path) -> Policy {
        let mut policy = test_policy();
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
        policy
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
            PROD_SCENARIO_ID,
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
            PROD_SCENARIO_ID,
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
            PROD_SCENARIO_ID,
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
            PROD_SCENARIO_ID,
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
    /// No execution object exists on `Err`, so no child can exist either.
    /// Non-Unix: mechanics detection fails closed first (Windows sandbox
    /// unavailable in CI), which is the same `Err`-with-empty-ledger proof.
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
        let backend = FailBackend { report: None };
        let mut log = ProdSpawnLog::new();
        let err = execute_with_backend(
            &test_policy(),
            vec!["sh".to_string()],
            PathBuf::from("/tmp"),
            HashMap::new(),
            NetMode::Off,
            Some(Tier::FsOnly),
            Duration::from_secs(5),
            Box::new(backend),
            &mut log,
        );
        let err = match err {
            Ok(_) => panic!("preparation failure must not produce an execution"),
            Err(e) => e,
        };
        assert!(
            log.is_empty(),
            "spawn ledger unchanged on preparation failure"
        );
        // Two fail-closed origins share this shape: the injected capability
        // backend refuses preparation (Unix), or real mechanics detection
        // refuses first (non-Unix, e.g. Windows sandbox unavailable in CI).
        // Both are `Err` with an empty ledger and no child — never a silent
        // direct fallback.
        let msg = err.to_string();
        assert!(
            msg.contains("fail-closed") || msg.contains("refusing"),
            "fail-closed error, got: {err:#}"
        );
    }

    /// TEST-PROD-BACKEND-CALLED-001: production runner calls the backend.
    /// Unix-only: asserts a real spawn through the boundary (Windows uses
    /// `cmd` plumbing covered by the fail-closed test above).
    #[cfg(unix)]
    #[test]
    fn test_prod_backend_called_001_runner_calls_backend() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Arc,
        };
        struct CountBackend {
            prepares: Arc<AtomicUsize>,
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
                self.prepares.fetch_add(1, AtomicOrdering::SeqCst);
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
            fn enforcement(&self) -> Option<&EnforcementReport> {
                self.report.as_ref()
            }
            fn teardown(&mut self) {
                self.report = None;
            }
        }
        let prepares = Arc::new(AtomicUsize::new(0));
        let backend = CountBackend {
            prepares: Arc::clone(&prepares),
            report: None,
        };
        let tmp = std::env::temp_dir().join(format!("vetto-prod-called-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmp);
        // No /bin/true on macOS: use the platform shell.
        let argv = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ];
        let mut log = ProdSpawnLog::new();
        let policy = functional_test_policy(&tmp);
        let out = execute_with_backend(
            &policy,
            argv,
            tmp.clone(),
            HashMap::new(),
            NetMode::Off,
            None,
            Duration::from_secs(10),
            Box::new(backend),
            &mut log,
        )
        .expect("count backend run");
        assert_eq!(
            prepares.load(AtomicOrdering::SeqCst),
            1,
            "backend entered exactly once"
        );
        assert_eq!(log.len(), 1, "one spawn == one scenario");
        assert!(out.spawn_via_backend);
        assert!(!out.allows_pass(&[SecurityCapability::FilesystemIsolation]));
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
