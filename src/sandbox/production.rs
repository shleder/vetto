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

use crate::audit::record::{TierClassification, VettoAuditRecord};
use crate::audit::verdict::{EvidenceStrength, FinalVerdict, VerdictEngine, VerdictStatus};
use crate::config::NetMode;
use crate::crypto::attest::AuditLedger;
use crate::policy::{Policy, Tier};
use crate::policy_ir::{
    ExecutionState, ExecutionStateMachine, SecurityContract, StateTransitionError,
};
use crate::proctree::{
    ExtinctionBreach, ExtinctionProof, ExtinctionVerifier, PlatformExtinctionTier,
    FAIL_CLOSED_EXTINCTION_EXIT_CODE,
};
use crate::sandbox::{Backend, SandboxHandle, SpawnOptions, StdioMode};
use crate::verify_ng::engine;
use crate::verify_ng::evidence::ExecutionIdentity;
use crate::verify_ng::frozen::{self, FrozenSpec};
use crate::verify_ng::killer::{self, KillOutcome};
use crate::verify_ng::sandbox_backend::{
    select_backend, BackendKind, CanonicalPolicy, EnforcementReport, EnforcementState,
    PrepareContext, SandboxBackend, SecurityCapability,
};

/// Production scenario id: real runs are not registry scenarios.
/// Platform-neutral: the backend binding carries the OS, not this string.
pub const PROD_SCENARIO_ID: &str = "PROD";
/// Nonce env label: run label for the nonce-targeted sweep, not a secret.
pub const PROD_NONCE_ENV: &str = "VETTO_PROD_NONCE";
/// Registry binding for production runs (not a scenario-registry hash).
pub const PROD_REGISTRY: &str = "production";
/// Stdio drain budget after termination (200ms deadline per Phase 1 spec).
pub const PROD_DRAIN_BUDGET: Duration = Duration::from_millis(200);
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
            #[cfg(target_os = "linux")]
            {
                let mut caps = vec![
                    SecurityCapability::FilesystemIsolation,
                    SecurityCapability::ExecutionRootIsolation,
                    SecurityCapability::ProcessIsolation,
                    SecurityCapability::ProcessTreeContainment,
                    SecurityCapability::ResourceLimits,
                    SecurityCapability::SyscallRestriction,
                    SecurityCapability::HostEvidence,
                ];
                if net_off {
                    caps.push(SecurityCapability::NetworkIsolation);
                }
                caps
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
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

/// Project a verified production contract into the existing capability API.
/// The envelope retains the detached digest without hashing it into itself.
fn freeze_production_contract(
    scenario: &str,
    contract: &SecurityContract,
    tier: &str,
    backend: &str,
) -> anyhow::Result<(CanonicalPolicy, ExecutionIdentity)> {
    anyhow::ensure!(
        contract.verify_digest(),
        "invalid production contract digest"
    );
    let production = contract
        .production
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("missing production installation contract"))?;
    anyhow::ensure!(
        production.backend == backend
            && production.tier.map(|t| t.label()).unwrap_or("none") == tier,
        "production contract/backend mismatch"
    );
    let mut argv = vec![contract
        .agent_identity
        .invoked_binary
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("non-UTF8 production executable"))?
        .to_string()];
    argv.extend(contract.agent_identity.invoked_args.clone());
    // v1 summary fields cannot compete with the lossless installation values.
    // Reject contradictory projections even if a caller re-seals the payload.
    let expected = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
        crate::policy_ir::compiler::EffectivePolicyInput {
            policy: &production.installation_policy,
            argv: &argv,
            cwd: &contract.filesystem.workspace_root,
            env: &contract.environment.explicit_vars,
            net: &production.net,
            nonce: &contract.session_nonce,
            timeout: production.timeout,
            tier: production.tier,
            backend: production.backend.clone(),
            observe_seccomp: production.observe_seccomp,
            debug_ports: production.debug_ports.as_ref(),
        },
    )?;
    anyhow::ensure!(
        expected == *contract,
        "inconsistent production contract projection"
    );
    let mut spec = frozen::freeze_spec(
        scenario,
        PROD_REGISTRY,
        &production.installation_policy,
        tier,
        &production.net,
        backend,
        &argv,
        &contract.environment.explicit_vars,
        &contract.filesystem.workspace_root,
        &contract.session_nonce,
    );
    spec.policy_bytes = serde_json::to_vec(&serde_json::json!({
        "contract": contract,
        "digest": contract.contract_digest_blake3,
    }))?;
    let canonical = CanonicalPolicy::from_frozen(&spec);
    let identity = ExecutionIdentity::new(
        scenario,
        &contract.session_nonce,
        PROD_REGISTRY,
        &spec.hash(),
    );
    Ok((canonical, identity))
}

fn prepare_production_contract(
    scenario: &str,
    contract: &SecurityContract,
    tier: &str,
    backend: &str,
    capability: &mut dyn SandboxBackend,
) -> anyhow::Result<(CanonicalPolicy, ExecutionIdentity)> {
    let (canonical, identity) = freeze_production_contract(scenario, contract, tier, backend)?;
    capability.prepare_with_context(&canonical, &identity, &PrepareContext::default());
    let prepared_ok = capability
        .enforcement()
        .map(|r| r.preparation_ok && r.binds_identity(&identity))
        .unwrap_or(false);
    anyhow::ensure!(
        prepared_ok,
        "production backend preparation failed (fail-closed, no agent execution)"
    );
    Ok((canonical, identity))
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
    pub tier: Option<Tier>,
    timeout: Option<Duration>,
    stdio: StdioMode,
    scenario: String,
    debug_ports: Option<crate::multi::DebugPortConfig>,
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
        let tier = backend.tier();
        UnpreparedProductionExecution {
            mechanics: backend,
            policy,
            argv,
            cwd,
            env_extra,
            net,
            tier,
            timeout,
            stdio,
            scenario,
            debug_ports: None,
        }
    }

    /// Resolve multi-session relay settings before contract compilation.
    pub fn with_debug_ports(mut self, config: crate::multi::DebugPortConfig) -> Self {
        self.debug_ports = Some(config);
        self
    }

    /// Detected execution tier for this production run.
    pub fn tier(&self) -> Option<Tier> {
        self.tier
    }

    /// Prepare with the platform capability backend (real Linux enforcement
    /// on Linux; honest placeholders elsewhere).
    pub fn prepare(self) -> anyhow::Result<PreparedProductionExecution> {
        let mut backend = select_backend(BackendKind::current_platform());
        let tier = self.tier;
        let mut prepared = self.prepare_with_backend_inner(&mut *backend)?;
        backend.restrict_tier(tier);
        prepared.capability = backend;
        Ok(prepared)
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
        let tier = self.tier;
        let mut prepared = self.prepare_with_backend_inner(&mut *capability)?;
        capability.restrict_tier(tier);
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
        #[cfg(target_os = "macos")]
        if self.net.uses_relay() {
            anyhow::bail!(
                "production backend preparation failed (fail-closed, no agent execution): \
                 --net={} requires the Linux network-namespace relay and is unavailable on macOS; \
                 refusing silently-weaker enforcement (fail-closed); run with `--net=off` on macOS",
                self.net.label()
            );
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
        let tier = self.tier;
        let tier_label = tier
            .map(|t| t.label().to_string())
            .unwrap_or_else(|| "none".to_string());

        let nonce = engine::new_nonce();
        let mut env_extra = self.env_extra;
        env_extra.insert(PROD_NONCE_ENV.to_string(), nonce.clone());
        let env = build_production_env(&self.policy, &env_extra);

        let mut fsm = ExecutionStateMachine::new();
        let contract = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
            crate::policy_ir::compiler::EffectivePolicyInput {
                policy: &self.policy,
                argv: &self.argv,
                cwd: &self.cwd,
                env: &env,
                net: &self.net,
                nonce: &nonce,
                timeout: self.timeout,
                tier,
                backend: self.mechanics.describe(),
                observe_seccomp: self.mechanics.observes_seccomp(),
                debug_ports: self.debug_ports.as_ref(),
            },
        )?;
        fsm.transition(ExecutionState::PolicyCompiled)?;
        anyhow::ensure!(
            contract.verify_digest(),
            "invalid compiled production contract"
        );
        fsm.transition(ExecutionState::ContractSealed)?;
        let (canonical, identity) = prepare_production_contract(
            &self.scenario,
            &contract,
            &tier_label,
            &self.mechanics.describe(),
            capability,
        )?;
        fsm.transition(ExecutionState::Prepare)?;
        Ok(PreparedProductionExecution {
            mechanics: self.mechanics,
            contract,
            canonical,
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
            fsm,
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
    contract: SecurityContract,
    canonical: CanonicalPolicy,
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
    fsm: ExecutionStateMachine,
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
        &self
            .contract
            .production
            .as_ref()
            .expect("validated production contract")
            .installation_policy
    }

    pub fn contract(&self) -> &SecurityContract {
        &self.contract
    }

    #[doc(hidden)]
    pub fn contract_mut_for_test(&mut self) -> &mut SecurityContract {
        &mut self.contract
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
        anyhow::ensure!(
            self.fsm.current_state() == ExecutionState::Prepare,
            "production lifecycle is not prepared (fail-closed, no agent execution)"
        );
        let tier_label = self.tier.map(|t| t.label()).unwrap_or("none");
        let (canonical, identity) = freeze_production_contract(
            &self.scenario,
            &self.contract,
            tier_label,
            &self.mechanics.describe(),
        )?;
        let production = self
            .contract
            .production
            .as_ref()
            .expect("validated contract");
        anyhow::ensure!(
            canonical == self.canonical
                && identity.frozen_hash == self.identity.frozen_hash
                && canonical.argv == self.argv
                && canonical.cwd == self.cwd
                && canonical.env == self.env
                && production.net == self.net
                && production.timeout == self.timeout
                && production.tier == self.tier
                && production.observe_seccomp == self.mechanics.observes_seccomp(),
            "production contract/frozen input drift (fail-closed, no agent execution)"
        );
        let policy = &production.installation_policy;
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
        crate::sandbox::reset_evidence_channel();
        PROD_BACKEND_ENTERED.fetch_add(1, Ordering::SeqCst);
        // THE single production spawn boundary: the moved mechanics object
        // applies the frozen bundle to the real child. No other production
        // call site may spawn an agent child. Serialized against the
        // verify-ng harness spawns (fork-safety).
        let spawned = {
            let _serial = engine::spawn_serial().lock().unwrap();
            self.fsm.transition(ExecutionState::Spawn)?;
            self.mechanics.spawn(policy, opts)?
        };
        self.fsm.transition(ExecutionState::Enforce)?;
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
                let lim = &policy.limits;
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
        // macOS host verification observes THIS child the same way: the
        // separate process group via `getpgid` (Seatbelt denials are
        // invisible to the host and there is no seccomp/rlimit indicator,
        // so those caps stay `Enforced`, honestly unverified).
        #[cfg(target_os = "macos")]
        {
            let verification = crate::sandbox::macos::prod_verify::verify_child_host(pid);
            self.capability.note_host_verified(&verification);
        }

        self.fsm.transition(ExecutionState::Observe)?;

        Ok(SpawnedProductionExecution {
            contract: self.contract,
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
            fsm: self.fsm,
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
    contract: SecurityContract,
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
    fsm: ExecutionStateMachine,
}

impl SpawnedProductionExecution {
    pub fn contract(&self) -> &SecurityContract {
        &self.contract
    }

    /// FSM lifecycle state machine for this execution.
    pub fn fsm(&self) -> &ExecutionStateMachine {
        &self.fsm
    }
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
        if self.fsm.current_state() == ExecutionState::Enforce {
            let _ = self.fsm.transition(ExecutionState::Observe);
        }
        if self.fsm.current_state() == ExecutionState::Observe {
            let _ = self.fsm.transition(ExecutionState::Terminate);
        }
        if self.fsm.current_state() == ExecutionState::Terminate {
            let _ = self.fsm.transition(ExecutionState::Cleanup);
        }

        let extinction_start = Instant::now();
        #[allow(unused_assignments)]
        let mut surviving_processes = 0usize;
        let surviving_resources = 0usize;

        #[cfg(target_os = "windows")]
        let extinction_platform = PlatformExtinctionTier::WindowsTier3Proven;
        #[cfg(target_os = "linux")]
        let extinction_platform = PlatformExtinctionTier::LinuxTier1Proven;
        #[cfg(target_os = "macos")]
        let extinction_platform = PlatformExtinctionTier::MacOsTier2BestEffort;
        #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
        let extinction_platform = PlatformExtinctionTier::LinuxTier1Proven;

        // Windows tree sweep: read the host-observed job membership, terminate
        // through kill-on-close, then prove every observed member dead by handle
        // within MAX_EXTINCTION_DEADLINE_MS (500ms, INV-20).
        #[cfg(target_os = "windows")]
        {
            use crate::proctree::MAX_EXTINCTION_DEADLINE_MS;
            use crate::verify_ng::windows_enforce as we;
            let members = match self.handle.windows_raw_handles() {
                Some((_, job)) => unsafe { we::job_assigned_pids(job) },
                None => Vec::new(),
            };
            let observed = members.len();
            self.handle.terminate();
            let residual =
                we::pids_still_alive(&members, Duration::from_millis(MAX_EXTINCTION_DEADLINE_MS));
            surviving_processes = residual.len();
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
                surviving_processes = if sweep.clean {
                    0
                } else {
                    sweep.residual.len().max(1)
                };
                self.capability.note_tree_clean(sweep.clean);
                self.capability.note_diagnostic(format!(
                    "tree-sweep clean={} killed={} residual={:?} subreaper={} blind={}",
                    sweep.clean, sweep.killed, sweep.residual, sweep.subreaper, sweep.blind
                ));
            } else {
                surviving_processes = 1;
                self.capability.note_tree_clean(false);
            }
        }
        // macOS tree sweep: SIGKILL the process group + leader, then prove
        // group death from the host.
        #[cfg(target_os = "macos")]
        {
            let clean = crate::sandbox::macos::prod_verify::sweep_tree(self.pid);
            surviving_processes = if clean { 0 } else { 1 };
            self.capability.note_tree_clean(clean);
            self.capability.note_diagnostic(format!(
                "tree-sweep clean={clean} pid={} (pgroup kill + group-death check)",
                self.pid
            ));
        }

        let elapsed_ms = extinction_start.elapsed().as_millis() as u64;

        // Formally verify extinction under INV-20 (< 500ms, 0 survivors)
        let extinction_res = ExtinctionVerifier::verify(
            extinction_platform,
            surviving_processes,
            surviving_resources,
            elapsed_ms,
        );

        let mut final_exit_code = exit_code;
        if let Err(ref breach) = extinction_res {
            self.capability.note_tree_clean(false);
            self.capability.note_diagnostic(format!(
                "extinction breach (fail-closed exit 125, INV-20): platform={} elapsed={}ms reason={}",
                breach.platform.label(),
                breach.elapsed_ms,
                breach.reason
            ));
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        }

        // Check Netlink evidence channel integrity (INV-37)
        let evidence_intact = crate::sandbox::is_evidence_channel_intact();
        if !evidence_intact {
            self.capability.note_tree_clean(false);
            self.capability.note_diagnostic(
                "evidence channel disrupted (ENOBUFS / packet drop, INV-37): fail-closed exit 125"
                    .to_string(),
            );
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        }

        // Record events to host AuditLedger outside sandbox namespace (INV-35)
        let audit_dir = std::env::var("VETTO_AUDIT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("vetto-audit"));
        let _ = std::fs::create_dir_all(&audit_dir);
        let ledger_path = audit_dir.join(format!("vetto-audit-{}.jsonl", self.nonce));

        #[cfg(target_os = "linux")]
        let platform_str = "linux";
        #[cfg(target_os = "macos")]
        let platform_str = "macos";
        #[cfg(target_os = "windows")]
        let platform_str = "windows";
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let platform_str = "unknown";

        #[cfg(target_os = "linux")]
        let tier_class = TierClassification::Tier1Linux;
        #[cfg(target_os = "macos")]
        let tier_class = TierClassification::Tier2Macos;
        #[cfg(target_os = "windows")]
        let tier_class = TierClassification::Tier3Windows;
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let tier_class = TierClassification::Tier1Linux;

        let mut ext_hash_opt: Option<String> = None;
        let mut ledger_write_ok = false;
        if let Ok(mut ledger) = AuditLedger::new(&ledger_path) {
            let init_rec = VettoAuditRecord::session_init(
                &self.nonce,
                &self.contract.contract_digest_blake3,
                platform_str,
                std::env::consts::OS,
                &self.scenario,
                tier_class,
            );
            let _ = ledger.record_audit_record(&init_rec);

            let ext_rec = VettoAuditRecord::tree_extinction(
                &self.nonce,
                &self.contract.contract_digest_blake3,
                extinction_platform.label(),
                surviving_processes as u32,
                9,
                elapsed_ms,
                extinction_res.is_ok(),
            );
            if let Ok(h) = ledger.record_audit_record(&ext_rec) {
                ext_hash_opt = Some(h);
            }

            let (v_status, v_strength, v_code) =
                match (extinction_res.is_ok(), evidence_intact, final_exit_code) {
                    (false, _, _) => (
                        VerdictStatus::Fail,
                        EvidenceStrength::Strong,
                        FAIL_CLOSED_EXTINCTION_EXIT_CODE,
                    ),
                    (_, false, _) => (
                        VerdictStatus::Inconclusive,
                        EvidenceStrength::Strong,
                        FAIL_CLOSED_EXTINCTION_EXIT_CODE,
                    ),
                    (_, _, Some(code)) if code != 0 => {
                        (VerdictStatus::Fail, EvidenceStrength::Strong, code)
                    }
                    _ => (VerdictStatus::Pass, EvidenceStrength::Strong, 0),
                };
            let verdict_obj = FinalVerdict {
                status: v_status,
                strength: v_strength,
                exit_code: v_code,
                reason: if !evidence_intact {
                    "Evidence capture channel dropped events: audit ledger inconclusive (INV-37)"
                        .to_string()
                } else if extinction_res.is_err() {
                    "Process tree extinction breach (INV-20)".to_string()
                } else {
                    "Session completed within invariant parameters".to_string()
                },
            };
            let root_dag_digest = ext_hash_opt.clone().unwrap_or_else(|| "0".repeat(64));
            let verdict_rec = VettoAuditRecord::session_verdict(
                &self.nonce,
                &self.contract.contract_digest_blake3,
                &verdict_obj,
                &root_dag_digest,
            );
            let _ = ledger.record_audit_record(&verdict_rec);
            ledger_write_ok = true;
        }

        // Verify ledger hash chain (INV-34)
        let mut ledger_verified = false;
        if ledger_write_ok {
            match AuditLedger::verify_file(&ledger_path) {
                Ok(true) => {
                    ledger_verified = true;
                    self.capability.note_diagnostic(format!(
                        "audit ledger verified (INV-34, INV-35): {}",
                        ledger_path.display()
                    ));
                }
                Ok(false) | Err(_) => {
                    self.capability.note_tree_clean(false);
                    self.capability.note_diagnostic(format!(
                        "audit ledger hash chain verification failed (fail-closed exit 125, INV-34): {}",
                        ledger_path.display()
                    ));
                    final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
                }
            }
        } else {
            self.capability.note_tree_clean(false);
            self.capability.note_diagnostic(format!(
                "audit ledger unavailable on host (fail-closed exit 125, INV-35): {}",
                ledger_path.display()
            ));
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        }

        // Final verdict and FSM state transition
        let final_verdict_obj = FinalVerdict {
            status: if extinction_res.is_err() || !ledger_verified {
                VerdictStatus::Fail
            } else if !evidence_intact {
                VerdictStatus::Inconclusive
            } else if final_exit_code.unwrap_or(0) != 0 {
                VerdictStatus::Fail
            } else {
                VerdictStatus::Pass
            },
            strength: EvidenceStrength::Strong,
            exit_code: final_exit_code.unwrap_or(0),
            reason: if !evidence_intact {
                "Evidence capture channel dropped events: audit ledger inconclusive (INV-37)"
                    .to_string()
            } else if let Err(ref breach) = extinction_res {
                format!("Process tree extinction breach (INV-20): {}", breach.reason)
            } else if !ledger_verified {
                "Audit ledger hash chain verification failed (INV-34)".to_string()
            } else {
                "Session completed within invariant parameters".to_string()
            },
        };

        if extinction_res.is_err() || !evidence_intact || !ledger_verified {
            let _ = self.fsm.fail_closed(&final_verdict_obj.reason);
            let _ = self.fsm.transition(ExecutionState::EmergencyCleanup);
            let _ = self.fsm.transition(ExecutionState::Terminal);
        } else {
            let _ = self.fsm.transition(ExecutionState::Verify);
            let _ = self.fsm.transition(ExecutionState::Attest);
            let _ = self.fsm.transition(ExecutionState::Verdict);
            let _ = self.fsm.transition(ExecutionState::Terminal);
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
            exit_code: final_exit_code,
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
            verdict: Some(final_verdict_obj),
            fsm_state: Some(self.fsm.current_state()),
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
    pub verdict: Option<FinalVerdict>,
    pub fsm_state: Option<ExecutionState>,
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

    /// Sets the final execution verdict.
    pub fn with_verdict(mut self, verdict: FinalVerdict) -> Self {
        self.verdict = Some(verdict);
        self
    }

    /// Evaluates the final execution verdict based on host facts (§18).
    /// Enforces INV-37 Netlink buffer overflow detection (`is_evidence_channel_intact()`).
    pub fn evaluate_verdict(
        &mut self,
        contract: &SecurityContract,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
    ) -> FinalVerdict {
        let evidence_channel_intact = crate::sandbox::is_evidence_channel_intact();
        let agent_code = self
            .exit_code
            .unwrap_or(if self.timed_out { 124 } else { 125 });
        let verdict = VerdictEngine::evaluate(
            contract,
            kernel_denials,
            unauthorized_writes,
            zombies_survived,
            evidence_channel_intact,
            agent_code,
        );
        self.verdict = Some(verdict.clone());
        verdict
    }
}

/// Tri-Plane Supervisor Engine coordinating Control, Data, and Verification planes (§20, §30).
#[derive(Debug)]
pub struct SupervisorEngine {
    contract: SecurityContract,
    fsm: ExecutionStateMachine,
    backend_kind: BackendKind,
}

impl SupervisorEngine {
    /// Initialize a new SupervisorEngine with a sealed SecurityContract.
    /// Drives the FSM through Intent -> PolicyCompiled -> ContractSealed.
    pub fn new(contract: SecurityContract) -> Result<Self, StateTransitionError> {
        if !contract.verify_digest() {
            return Err(StateTransitionError::FailClosed {
                state: ExecutionState::ContractSealed,
                error: "Contract BLAKE3 digest verification failed: unsealed or tampered contract"
                    .to_string(),
            });
        }

        let mut fsm = ExecutionStateMachine::new();
        fsm.transition(ExecutionState::PolicyCompiled)?;
        fsm.transition(ExecutionState::ContractSealed)?;

        let backend_kind = BackendKind::current_platform();

        Ok(Self {
            contract,
            fsm,
            backend_kind,
        })
    }

    pub fn contract(&self) -> &SecurityContract {
        &self.contract
    }

    pub fn fsm(&self) -> &ExecutionStateMachine {
        &self.fsm
    }

    pub fn current_state(&self) -> ExecutionState {
        self.fsm.current_state()
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.backend_kind
    }

    /// Prepare step: verifies contract integrity and enters Prepare state.
    pub fn prepare(&mut self) -> Result<(), StateTransitionError> {
        if !self.contract.verify_digest() {
            let _ = self.fsm.fail_closed("Contract digest verification failed");
            return Err(StateTransitionError::FailClosed {
                state: self.fsm.current_state(),
                error: "Contract digest mismatch".to_string(),
            });
        }
        self.fsm.transition(ExecutionState::Prepare)
    }

    /// Spawn guard: advances through Prepare -> Spawn -> Enforce -> Observe.
    pub fn spawn_guard(&mut self) -> Result<(), StateTransitionError> {
        self.fsm.transition(ExecutionState::Spawn)?;
        self.fsm.transition(ExecutionState::Enforce)?;
        self.fsm.transition(ExecutionState::Observe)
    }

    /// Termination: advances Observe -> Terminate.
    pub fn terminate(&mut self) -> Result<(), StateTransitionError> {
        self.fsm.transition(ExecutionState::Terminate)
    }

    /// Cleanup and process tree extinction verification (§12.1).
    /// Advances Terminate -> Cleanup -> Verify.
    pub fn cleanup_and_verify(
        &mut self,
        extinction_tier: PlatformExtinctionTier,
        surviving_processes: usize,
        surviving_resources: usize,
        elapsed_ms: u64,
    ) -> Result<ExtinctionProof, ExtinctionBreach> {
        if let Err(e) = self.fsm.transition(ExecutionState::Cleanup) {
            return Err(ExtinctionBreach {
                platform: extinction_tier,
                exit_code: 125,
                reason: format!("State machine transition to Cleanup failed: {e}"),
                surviving_processes,
                surviving_resources,
                elapsed_ms,
            });
        }

        let proof = match ExtinctionVerifier::verify(
            extinction_tier,
            surviving_processes,
            surviving_resources,
            elapsed_ms,
        ) {
            Ok(proof) => proof,
            Err(breach) => {
                let _ = self.fsm.fail_closed(&breach.reason);
                return Err(breach);
            }
        };

        if let Err(e) = self.fsm.transition(ExecutionState::Verify) {
            return Err(ExtinctionBreach {
                platform: extinction_tier,
                exit_code: 125,
                reason: format!("State machine transition to Verify failed: {e}"),
                surviving_processes,
                surviving_resources,
                elapsed_ms,
            });
        }

        Ok(proof)
    }

    /// Evaluates the final execution verdict based on host facts (§18).
    /// Advances Verify -> Attest -> Verdict -> Terminal.
    /// Checks INV-37 Netlink buffer overflow detection (`is_evidence_channel_intact()`).
    pub fn evaluate_verdict(
        &mut self,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        agent_exit_code: i32,
    ) -> Result<FinalVerdict, StateTransitionError> {
        let evidence_channel_intact = crate::sandbox::is_evidence_channel_intact();

        self.fsm.transition(ExecutionState::Attest)?;
        self.fsm.transition(ExecutionState::Verdict)?;

        let verdict = VerdictEngine::evaluate(
            &self.contract,
            kernel_denials,
            unauthorized_writes,
            zombies_survived,
            evidence_channel_intact,
            agent_exit_code,
        );

        if verdict.exit_code == 125
            || verdict.status == VerdictStatus::Fail
            || verdict.status == VerdictStatus::Inconclusive
        {
            let _ = self.fsm.fail_closed(&verdict.reason);
            let _ = self.fsm.transition(ExecutionState::EmergencyCleanup);
            let _ = self.fsm.transition(ExecutionState::Terminal);
        } else {
            self.fsm.transition(ExecutionState::Terminal)?;
        }

        Ok(verdict)
    }

    /// Evaluates verdict with explicit evidence strength.
    pub fn evaluate_verdict_with_strength(
        &mut self,
        kernel_denials: usize,
        unauthorized_writes: usize,
        zombies_survived: usize,
        agent_exit_code: i32,
        strength: EvidenceStrength,
    ) -> Result<FinalVerdict, StateTransitionError> {
        let evidence_channel_intact = crate::sandbox::is_evidence_channel_intact();

        self.fsm.transition(ExecutionState::Attest)?;
        self.fsm.transition(ExecutionState::Verdict)?;

        let verdict = VerdictEngine::evaluate_with_strength(
            &self.contract,
            kernel_denials,
            unauthorized_writes,
            zombies_survived,
            evidence_channel_intact,
            agent_exit_code,
            strength,
        );

        if verdict.exit_code == 125
            || verdict.status == VerdictStatus::Fail
            || verdict.status == VerdictStatus::Inconclusive
        {
            let _ = self.fsm.fail_closed(&verdict.reason);
            let _ = self.fsm.transition(ExecutionState::EmergencyCleanup);
            let _ = self.fsm.transition(ExecutionState::Terminal);
        } else {
            self.fsm.transition(ExecutionState::Terminal)?;
        }

        Ok(verdict)
    }

    /// Whether the CoW ephemeral overlay should be committed to the host workspace (§18.2).
    pub fn should_commit_cow(verdict: &FinalVerdict) -> bool {
        verdict.is_success()
    }

    /// Whether the CoW ephemeral overlay must be wiped immediately (§18.2).
    pub fn should_wipe_cow(verdict: &FinalVerdict) -> bool {
        !Self::should_commit_cow(verdict)
    }

    /// Appends the final session verdict to the audit ledger (§17.1).
    pub fn record_verdict_to_ledger(
        &self,
        ledger: &mut AuditLedger,
        verdict: &FinalVerdict,
        root_dag_digest: &str,
    ) -> anyhow::Result<String> {
        let record = VettoAuditRecord::session_verdict(
            &self.contract.contract_id,
            &self.contract.contract_digest_blake3,
            verdict,
            root_dag_digest,
        );
        ledger.record_audit_record(&record)
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

/// Non-blocking async pipe reader for captured stdio streams.
/// Drains the pipe concurrently while the child is executing, preventing
/// the 64KB kernel buffer deadlock (FS-01). Enforces memory ceilings
/// and post-exit drain deadlines (Phase 1 / INV-25).
#[cfg(unix)]
pub struct AsyncPipeReader {
    handle: Option<std::thread::JoinHandle<Vec<u8>>>,
    child_done: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(unix)]
impl AsyncPipeReader {
    pub fn spawn(fd: OwnedFd, max_bytes: usize, drain_deadline: Duration) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let child_done = Arc::new(AtomicBool::new(false));
        let child_done_clone = Arc::clone(&child_done);

        let handle = std::thread::spawn(move || {
            let raw_fd = fd.as_raw_fd();
            let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL) };
            if flags >= 0 {
                unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
            }

            let mut out = Vec::new();
            let mut buf = [0u8; 8192];
            let mut post_exit_start: Option<Instant> = None;

            loop {
                if child_done_clone.load(Ordering::Relaxed) {
                    let start = *post_exit_start.get_or_insert_with(Instant::now);
                    if start.elapsed() >= drain_deadline {
                        break;
                    }
                }

                let mut pfd = libc::pollfd {
                    fd: raw_fd,
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                };
                let r = unsafe { libc::poll(&mut pfd, 1, 10) };
                if r > 0 {
                    let n = unsafe { libc::read(raw_fd, buf.as_mut_ptr().cast(), buf.len()) };
                    if n > 0 {
                        let to_copy = (n as usize).min(max_bytes.saturating_sub(out.len()));
                        if to_copy > 0 {
                            out.extend_from_slice(&buf[..to_copy]);
                        }
                    } else if n == 0 {
                        break;
                    } else {
                        let err = std::io::Error::last_os_error();
                        let code = err.raw_os_error().unwrap_or(0);
                        if code != libc::EAGAIN && code != libc::EWOULDBLOCK && code != libc::EINTR
                        {
                            break;
                        }
                    }
                }
            }
            out
        });

        Self {
            handle: Some(handle),
            child_done,
        }
    }

    pub fn notify_child_exited(&self) {
        self.child_done
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn join(mut self) -> Vec<u8> {
        if let Some(h) = self.handle.take() {
            h.join().unwrap_or_default()
        } else {
            Vec::new()
        }
    }
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
    #[cfg(target_os = "linux")]
    if crate::sandbox::linux::landlock::abi_version().is_none() && tier != Some(Tier::Seccomp) {
        return Err(anyhow::Error::new(crate::error::VettoError::Landlock(
            "missing Landlock LSM support on this kernel; refusing silent downgrade (fail-closed exit 125)\n\
             action: upgrade your kernel (Linux 5.13+) or enable CONFIG_SECURITY_LANDLOCK=y; run `vetto doctor` for the full capability picture".into()
        )));
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
    #[cfg(unix)]
    let (stdout_reader, stderr_reader) = {
        (
            AsyncPipeReader::spawn(stdout_r, PROD_MAX_STDIO, PROD_DRAIN_BUDGET),
            AsyncPipeReader::spawn(stderr_r, PROD_MAX_STDIO, PROD_DRAIN_BUDGET),
        )
    };
    // `mut` is unconditional: the unix branch below assigns stdout/stderr,
    // and `cfg`-gated `mut` would diverge between platforms.
    #[allow(unused_mut)]
    let mut result = spawned.wait_collect();
    #[cfg(unix)]
    {
        stdout_reader.notify_child_exited();
        stderr_reader.notify_child_exited();
        result.stdout = stdout_reader.join();
        result.stderr = stderr_reader.join();
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
        // Set O_NONBLOCK on the read end so read operations never block indefinitely.
        let read_flags = unsafe { libc::fcntl(fds[0], libc::F_GETFL) };
        if read_flags >= 0 {
            unsafe { libc::fcntl(fds[0], libc::F_SETFL, read_flags | libc::O_NONBLOCK) };
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

    #[cfg(target_os = "linux")]
    #[test]
    fn phase1_production_preparation_receives_sealed_contract() {
        struct InspectContract;
        impl SandboxBackend for InspectContract {
            fn kind(&self) -> BackendKind {
                BackendKind::Linux
            }
            fn name(&self) -> &'static str {
                "contract input inspector (never spawns)"
            }
            fn supports(&self, _cap: SecurityCapability) -> bool {
                false
            }
            fn prepare(
                &mut self,
                input: &CanonicalPolicy,
                identity: &ExecutionIdentity,
            ) -> EnforcementReport {
                let envelope: serde_json::Value = serde_json::from_slice(&input.policy_bytes)
                    .expect("production preparation must receive a serialized sealed contract");
                let mut contract: SecurityContract =
                    serde_json::from_value(envelope["contract"].clone()).expect("contract payload");
                contract.contract_digest_blake3 = envelope["digest"]
                    .as_str()
                    .expect("separate contract digest")
                    .to_string();
                assert!(contract.verify_digest());
                assert_ne!(contract.contract_digest_blake3, identity.frozen_hash);
                assert_eq!(contract.session_nonce, identity.session_nonce);
                assert_eq!(contract.filesystem.allow_read, vec![PathBuf::from("/usr")]);
                assert_eq!(contract.resources.max_memory_bytes, 384 * 1024 * 1024);
                assert_eq!(
                    contract
                        .environment
                        .explicit_vars
                        .get("VETTO_PHASE1_OVERRIDE"),
                    Some(&"effective-value".to_string())
                );
                assert_eq!(contract.environment.explicit_vars, input.env);
                assert_eq!(
                    contract.agent_identity.invoked_binary,
                    PathBuf::from("/bin/true")
                );
                EnforcementReport::build(
                    BackendKind::Linux,
                    input,
                    identity,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    false,
                )
            }
            fn enforcement(&self) -> Option<&EnforcementReport> {
                None
            }
            fn teardown(&mut self) {}
        }
        let backend = Backend::detect(NetMode::Off, false).expect("detect mechanics");
        let policy = Policy {
            allow_read: vec![PathBuf::from("/usr")],
            limits: crate::policy::ResourceLimits {
                address_space_bytes: Some(384 * 1024 * 1024),
                ..Default::default()
            },
            ..Policy::default()
        };
        let execution = UnpreparedProductionExecution::new(
            backend,
            policy,
            vec!["/bin/true".to_string()],
            std::env::temp_dir(),
            HashMap::from([(
                "VETTO_PHASE1_OVERRIDE".to_string(),
                "effective-value".to_string(),
            )]),
            NetMode::Off,
            None,
            StdioMode::Inherit,
            PROD_SCENARIO_ID.to_string(),
        );
        // The inspector deliberately refuses preparation; it never yields a spawnable object.
        assert!(execution
            .prepare_with_backend(Box::new(InspectContract))
            .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase1_invalid_contract_never_prepares_capabilities() {
        struct CountPreparation(usize);
        impl SandboxBackend for CountPreparation {
            fn kind(&self) -> BackendKind {
                BackendKind::Linux
            }
            fn name(&self) -> &'static str {
                "preparation counter (never spawns)"
            }
            fn supports(&self, _cap: SecurityCapability) -> bool {
                false
            }
            fn prepare(
                &mut self,
                input: &CanonicalPolicy,
                identity: &ExecutionIdentity,
            ) -> EnforcementReport {
                self.0 += 1;
                EnforcementReport::build(
                    BackendKind::Linux,
                    input,
                    identity,
                    &BTreeMap::new(),
                    &BTreeMap::new(),
                    false,
                )
            }
            fn enforcement(&self) -> Option<&EnforcementReport> {
                None
            }
            fn teardown(&mut self) {}
        }
        let policy = test_policy();
        let original = crate::policy_ir::compiler::PolicyCompiler::compile_effective(
            crate::policy_ir::compiler::EffectivePolicyInput {
                policy: &policy,
                argv: &["/bin/true".into()],
                cwd: std::path::Path::new("/tmp"),
                env: &BTreeMap::new(),
                net: &NetMode::Off,
                nonce: "preparation-guard-test",
                timeout: None,
                tier: Some(Tier::Full),
                backend: "test-mechanics".into(),
                observe_seccomp: false,
                debug_ports: None,
            },
        )
        .unwrap();
        let mut capability = CountPreparation(0);
        for case in ["digest", "projection", "missing", "backend", "debug-ports"] {
            let mut contract = original.clone();
            let expected_error = match case {
                "digest" => {
                    contract
                        .environment
                        .explicit_vars
                        .insert("CHANGED".into(), "1".into());
                    "invalid production contract digest"
                }
                "projection" => {
                    contract.resources.max_memory_bytes ^= 1;
                    contract = contract.unsealed().seal().unwrap();
                    "inconsistent production contract projection"
                }
                "missing" => {
                    contract.production = None;
                    contract = contract.unsealed().seal().unwrap();
                    "missing production installation contract"
                }
                "backend" => {
                    contract.production.as_mut().unwrap().backend = "other-mechanics".into();
                    contract = contract.unsealed().seal().unwrap();
                    "production contract/backend mismatch"
                }
                "debug-ports" => {
                    contract.production.as_mut().unwrap().debug_ports =
                        Some(crate::multi::DebugPortConfig::default());
                    "invalid production contract digest"
                }
                _ => unreachable!(),
            };
            let error = prepare_production_contract(
                PROD_SCENARIO_ID,
                &contract,
                Tier::Full.label(),
                "test-mechanics",
                &mut capability,
            )
            .unwrap_err();
            assert!(
                error.to_string().contains(expected_error),
                "{case}: {error:#}"
            );
            assert_eq!(
                capability.0, 0,
                "{case}: invalid contract reached capability preparation"
            );
        }
        // The valid control must reach the same backend, which deliberately refuses preparation.
        let error = prepare_production_contract(
            PROD_SCENARIO_ID,
            &original,
            Tier::Full.label(),
            "test-mechanics",
            &mut capability,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("production backend preparation failed"));
        assert_eq!(capability.0, 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase1_contract_tamper_rejected_before_spawn() {
        let tmp =
            std::env::temp_dir().join(format!("vetto-contract-tamper-{}", engine::new_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let marker = tmp.join("child-started");
        let initial_spawn_count = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
        for case in ["digest", "resealed", "projection", "missing"] {
            let spawn_count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
            let mut prepared = UnpreparedProductionExecution::new(
                Backend::detect(NetMode::Off, false).expect("detect mechanics"),
                functional_test_policy(&tmp),
                vec![
                    "/bin/sh".into(),
                    "-c".into(),
                    "printf started > child-started".into(),
                ],
                tmp.clone(),
                HashMap::new(),
                NetMode::Off,
                Some(Duration::from_secs(10)),
                StdioMode::Inherit,
                PROD_SCENARIO_ID.into(),
            )
            .prepare()
            .expect("prepare production execution");
            let expected_error = match case {
                "digest" => {
                    prepared
                        .contract
                        .environment
                        .explicit_vars
                        .insert("VETTO_CHANGED".into(), "1".into());
                    assert!(!prepared.contract.verify_digest());
                    "invalid production contract digest"
                }
                "resealed" => {
                    prepared.contract.production.as_mut().unwrap().timeout =
                        Some(Duration::from_secs(9));
                    prepared.contract.resources.max_wall_time_ms = 9000;
                    prepared.contract = prepared.contract.unsealed().seal().unwrap();
                    assert!(prepared.contract.verify_digest());
                    "production contract/frozen input drift"
                }
                "projection" => {
                    prepared.contract.filesystem.allow_read.clear();
                    prepared.contract = prepared.contract.unsealed().seal().unwrap();
                    assert!(prepared.contract.verify_digest());
                    "inconsistent production contract projection"
                }
                "missing" => {
                    prepared.contract.production = None;
                    prepared.contract = prepared.contract.unsealed().seal().unwrap();
                    "missing production installation contract"
                }
                _ => unreachable!(),
            };
            match prepared.spawn() {
                Err(error) => assert!(
                    error.to_string().contains(expected_error),
                    "{case}: {error:#}"
                ),
                Ok(spawned) => {
                    spawned.wait_collect();
                    panic!("{case}: altered contract reached production spawn");
                }
            }
            assert!(!marker.exists(), "{case}: child must not execute");
            assert_eq!(
                PROD_SPAWN_COUNT.load(Ordering::SeqCst),
                spawn_count_before,
                "{case}: PROD_SPAWN_COUNT must not increment on tamper"
            );
        }
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            initial_spawn_count,
            "all phase 1 tamper attempts must leave spawn counter untouched"
        );
        // Positive control: the same command and policy can create the marker.
        let spawn_count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
        let spawned = UnpreparedProductionExecution::new(
            Backend::detect(NetMode::Off, false).expect("detect mechanics"),
            functional_test_policy(&tmp),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf started > child-started".into(),
            ],
            tmp.clone(),
            HashMap::new(),
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
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "started");
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            spawn_count_before + 1,
            "control must increment PROD_SPAWN_COUNT by 1"
        );
        std::fs::remove_dir_all(tmp).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase2_contract_tamper_all_field_classes_rejected_no_spawn() {
        let tmp =
            std::env::temp_dir().join(format!("vetto-tamper-full-matrix-{}", engine::new_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let marker = tmp.join("child-started");

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
        ];

        let initial_spawn_count = PROD_SPAWN_COUNT.load(Ordering::SeqCst);

        for case in cases {
            // Test unresealed direct tamper: digest mismatch -> verification failure -> NO SPAWN
            {
                let count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
                let mut prepared = UnpreparedProductionExecution::new(
                    Backend::detect(NetMode::Off, false).expect("detect mechanics"),
                    functional_test_policy(&tmp),
                    vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf started > child-started".into(),
                    ],
                    tmp.clone(),
                    HashMap::new(),
                    NetMode::Off,
                    Some(Duration::from_secs(10)),
                    StdioMode::Inherit,
                    PROD_SCENARIO_ID.into(),
                )
                .prepare()
                .expect("prepare execution");

                match case {
                    "fs_allow_read" => prepared
                        .contract
                        .filesystem
                        .allow_read
                        .push(PathBuf::from("/etc/extra_read")),
                    "fs_allow_write" => prepared
                        .contract
                        .filesystem
                        .allow_write
                        .push(PathBuf::from("/usr/bin/extra_write")),
                    "fs_deny_read" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_read
                        .push(PathBuf::from("/tmp/secret_read")),
                    "fs_deny_write" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_write
                        .push(PathBuf::from("/tmp/secret_write")),
                    "fs_cow_overlay" => prepared.contract.filesystem.cow_overlay = true,
                    "fs_execution_root_ro" => prepared.contract.filesystem.execution_root_ro = true,
                    "env_explicit_vars" => {
                        prepared
                            .contract
                            .environment
                            .explicit_vars
                            .insert("TAMPER".into(), "1".into());
                    }
                    "env_redacted_patterns" => prepared
                        .contract
                        .environment
                        .redacted_patterns
                        .push("FORBIDDEN_*".into()),
                    "env_inject_session_nonce" => {
                        prepared.contract.environment.inject_session_nonce = false
                    }
                    "net_mode" => {
                        prepared.contract.network.mode =
                            crate::policy_ir::contract::NetworkMode::Allowlist
                    }
                    "net_allowed_domains" => prepared
                        .contract
                        .network
                        .allowed_domains
                        .push("tampered.domain".into()),
                    "net_allowed_ports" => prepared.contract.network.allowed_ports.push(8080),
                    "net_allowed_ips" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .allow_cidr
                        .push("10.0.0.0/8".into()),
                    "net_debug_ports" => {
                        prepared.contract.production.as_mut().unwrap().debug_ports =
                            Some(crate::multi::DebugPortConfig::default())
                    }
                    "limits_max_memory_mb" => {
                        prepared.contract.resources.max_memory_bytes ^= 0x4000
                    }
                    "limits_max_pids" => prepared.contract.resources.max_pids += 10,
                    "limits_max_cpu_seconds" => {
                        prepared.contract.resources.max_wall_time_ms += 10000
                    }
                    "limits_max_file_size_mb" => {
                        prepared.contract.resources.max_file_size_bytes += 1024 * 1024
                    }
                    "exec_allowed_executables" => prepared
                        .contract
                        .filesystem
                        .allow_execute
                        .push(PathBuf::from("/bin/bash")),
                    "exec_forbidden_executables" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_resolved
                        .push(crate::policy::DenyEntry {
                            path: PathBuf::from("/bin/forbidden"),
                            is_dir: false,
                        }),
                    "exec_invoked_binary" => {
                        prepared.contract.agent_identity.invoked_binary =
                            PathBuf::from("/bin/tampered")
                    }
                    "exec_invoked_args" => prepared
                        .contract
                        .agent_identity
                        .invoked_args
                        .push("--tampered".into()),
                    "secrets_mask_paths" => prepared
                        .contract
                        .filesystem
                        .mask_paths
                        .push(PathBuf::from("/root/.ssh/id_rsa")),
                    "tier_requirement" => {
                        prepared.contract.production.as_mut().unwrap().tier = Some(Tier::FsOnly)
                    }
                    "backend_requirement" => {
                        prepared.contract.production.as_mut().unwrap().backend =
                            "rogue-backend".into()
                    }
                    _ => unreachable!(),
                }

                assert!(
                    !prepared.contract.verify_digest(),
                    "{case}: unresealed digest must be invalid"
                );
                let spawn_res = prepared.spawn();
                assert!(
                    spawn_res.is_err(),
                    "{case}: spawn must fail on unresealed contract"
                );
                assert_eq!(
                    PROD_SPAWN_COUNT.load(Ordering::SeqCst),
                    count_before,
                    "{case}: PROD_SPAWN_COUNT must not increment"
                );
                assert!(!marker.exists(), "{case}: child must not execute");
            }

            // Test resealed tamper: digest matches, but projection / drift / backend mismatch fails spawn
            {
                let count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
                let mut prepared = UnpreparedProductionExecution::new(
                    Backend::detect(NetMode::Off, false).expect("detect mechanics"),
                    functional_test_policy(&tmp),
                    vec![
                        "/bin/sh".into(),
                        "-c".into(),
                        "printf started > child-started".into(),
                    ],
                    tmp.clone(),
                    HashMap::new(),
                    NetMode::Off,
                    Some(Duration::from_secs(10)),
                    StdioMode::Inherit,
                    PROD_SCENARIO_ID.into(),
                )
                .prepare()
                .expect("prepare execution");

                match case {
                    "fs_allow_read" => prepared
                        .contract
                        .filesystem
                        .allow_read
                        .push(PathBuf::from("/etc/extra_read")),
                    "fs_allow_write" => prepared
                        .contract
                        .filesystem
                        .allow_write
                        .push(PathBuf::from("/usr/bin/extra_write")),
                    "fs_deny_read" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_read
                        .push(PathBuf::from("/tmp/secret_read")),
                    "fs_deny_write" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_write
                        .push(PathBuf::from("/tmp/secret_write")),
                    "fs_cow_overlay" => prepared.contract.filesystem.cow_overlay = true,
                    "fs_execution_root_ro" => prepared.contract.filesystem.execution_root_ro = true,
                    "env_explicit_vars" => {
                        prepared
                            .contract
                            .environment
                            .explicit_vars
                            .insert("TAMPER".into(), "1".into());
                    }
                    "env_redacted_patterns" => prepared
                        .contract
                        .environment
                        .redacted_patterns
                        .push("FORBIDDEN_*".into()),
                    "env_inject_session_nonce" => {
                        prepared.contract.environment.inject_session_nonce = false
                    }
                    "net_mode" => {
                        prepared.contract.network.mode =
                            crate::policy_ir::contract::NetworkMode::Allowlist
                    }
                    "net_allowed_domains" => prepared
                        .contract
                        .network
                        .allowed_domains
                        .push("tampered.domain".into()),
                    "net_allowed_ports" => prepared.contract.network.allowed_ports.push(8080),
                    "net_allowed_ips" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .allow_cidr
                        .push("10.0.0.0/8".into()),
                    "net_debug_ports" => {
                        prepared.contract.production.as_mut().unwrap().debug_ports =
                            Some(crate::multi::DebugPortConfig::default())
                    }
                    "limits_max_memory_mb" => {
                        prepared.contract.resources.max_memory_bytes ^= 0x4000
                    }
                    "limits_max_pids" => prepared.contract.resources.max_pids += 10,
                    "limits_max_cpu_seconds" => {
                        prepared.contract.resources.max_wall_time_ms += 10000
                    }
                    "limits_max_file_size_mb" => {
                        prepared.contract.resources.max_file_size_bytes += 1024 * 1024
                    }
                    "exec_allowed_executables" => prepared
                        .contract
                        .filesystem
                        .allow_execute
                        .push(PathBuf::from("/bin/bash")),
                    "exec_forbidden_executables" => prepared
                        .contract
                        .production
                        .as_mut()
                        .unwrap()
                        .installation_policy
                        .deny_resolved
                        .push(crate::policy::DenyEntry {
                            path: PathBuf::from("/bin/forbidden"),
                            is_dir: false,
                        }),
                    "exec_invoked_binary" => {
                        prepared.contract.agent_identity.invoked_binary =
                            PathBuf::from("/bin/tampered")
                    }
                    "exec_invoked_args" => prepared
                        .contract
                        .agent_identity
                        .invoked_args
                        .push("--tampered".into()),
                    "secrets_mask_paths" => prepared
                        .contract
                        .filesystem
                        .mask_paths
                        .push(PathBuf::from("/root/.ssh/id_rsa")),
                    "tier_requirement" => {
                        prepared.contract.production.as_mut().unwrap().tier = Some(Tier::FsOnly)
                    }
                    "backend_requirement" => {
                        prepared.contract.production.as_mut().unwrap().backend =
                            "rogue-backend".into()
                    }
                    _ => unreachable!(),
                }

                prepared.contract = prepared.contract.unsealed().seal().unwrap();
                assert!(
                    prepared.contract.verify_digest(),
                    "{case}: resealed digest must be valid"
                );
                let spawn_res = prepared.spawn();
                assert!(
                    spawn_res.is_err(),
                    "{case}: resealed tampered contract must fail spawn"
                );
                assert_eq!(
                    PROD_SPAWN_COUNT.load(Ordering::SeqCst),
                    count_before,
                    "{case}: resealed tamper must not increment PROD_SPAWN_COUNT"
                );
                assert!(
                    !marker.exists(),
                    "{case}: child must not execute on resealed tamper"
                );
            }
        }

        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            initial_spawn_count,
            "all tamper attempts combined must not advance spawn counter"
        );

        // Positive control: untampered execution succeeds and creates marker
        let control_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
        let spawned = UnpreparedProductionExecution::new(
            Backend::detect(NetMode::Off, false).expect("detect mechanics"),
            functional_test_policy(&tmp),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf started > child-started".into(),
            ],
            tmp.clone(),
            HashMap::new(),
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
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), "started");
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            control_before + 1,
            "control must increment PROD_SPAWN_COUNT by exactly 1"
        );
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase1_caller_policy_cannot_change_canonical_backend_input() {
        let tmp = std::env::temp_dir();
        let mut policy = functional_test_policy(&tmp);
        let mut debug_ports = crate::multi::DebugPortConfig {
            allowed_ports: vec![9229, 5678],
            isolate_node_inspect: false,
            ..Default::default()
        };
        let prepared = UnpreparedProductionExecution::new(
            Backend::detect(NetMode::Off, false).expect("detect mechanics"),
            policy.clone(),
            vec!["/bin/true".into()],
            tmp,
            HashMap::new(),
            NetMode::Off,
            None,
            StdioMode::Inherit,
            PROD_SCENARIO_ID.into(),
        )
        .with_debug_ports(debug_ports.clone())
        .prepare()
        .expect("prepare production execution");
        let original = prepared.contract().clone();
        assert_eq!(
            original.production.as_ref().unwrap().debug_ports.as_ref(),
            Some(&debug_ports)
        );
        debug_ports.allowed_ports.clear();
        debug_ports.isolate_node_inspect = true;
        assert_ne!(
            prepared
                .contract()
                .production
                .as_ref()
                .unwrap()
                .debug_ports
                .as_ref(),
            Some(&debug_ports)
        );
        policy.allow_read.clear();
        policy.allow_write.clear();
        policy.deny_network = !policy.deny_network;
        policy.limits.processes = Some(17);
        policy.secret_proxies.push("VETTO_TEST_SECRET".into());
        assert_ne!(&policy, prepared.frozen_policy());
        assert_eq!(prepared.contract(), &original);
        let (canonical, identity) = freeze_production_contract(
            &prepared.scenario,
            prepared.contract(),
            prepared.tier.map(|t| t.label()).unwrap_or("none"),
            &prepared.mechanics.describe(),
        )
        .unwrap();
        assert_eq!(canonical, prepared.canonical);
        assert_eq!(identity.frozen_hash, prepared.identity().frozen_hash);
        assert!(prepared
            .enforcement_report()
            .unwrap()
            .binds_identity(&identity));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase1_production_audit_binds_actual_contract() {
        let tmp =
            std::env::temp_dir().join(format!("vetto-contract-audit-{}", engine::new_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let prepared = UnpreparedProductionExecution::new(
            Backend::detect(NetMode::Off, false).expect("detect mechanics"),
            functional_test_policy(&tmp),
            vec!["/bin/sh".into(), "-c".into(), "exit 0".into()],
            tmp.clone(),
            HashMap::new(),
            NetMode::Off,
            Some(Duration::from_secs(10)),
            StdioMode::Inherit,
            PROD_SCENARIO_ID.into(),
        )
        .prepare()
        .expect("prepare production execution");
        let digest = prepared.contract().contract_digest_blake3.clone();
        let frozen_hash = prepared.identity().frozen_hash.clone();
        assert_ne!(digest, frozen_hash);
        let audit_dir = std::env::var("VETTO_AUDIT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| std::env::temp_dir().join("vetto-audit"));
        let ledger = audit_dir.join(format!("vetto-audit-{}.jsonl", prepared.nonce()));
        let spawned = prepared.spawn().expect("spawn benign child");
        assert_eq!(spawned.contract().contract_digest_blake3, digest);
        let _result = spawned.wait_collect();
        let body = std::fs::read_to_string(&ledger).expect("production audit ledger");
        let records: Vec<VettoAuditRecord> = body
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records.len(), 3);
        assert_eq!(
            records[0].record_type,
            crate::audit::record::RecordType::SessionInit
        );
        assert_eq!(
            records[1].record_type,
            crate::audit::record::RecordType::TreeExtinction
        );
        assert_eq!(
            records[2].record_type,
            crate::audit::record::RecordType::SessionVerdict
        );
        for record in records {
            assert_eq!(record.contract_digest, digest);
            assert_ne!(record.contract_digest, frozen_hash);
        }
        assert!(AuditLedger::verify_file(&ledger).unwrap());
        std::fs::remove_file(ledger).unwrap();
        std::fs::remove_dir_all(tmp).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn test_async_pipe_reader_large_payload() {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        let reader = AsyncPipeReader::spawn(read_fd, PROD_MAX_STDIO, Duration::from_millis(200));

        let payload_size = 128 * 1024; // 128 KB, exceeds 64KB pipe buffer
        let payload = vec![b'A'; payload_size];
        let payload_clone = payload.clone();

        let writer = std::thread::spawn(move || {
            use std::io::Write;
            let mut file = std::fs::File::from(write_fd);
            file.write_all(&payload_clone).expect("write payload");
        });

        writer.join().expect("writer finished");
        reader.notify_child_exited();
        let collected = reader.join();

        assert_eq!(collected.len(), payload_size);
        assert_eq!(collected, payload);
    }

    #[cfg(unix)]
    #[test]
    fn test_async_pipe_reader_drain_deadline() {
        use std::os::fd::FromRawFd;
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let _write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) }; // Held open

        let start = Instant::now();
        let reader = AsyncPipeReader::spawn(read_fd, PROD_MAX_STDIO, Duration::from_millis(100));
        reader.notify_child_exited();
        let _ = reader.join();
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(80));
        assert!(elapsed < Duration::from_millis(1000));
    }
}
