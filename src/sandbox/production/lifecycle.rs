//! Authoritative production execution boundary lifecycle and Typestate FSM.
//!
//! Typestate progression:
//! UnpreparedProductionExecution -> PreparedProductionExecution -> SpawnedProductionExecution

use std::collections::{BTreeMap, HashMap};
#[cfg(unix)]
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use crate::audit::record::{TierClassification, VettoAuditRecord};
use crate::audit::verdict::{EvidenceStrength, FinalVerdict, VerdictStatus};
use crate::config::NetMode;
use crate::crypto::attest::AuditLedger;
use crate::policy::{Policy, Tier};
use crate::policy_ir::{
    ExecutionState, ExecutionStateMachine, SecurityContract, StateTransitionError,
};
use crate::proctree::{
    ExtinctionVerifier, PlatformExtinctionTier, FAIL_CLOSED_EXTINCTION_EXIT_CODE,
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

use super::context::ProductionSessionContext;
use super::drain::StreamCollector;
use super::error::ProductionError;
use super::signals::{EscalationPolicy, ScopedSignalForwarder, SignalTarget};
use super::{
    ProdSpawnEvent, ProductionResult, PROD_EXIT_POLL, PROD_NONCE_ENV, PROD_REGISTRY, RUN_NONCE_ENV,
};

pub type UnpreparedExecution = UnpreparedProductionExecution;
pub type PreparedExecution = PreparedProductionExecution;
pub type SpawnedExecution = SpawnedProductionExecution;

/// Frozen snapshot of every spawn input, for policy-drift verification.
#[derive(Debug, Clone)]
pub struct FrozenProductionInputs {
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub tier: Option<Tier>,
    pub net_label: String,
    pub stdio_captured: bool,
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

/// Project a verified production contract into the existing capability API.
pub fn freeze_production_contract(
    scenario: &str,
    contract: &SecurityContract,
    tier: &str,
    backend: &str,
) -> Result<(CanonicalPolicy, ExecutionIdentity), ProductionError> {
    if !contract.verify_digest() {
        return Err(ProductionError::ContractDigestMismatch);
    }
    let production = contract.production.as_ref().ok_or_else(|| {
        ProductionError::ContractDrift("missing production installation contract".into())
    })?;
    if production.backend != backend
        || production.tier.map(|t| t.label()).unwrap_or("none") != tier
    {
        return Err(ProductionError::ContractDrift(
            "production contract/backend mismatch".into(),
        ));
    }
    let mut argv = vec![contract
        .agent_identity
        .invoked_binary
        .to_str()
        .ok_or_else(|| {
            ProductionError::PreparationFailed("non-UTF8 production executable".into())
        })?
        .to_string()];
    argv.extend(contract.agent_identity.invoked_args.clone());

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
    )
    .map_err(|e| ProductionError::PreparationFailed(e.to_string()))?;

    if expected != *contract {
        return Err(ProductionError::ContractDrift(
            "inconsistent production contract projection".into(),
        ));
    }

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
    }))
    .map_err(|e| ProductionError::PreparationFailed(e.to_string()))?;

    let canonical = CanonicalPolicy::from_frozen(&spec);
    let identity =
        ExecutionIdentity::new(scenario, &contract.session_nonce, PROD_REGISTRY, &spec.hash());
    Ok((canonical, identity))
}

pub fn prepare_production_contract(
    scenario: &str,
    contract: &SecurityContract,
    tier: &str,
    backend: &str,
    capability: &mut dyn SandboxBackend,
) -> Result<(CanonicalPolicy, ExecutionIdentity), ProductionError> {
    let (canonical, identity) = freeze_production_contract(scenario, contract, tier, backend)?;
    capability.prepare_with_context(&canonical, &identity, &PrepareContext::default());
    let prepared_ok = capability
        .enforcement()
        .map(|r| r.preparation_ok && r.binds_identity(&identity))
        .unwrap_or(false);
    if !prepared_ok {
        return Err(ProductionError::PreparationFailed(
            "production backend preparation failed (fail-closed, no agent execution)".into(),
        ));
    }
    Ok((canonical, identity))
}

/// Unprepared production execution: OWNED frozen inputs, NO spawn method.
pub struct UnpreparedProductionExecution {
    pub context: ProductionSessionContext,
    pub mechanics: Backend,
    pub policy: Policy,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env_extra: HashMap<String, String>,
    pub net: NetMode,
    pub tier: Option<Tier>,
    pub timeout: Option<Duration>,
    pub stdio: StdioMode,
    pub scenario: String,
    pub debug_ports: Option<crate::policy_ir::contract::DebugPortConfig>,
}

impl UnpreparedProductionExecution {
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
        Self {
            context: ProductionSessionContext::new(scenario.clone()),
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

    pub fn with_context(mut self, context: ProductionSessionContext) -> Self {
        self.context = context;
        self
    }

    pub fn with_debug_ports(
        mut self,
        config: crate::policy_ir::contract::DebugPortConfig,
    ) -> Self {
        self.debug_ports = Some(config);
        self
    }

    pub fn tier(&self) -> Option<Tier> {
        self.tier
    }

    pub fn prepare(self) -> Result<PreparedProductionExecution, ProductionError> {
        let mut backend = select_backend(BackendKind::current_platform());
        let tier = self.tier;
        let mut prepared = self.prepare_with_backend_inner(&mut *backend)?;
        backend.restrict_tier(tier);
        prepared.capability = backend;
        Ok(prepared)
    }

    pub fn prepare_with_backend(
        self,
        mut capability: Box<dyn SandboxBackend>,
    ) -> Result<PreparedProductionExecution, ProductionError> {
        let tier = self.tier;
        let mut prepared = self.prepare_with_backend_inner(&mut *capability)?;
        capability.restrict_tier(tier);
        prepared.capability = capability;
        Ok(prepared)
    }

    fn prepare_with_backend_inner(
        self,
        capability: &mut dyn SandboxBackend,
    ) -> Result<PreparedProductionExecution, ProductionError> {
        self.context.metrics.record_backend_entered();

        if self.argv.is_empty() {
            return Err(ProductionError::PreparationFailed(
                "no production command provided".into(),
            ));
        }
        #[cfg(target_os = "macos")]
        if self.net.uses_relay() && !matches!(self.net, NetMode::Allowlist(_)) {
            return Err(ProductionError::PreparationFailed(format!(
                "production backend preparation failed (fail-closed, no agent execution): \
                 --net={} requires the Linux network-namespace relay and is unavailable on macOS; \
                 refusing silently-weaker enforcement (fail-closed); run with `--net=off` or `--net=allowlist` on macOS",
                self.net.label()
            )));
        }
        #[cfg(target_os = "linux")]
        if self.net.uses_relay()
            && matches!(
                self.mechanics.tier(),
                Some(Tier::FsOnly) | Some(Tier::Seccomp)
            )
        {
            return Err(ProductionError::PreparationFailed(
                "network relay modes require Tier FULL; refusing to run (fail-closed)".into(),
            ));
        }

        let tier = self.tier;
        let tier_label = tier
            .map(|t| t.label().to_string())
            .unwrap_or_else(|| "none".to_string());

        let nonce = engine::new_nonce();
        let mut env_extra = self.env_extra;
        env_extra.insert(PROD_NONCE_ENV.to_string(), nonce.clone());
        env_extra.insert(RUN_NONCE_ENV.to_string(), nonce.clone());
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
        )
        .map_err(|e| ProductionError::PreparationFailed(e.to_string()))?;

        fsm.transition(ExecutionState::PolicyCompiled)
            .map_err(|_| ProductionError::InvalidState {
                expected: ExecutionState::PolicyCompiled,
                actual: fsm.current_state(),
            })?;

        if !contract.verify_digest() {
            return Err(ProductionError::ContractDigestMismatch);
        }

        fsm.transition(ExecutionState::ContractSealed)
            .map_err(|_| ProductionError::InvalidState {
                expected: ExecutionState::ContractSealed,
                actual: fsm.current_state(),
            })?;

        let (canonical, identity) = prepare_production_contract(
            &self.scenario,
            &contract,
            &tier_label,
            &self.mechanics.describe(),
            capability,
        )?;

        fsm.transition(ExecutionState::Prepare)
            .map_err(|_| ProductionError::InvalidState {
                expected: ExecutionState::Prepare,
                actual: fsm.current_state(),
            })?;

        Ok(PreparedProductionExecution {
            context: self.context,
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
            capability: select_backend(BackendKind::Direct),
        })
    }
}

/// Prepared production execution: the Stage 3B capability backend is
/// prepared against the frozen bundle, and the legacy mechanics object that
/// will perform the spawn is owned here.
pub struct PreparedProductionExecution {
    pub context: ProductionSessionContext,
    pub mechanics: Backend,
    pub contract: SecurityContract,
    pub canonical: CanonicalPolicy,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub env: BTreeMap<String, String>,
    pub net: NetMode,
    pub tier: Option<Tier>,
    pub timeout: Option<Duration>,
    pub stdio: StdioMode,
    pub scenario: String,
    pub nonce: String,
    pub identity: ExecutionIdentity,
    pub fsm: ExecutionStateMachine,
    pub capability: Box<dyn SandboxBackend>,
}

impl PreparedProductionExecution {
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn backend_kind(&self) -> BackendKind {
        self.capability.kind()
    }

    pub fn enforcement_report(&self) -> Option<&EnforcementReport> {
        self.capability.enforcement()
    }

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

    pub fn spawn(mut self) -> Result<SpawnedProductionExecution, ProductionError> {
        if self.fsm.current_state() != ExecutionState::Prepare {
            return Err(ProductionError::InvalidState {
                expected: ExecutionState::Prepare,
                actual: self.fsm.current_state(),
            });
        }

        let tier_label = self.tier.map(|t| t.label()).unwrap_or("none");
        let (canonical, identity) = freeze_production_contract(
            &self.scenario,
            &self.contract,
            tier_label,
            &self.mechanics.describe(),
        )?;

        let production = self.contract.production.as_ref().ok_or_else(|| {
            ProductionError::ContractDrift("missing production installation contract".into())
        })?;

        if canonical != self.canonical
            || identity.frozen_hash != self.identity.frozen_hash
            || canonical.argv != self.argv
            || canonical.cwd != self.cwd
            || canonical.env != self.env
            || production.net != self.net
            || production.timeout != self.timeout
            || production.tier != self.tier
            || production.observe_seccomp != self.mechanics.observes_seccomp()
        {
            return Err(ProductionError::ContractDrift(
                "production contract/frozen input drift (fail-closed, no agent execution)".into(),
            ));
        }

        if self.mechanics.net_label() != self.net.label() {
            return Err(ProductionError::ContractDrift(
                "production net drift (fail-closed, no agent execution)".into(),
            ));
        }

        #[cfg(target_os = "linux")]
        if let Some(plan) = self.capability.pre_exec_plan() {
            if plan.net_deny != matches!(self.net, NetMode::Off) {
                return Err(ProductionError::ContractDrift(
                    "production plan/net drift (fail-closed, no agent execution)".into(),
                ));
            }
            if !plan.new_pgroup {
                return Err(ProductionError::ContractDrift(
                    "production plan lost process-group containment (fail-closed)".into(),
                ));
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

        let policy = &production.installation_policy;
        let spawned = {
            let _serial = engine::spawn_serial()
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            self.fsm
                .transition(ExecutionState::Spawn)
                .map_err(|_| ProductionError::InvalidState {
                    expected: ExecutionState::Spawn,
                    actual: self.fsm.current_state(),
                })?;
            self.mechanics
                .spawn(policy, opts)
                .map_err(|e| ProductionError::SpawnFailed(e.to_string()))?
        };

        self.fsm
            .transition(ExecutionState::Enforce)
            .map_err(|_| ProductionError::InvalidState {
                expected: ExecutionState::Enforce,
                actual: self.fsm.current_state(),
            })?;

        self.context.metrics.record_spawn();
        let pid = spawned.handle.root_pid;
        self.context.signals.target_pid.store(pid as i32, Ordering::SeqCst);
        crate::sandbox::handle::register_active_root(pid);
        self.capability.note_spawned(pid);

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

        #[cfg(target_os = "linux")]
        {
            use crate::verify_ng::linux_enforce as le;
            let mut verification = le::verify_child_host(pid);
            if let Ok(limits_body) = std::fs::read_to_string(format!("/proc/{pid}/limits")) {
                let lim = &policy.limits;
                let expect = |row: &str, v: Option<u64>| match v {
                    Some(x) => le::limits_field_is(&limits_body, row, x),
                    None => false,
                };
                verification.rlimit_as_ok =
                    expect("Max address space", lim.address_space_bytes);
                verification.rlimit_nproc_ok = expect("Max processes", lim.processes);
                verification.rlimit_cpu_ok = expect("Max cpu time", lim.cpu_seconds);
                verification.rlimit_fsize_ok = expect("Max file size", lim.file_size_bytes);
            }
            self.capability.note_host_verified(&verification);
        }

        #[cfg(target_os = "macos")]
        {
            let verification = crate::sandbox::macos::prod_verify::verify_child_host(pid);
            self.capability.note_host_verified(&verification);
        }

        let forwarder = ScopedSignalForwarder::install(
            self.context.clone(),
            SignalTarget::Process(pid),
            EscalationPolicy::default(),
        )
        .ok();

        self.fsm
            .transition(ExecutionState::Observe)
            .map_err(|_| ProductionError::InvalidState {
                expected: ExecutionState::Observe,
                actual: self.fsm.current_state(),
            })?;

        Ok(SpawnedProductionExecution {
            context: self.context,
            contract: self.contract,
            handle: spawned.handle,
            #[cfg(unix)]
            broker_ctrl_fd: spawned.broker_ctrl_fd,
            #[cfg(unix)]
            relay_port: spawned.relay_port,
            #[cfg(unix)]
            notif_listener: spawned.notif_listener,
            pid,
            nonce: self.nonce,
            identity: self.identity,
            exec_root: self.cwd,
            scenario: self.scenario,
            timeout: self.timeout,
            capability: self.capability,
            fsm: self.fsm,
            collector: None,
            signals: forwarder,
        })
    }
}

/// Spawned production execution: real agent child plus supervision state.
pub struct SpawnedProductionExecution {
    pub context: ProductionSessionContext,
    pub contract: SecurityContract,
    pub handle: SandboxHandle,
    #[cfg(unix)]
    pub broker_ctrl_fd: Option<OwnedFd>,
    #[cfg(unix)]
    pub relay_port: Option<u16>,
    #[cfg(unix)]
    pub notif_listener: Option<OwnedFd>,
    pub pid: u32,
    pub nonce: String,
    pub identity: ExecutionIdentity,
    pub exec_root: PathBuf,
    pub scenario: String,
    pub timeout: Option<Duration>,
    pub capability: Box<dyn SandboxBackend>,
    pub fsm: ExecutionStateMachine,
    /// Optional stdio stream collector.
    /// When attached (via `with_collector`), streams are drained and joined on finish().
    /// When None, stdio drainage is managed externally (e.g. by supervise::pump
    /// or caller-owned AsyncPipeReader).
    pub collector: Option<StreamCollector>,
    pub signals: Option<ScopedSignalForwarder>,
}

impl SpawnedProductionExecution {
    /// Attach an optional stdio StreamCollector to be drained and joined on finish().
    pub fn with_collector(mut self, collector: StreamCollector) -> Self {
        self.collector = Some(collector);
        self
    }
    pub fn contract(&self) -> &SecurityContract {
        &self.contract
    }

    pub fn fsm(&self) -> &ExecutionStateMachine {
        &self.fsm
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }

    pub fn event(&self) -> ProdSpawnEvent {
        ProdSpawnEvent {
            run_id: self.nonce.clone(),
            pid: self.pid,
        }
    }

    pub fn enforcement_report(&self) -> Option<&EnforcementReport> {
        self.capability.enforcement()
    }

    #[cfg(unix)]
    pub fn take_broker_ctrl_fd(&mut self) -> Option<OwnedFd> {
        self.broker_ctrl_fd.take()
    }

    #[cfg(unix)]
    pub fn relay_port(&self) -> Option<u16> {
        self.relay_port
    }

    #[cfg(unix)]
    pub fn take_notif_listener(&mut self) -> Option<OwnedFd> {
        self.notif_listener.take()
    }

    pub fn wait_collect(mut self) -> ProductionResult {
        let timeout = self.timeout;
        let (exit_code, timed_out) = wait_for_exit(&mut self.handle, timeout);
        self.finish(Some(exit_code), timed_out)
    }

    pub fn finish(mut self, exit_code: Option<i32>, timed_out: bool) -> ProductionResult {
        let (stdout_bytes, stderr_bytes, _, _) = if let Some(c) = self.collector.take() {
            c.finish()
        } else {
            (Vec::new(), Vec::new(), false, false)
        };

        if self.fsm.current_state() == ExecutionState::Enforce {
            if let Err(e) = self.fsm.transition(ExecutionState::Observe) {
                self.capability
                    .note_diagnostic(format!("FSM transition Enforce->Observe failed: {e}"));
            }
        }
        if self.fsm.current_state() == ExecutionState::Observe {
            if let Err(e) = self.fsm.transition(ExecutionState::Terminate) {
                self.capability
                    .note_diagnostic(format!("FSM transition Observe->Terminate failed: {e}"));
            }
        }
        if self.fsm.current_state() == ExecutionState::Terminate {
            if let Err(e) = self.fsm.transition(ExecutionState::Cleanup) {
                self.capability
                    .note_diagnostic(format!("FSM transition Terminate->Cleanup failed: {e}"));
            }
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

        #[cfg(target_os = "windows")]
        {
            use crate::proctree::MAX_EXTINCTION_DEADLINE_MS;
            use crate::verify_ng::windows_enforce as we;
            let members = match self.handle.windows_raw_handles() {
                Some((_, job)) => unsafe { we::job_assigned_pids(job) },
                None => Vec::new(),
            };
            let observed = members.len();
            let _ = self.handle.terminate();
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
        let setsid_orphan_escaped = if matches!(
            self.handle.strategy,
            Some(crate::sandbox::handle::KillStrategy::ProcessGroup { sweep: true, .. })
        ) && exit_code.unwrap_or(0) == 0
        {
            let me = unsafe { libc::getpid() } as u32;
            let my_sid = crate::sandbox::linux::proctrack::session_of(0);
            let needle_run = format!("VETTO_RUN_NONCE={}", self.nonce);
            let needle_prod = format!("VETTO_PROD_NONCE={}", self.nonce);
            let deadline = Instant::now() + Duration::from_millis(250);
            let mut escaped = false;
            loop {
                let children =
                    crate::sandbox::linux::proctrack::scan_children(me, self.pid as i32);
                let found = children.iter().any(|&pid| {
                    if let Ok(st) = std::fs::read_to_string(format!("/proc/{pid}/status")) {
                        if let Some(rest) = st
                            .lines()
                            .find_map(|l| l.trim_start().strip_prefix("State:"))
                        {
                            let s = rest.trim_start();
                            if s.starts_with('Z') || s.starts_with('X') {
                                return false;
                            }
                        }
                    } else {
                        return false;
                    }
                    if match (my_sid, crate::sandbox::linux::proctrack::session_of(pid)) {
                        (Some(mine), Some(theirs)) => mine != theirs,
                        _ => false,
                    } {
                        if let Ok(env) = std::fs::read(format!("/proc/{pid}/environ")) {
                            crate::verify_ng::linux_enforce::contains_slice(
                                &env,
                                needle_run.as_bytes(),
                            ) || crate::verify_ng::linux_enforce::contains_slice(
                                &env,
                                needle_prod.as_bytes(),
                            )
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });
                if found {
                    escaped = true;
                    break;
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            escaped
        } else {
            false
        };

        #[cfg(target_os = "linux")]
        {
            if let Some(sweep) =
                crate::verify_ng::linux_enforce::sweep_tree_by_nonce(self.nonce.as_str(), self.pid)
            {
                let clean = sweep.clean && !sweep.blind && sweep.residual.is_empty();
                surviving_processes = if clean {
                    0
                } else {
                    sweep.residual.len().max(1)
                };
                self.capability.note_tree_clean(clean);
                self.capability.note_diagnostic(format!(
                    "tree-sweep clean={} killed={} residual={:?} subreaper={} blind={}",
                    clean, sweep.killed, sweep.residual, sweep.subreaper, sweep.blind
                ));
            } else {
                surviving_processes = 1;
                self.capability.note_tree_clean(false);
            }
        }

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

        let extinction_res = ExtinctionVerifier::verify(
            extinction_platform,
            surviving_processes,
            surviving_resources,
            elapsed_ms,
        );

        self.fsm.record_extinction_result(surviving_processes);

        let mut final_exit_code = exit_code;
        if timed_out && surviving_processes == 0 && extinction_res.is_ok() {
            final_exit_code = Some(124);
        }

        #[cfg(target_os = "linux")]
        if setsid_orphan_escaped && final_exit_code.unwrap_or(0) == 0 {
            self.capability.note_diagnostic(
                "setsid escaper swept in fs-only: containment gap forces fail-closed exit 125"
                    .to_string(),
            );
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        }

        if let Err(ref breach) = extinction_res {
            self.capability.note_tree_clean(false);
            self.capability.note_diagnostic(format!(
                "extinction breach (fail-closed exit 125, INV-20): platform={} elapsed={}ms reason={}",
                breach.platform.label(),
                breach.elapsed_ms,
                breach.reason
            ));
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
            let fsm_err = self.fsm.fail_closed(&breach.reason);
            if matches!(fsm_err, StateTransitionError::InvalidTransition { .. }) {
                self.capability
                    .note_diagnostic(format!("FSM transition to FailClosed failed: {fsm_err}"));
            }
            if let Err(e) = self.fsm.transition(ExecutionState::EmergencyCleanup) {
                self.capability
                    .note_diagnostic(format!("FSM transition to EmergencyCleanup failed: {e}"));
            }
        } else {
            if let Err(e) = self.fsm.transition(ExecutionState::Verify) {
                self.capability
                    .note_diagnostic(format!("FSM transition to Verify failed: {e}"));
            }
        }

        let evidence_intact = crate::sandbox::is_evidence_channel_intact()
            && self.context.evidence.channel_intact.load(Ordering::SeqCst);
        if !evidence_intact {
            self.capability.note_tree_clean(false);
            self.capability.note_diagnostic(
                "evidence channel disrupted (ENOBUFS / packet drop, INV-37): fail-closed exit 125"
                    .to_string(),
            );
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        }

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
        if self.fsm.current_state() == ExecutionState::Verify {
            if let Err(e) = self.fsm.transition(ExecutionState::Attest) {
                self.capability
                    .note_diagnostic(format!("FSM transition to Attest failed: {e}"));
            }
        }
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

        if self.fsm.current_state() == ExecutionState::Attest {
            if let Err(e) = self.fsm.transition(ExecutionState::Verdict) {
                self.capability
                    .note_diagnostic(format!("FSM transition to Verdict failed: {e}"));
            }
        }

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

        if extinction_res.is_err() {
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        } else if !evidence_intact || !ledger_verified {
            let fsm_err = self.fsm.fail_closed(&final_verdict_obj.reason);
            if matches!(fsm_err, StateTransitionError::InvalidTransition { .. }) {
                self.capability
                    .note_diagnostic(format!("FSM transition to FailClosed failed: {fsm_err}"));
            }
            if let Err(e) = self.fsm.transition(ExecutionState::EmergencyCleanup) {
                self.capability
                    .note_diagnostic(format!("FSM transition to EmergencyCleanup failed: {e}"));
            }
            if let Err(e) = self.fsm.transition(ExecutionState::Terminal) {
                self.capability
                    .note_diagnostic(format!("FSM transition to Terminal failed: {e}"));
            }
            final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
        } else {
            if let Err(e) = self.fsm.transition(ExecutionState::Terminal) {
                self.capability
                    .note_diagnostic(format!("FSM transition to Terminal failed: {e}"));
                final_exit_code = Some(FAIL_CLOSED_EXTINCTION_EXIT_CODE);
            }
        }

        let report = self
            .capability
            .enforcement()
            .cloned()
            .expect("prepared backend always holds a report");
        let diagnostic = self.capability.diagnostic();
        let backend_kind = self.capability.kind();
        let blocked_attempts = if final_verdict_obj.status == VerdictStatus::Fail && !timed_out {
            1
        } else {
            0
        };
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
            stdout: stdout_bytes,
            stderr: stderr_bytes,
            spawn_via_backend: true,
            diagnostic,
            verdict: Some(final_verdict_obj),
            fsm_state: Some(self.fsm.current_state()),
            blocked_attempts,
        }
    }
}

/// Proven wait for ANY production handle: deadline -> try_wait polling ->
/// terminate once -> bounded re-wait.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::production::{execute_with_backend, prod_tier_mapping, ProdSpawnLog, PROD_SCENARIO_ID};

    fn test_policy() -> Policy {
        Policy::default()
    }

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

    #[test]
    fn test_prod_policy_frozen_001_flips_hash() {
        let pol = test_policy();
        let env = BTreeMap::new();
        let cwd = PathBuf::from("/tmp");
        let argv = vec!["sh".to_string()];
        let (a, _, id_a) = crate::sandbox::production::freeze_production(
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
        let (b, _, _) = crate::sandbox::production::freeze_production(
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
        let (_, can, _) = crate::sandbox::production::freeze_production(
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
        assert_eq!(can.cwd, cwd);
        assert_eq!(can.cwd, a.cwd);
        assert_eq!(id_a.frozen_hash, a.hash());
    }

    #[test]
    fn test_prod_identity_binding_001_cwd_equals_exec_root() {
        let pol = test_policy();
        let env = BTreeMap::new();
        let cwd = PathBuf::from("/tmp");
        let argv = vec!["sh".to_string()];
        let (spec, can, id) = crate::sandbox::production::freeze_production(
            PROD_SCENARIO_ID,
            &pol,
            "fs-only",
            &NetMode::Off,
            "prod",
            &argv,
            &env,
            &cwd,
            "nonce-123",
        );
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
                    serde_json::from_value(envelope["contract"].clone())
                        .expect("contract payload");
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
                        Some(crate::policy_ir::contract::DebugPortConfig::default());
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
        let base_backend = Backend::detect(NetMode::Off, false).expect("detect mechanics");
        let test_policy = functional_test_policy(&tmp);
        let cmd = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf started > child-started".into(),
        ];
        for case in ["digest", "resealed", "projection", "missing"] {
            let mut prepared = UnpreparedProductionExecution::new(
                base_backend.clone(),
                test_policy.clone(),
                cmd.clone(),
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
        }
        let spawned = UnpreparedProductionExecution::new(
            base_backend,
            test_policy,
            cmd,
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
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn phase2_contract_tamper_all_field_classes_rejected_no_spawn() {
        let tmp =
            std::env::temp_dir().join(format!("vetto-tamper-full-matrix-{}", engine::new_nonce()));
        std::fs::create_dir_all(&tmp).unwrap();
        let marker = tmp.join("child-started");
        let base_backend = Backend::detect(NetMode::Off, false).expect("detect mechanics");
        let test_policy = functional_test_policy(&tmp);
        let cmd = vec![
            "/bin/sh".into(),
            "-c".into(),
            "printf started > child-started".into(),
        ];

        let cases = [
            "fs_allow_read",
            "fs_allow_write",
            "fs_deny_read",
            "fs_deny_write",
            "fs_cow_overlay",
            "fs_execution_root_ro",
            "env_explicit_vars",
            "env_redacted_patterns",
            "env_inject_session_nonce",
            "net_mode",
            "net_allowed_domains",
            "net_allowed_ports",
            "net_allowed_ips",
            "net_debug_ports",
            "limits_max_memory_mb",
            "limits_max_pids",
            "limits_max_cpu_seconds",
            "limits_max_file_size_mb",
            "exec_allowed_executables",
            "exec_forbidden_executables",
            "exec_invoked_binary",
            "exec_invoked_args",
            "secrets_mask_paths",
            "tier_requirement",
            "backend_requirement",
        ];

        for case in cases {
            {
                let mut prepared = UnpreparedProductionExecution::new(
                    base_backend.clone(),
                    test_policy.clone(),
                    cmd.clone(),
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
                    "fs_cow_overlay" => {
                        prepared.contract.filesystem.cow_overlay =
                            !prepared.contract.filesystem.cow_overlay
                    }
                    "fs_execution_root_ro" => {
                        prepared.contract.filesystem.execution_root_ro =
                            !prepared.contract.filesystem.execution_root_ro
                    }
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
                        prepared.contract.environment.inject_session_nonce =
                            !prepared.contract.environment.inject_session_nonce
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
                            Some(crate::policy_ir::contract::DebugPortConfig::default())
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
                        let p = prepared.contract.production.as_mut().unwrap();
                        p.tier = if p.tier == Some(Tier::FsOnly) {
                            Some(Tier::Full)
                        } else {
                            Some(Tier::FsOnly)
                        };
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
                assert!(!marker.exists(), "{case}: child must not execute");
            }

            {
                let mut prepared = UnpreparedProductionExecution::new(
                    base_backend.clone(),
                    test_policy.clone(),
                    cmd.clone(),
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
                    "fs_cow_overlay" => {
                        prepared.contract.filesystem.cow_overlay =
                            !prepared.contract.filesystem.cow_overlay
                    }
                    "fs_execution_root_ro" => {
                        prepared.contract.filesystem.execution_root_ro =
                            !prepared.contract.filesystem.execution_root_ro
                    }
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
                        prepared.contract.environment.inject_session_nonce =
                            !prepared.contract.environment.inject_session_nonce
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
                            Some(crate::policy_ir::contract::DebugPortConfig::default())
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
                        let p = prepared.contract.production.as_mut().unwrap();
                        p.tier = if p.tier == Some(Tier::FsOnly) {
                            Some(Tier::Full)
                        } else {
                            Some(Tier::FsOnly)
                        };
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
                assert!(
                    !marker.exists(),
                    "{case}: child must not execute on resealed tamper"
                );
            }
        }

        let spawned = UnpreparedProductionExecution::new(
            base_backend,
            test_policy,
            cmd,
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
        let _ = std::fs::remove_dir_all(tmp);
    }

    #[test]
    fn phase1_caller_policy_cannot_change_canonical_backend_input() {
        let tmp = std::env::temp_dir();
        let mut policy = functional_test_policy(&tmp);
        let mut debug_ports = crate::policy_ir::contract::DebugPortConfig {
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
        let _ = std::fs::remove_file(ledger);
        let _ = std::fs::remove_dir_all(tmp);
    }

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
        let msg = err.to_string();
        assert!(
            msg.contains("fail-closed") || msg.contains("refusing"),
            "fail-closed error, got: {err:#}"
        );
    }

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
