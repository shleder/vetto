//! Production execution modular package facade.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;

use crate::audit::verdict::FinalVerdict;
use crate::config::NetMode;
use crate::policy::{Policy, Tier};
use crate::policy_ir::ExecutionState;
use crate::verify_ng::evidence::ExecutionIdentity;
use crate::verify_ng::frozen::FrozenSpec;
use crate::verify_ng::sandbox_backend::{
    BackendKind, CanonicalPolicy, EnforcementReport, EnforcementState, SandboxBackend,
    SecurityCapability,
};
use crate::sandbox::StdioMode;

pub mod context;
pub mod drain;
pub mod error;
pub mod lifecycle;
pub mod signals;

pub use context::{
    ProductionSessionContext, SessionEvidenceState, SessionExecutionMetrics, SessionSignalState,
};
#[cfg(unix)]
pub use drain::piped_stdio_fds;
pub use drain::{AsyncPipeReader, DrainConfig, PipePair, StreamCollector};
pub use error::ProductionError;
pub use lifecycle::{
    build_production_env, freeze_production_contract, prepare_production_contract, wait_for_exit,
    FrozenProductionInputs, PreparedExecution, PreparedProductionExecution, SpawnedExecution,
    SpawnedProductionExecution, UnpreparedExecution, UnpreparedProductionExecution,
};
pub use signals::{EscalationPolicy, ScopedSignalForwarder, SignalTarget};

pub const PROD_SCENARIO_ID: &str = "PROD";
pub const PROD_NONCE_ENV: &str = "VETTO_PROD_NONCE";
pub const RUN_NONCE_ENV: &str = "VETTO_RUN_NONCE";
pub const SHIM_EXEC_NONCE_ENV: &str = "VETTO_SHIM_NONCE";
pub const PROD_REGISTRY: &str = "production";
pub const PROD_DRAIN_BUDGET: Duration = Duration::from_millis(200);
pub const PROD_MAX_STDIO: usize = 1 << 20;
pub const PROD_EXIT_POLL: Duration = Duration::from_millis(10);

/// One authoritative spawn event. `run_id` equals the run nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProdSpawnEvent {
    pub run_id: String,
    pub pid: u32,
}

/// Caller-owned spawn ledger: exactly one entry per execute call.
pub type ProdSpawnLog = Vec<ProdSpawnEvent>;

/// Explicit per-tier capability mapping.
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
    {}
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
        None => {
            #[cfg(target_os = "macos")]
            {
                let mut caps = vec![
                    SecurityCapability::FilesystemIsolation,
                    SecurityCapability::ProcessIsolation,
                    SecurityCapability::ProcessTreeContainment,
                    SecurityCapability::HostEvidence,
                ];
                if !matches!(net, NetMode::Allowlist(_)) {
                    caps.push(SecurityCapability::NetworkIsolation);
                }
                caps
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

/// Freeze production identity: policy cwd == FrozenSpec cwd == backend
/// exec_root == actual child cwd by construction.
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
    let spec = crate::verify_ng::frozen::freeze_spec(
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

/// Typed production execution result.
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
    pub blocked_attempts: usize,
}

impl ProductionResult {
    pub fn state(&self, cap: SecurityCapability) -> EnforcementState {
        self.report.state(cap)
    }

    pub fn allows_pass(&self, required: &[SecurityCapability]) -> bool {
        self.report.allows_pass(required)
    }

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

/// Real headless production execution through the authoritative boundary.
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
    let (stdout_r, stdout_w, stderr_r, stderr_w) = drain::piped_stdio_fds()?;
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
        Some(capability) => unprepared
            .prepare_with_backend(capability)
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        None => unprepared.prepare().map_err(|e| anyhow::anyhow!("{e}"))?,
    };
    let spawned = prepared.spawn().map_err(|e| anyhow::anyhow!("{e}"))?;
    spawn_log.push(spawned.event());
    #[cfg(unix)]
    {
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
