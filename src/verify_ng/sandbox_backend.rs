//! Cross-platform `SandboxBackend` architecture (Stage 3A: architecture only).
//!
//! Conceptual pipeline:
//!
//! ```text
//! Verify Engine
//!       v
//! Sandbox Policy (FrozenSpec -> CanonicalPolicy)
//!       v
//! SandboxBackend::prepare(...)
//!       v
//! OS-specific Enforcement (Stage 3B+; absent in Stage 3A)
//!       v
//! Execution (spawn -> collect -> teardown)
//!       v
//! Host Evidence (host-observed facts only)
//!       v
//! Oracle (pure decision function, no I/O)
//! ```
//!
//! Security principle: a policy field is NOT an enforcement guarantee. A
//! backend must distinguish `Requested`, `Configured`, `Enforced`,
//! `Verified`, `Unsupported`, and `Failed`, and must never claim enforcement
//! merely because it accepted a configuration.
//!
//! Stage honesty contract:
//!
//! ```text
//! Stage 3A was architecture only.
//! Stage 3B implements real Linux enforcement (landlock + seccomp + rlimit
//!   + process-group/tree sweep); Windows remains a placeholder.
//! Stage 3C-macOS implements real macOS enforcement (Seatbelt SBPL write +
//!   net-off isolation, setrlimit ceilings, process-group containment,
//!   kqueue parent-death watchdog); syscall filtering and exec-root READ
//!   isolation stay Unsupported (no seccomp equivalent; SBPL reads are
//!   broad by platform necessity).
//! ```
//!
//! Backends report `Unsupported` for every capability they cannot actually
//! install and never return `Enforced`/`Verified` without real enforcement.
//! `DirectBackend` (the pre-existing direct-exec plumbing) enforces only
//! `HostEvidence` (wait-status/kill/sentinel observation) and nothing else.
//! `LinuxBackend::prepare` reports at most `Configured` (probed, planned,
//! not yet installed); only a successful backend-controlled spawn promotes
//! to `Enforced`, and only host-observed `/proc` evidence promotes to
//! `Verified`. `MacosBackend::prepare` follows the same state machine (at
//! most `Configured`, plus `HostEvidence` which is `Enforced` by
//! construction); only a Seatbelt-confined spawn promotes to `Enforced`,
//! and only host-observed `getpgid` / group-death checks promote process
//! and tree capabilities to `Verified`. Fail-closed gating ([`apply_backend_ceiling`]) demotes any
//! `PASS` whose mandatory capabilities are not actually enforced to
//! `INCONCLUSIVE`, never to `PASS`.
//!
//! The oracle itself is untouched by this module: [`apply_backend_ceiling`]
//! and [`allows_pass`] are pure functions over already-structured reports,
//! so the oracle stays free of I/O and platform APIs.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::evidence::ExecutionIdentity;
use super::frozen::FrozenSpec;
use super::model::{Category, Verdict};
use super::registry::Scenario;

/// Security capabilities tracked by every backend.
///
/// Static support ([`SandboxBackend::supports`]) is distinct from per-run
/// enforcement ([`EnforcementReport::is_enforced`]): a backend may
/// eventually support a capability while a particular execution still
/// reports it as `Unsupported` or `Failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityCapability {
    FilesystemIsolation,
    NetworkIsolation,
    ProcessIsolation,
    ProcessTreeContainment,
    ResourceLimits,
    SyscallRestriction,
    ExecutionRootIsolation,
    HostEvidence,
}

impl SecurityCapability {
    pub fn label(self) -> &'static str {
        match self {
            SecurityCapability::FilesystemIsolation => "filesystem",
            SecurityCapability::NetworkIsolation => "network",
            SecurityCapability::ProcessIsolation => "process",
            SecurityCapability::ProcessTreeContainment => "tree",
            SecurityCapability::ResourceLimits => "resources",
            SecurityCapability::SyscallRestriction => "syscalls",
            SecurityCapability::ExecutionRootIsolation => "exec-root",
            SecurityCapability::HostEvidence => "host-evidence",
        }
    }

    /// Every tracked capability, in a fixed deterministic order.
    pub fn all() -> [SecurityCapability; 8] {
        [
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::NetworkIsolation,
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::ResourceLimits,
            SecurityCapability::SyscallRestriction,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::HostEvidence,
        ]
    }
}

/// Per-capability enforcement state for one execution.
///
/// The states are never collapsed: `Requested` (intent recorded) and
/// `Configured` (accepted into a backend config) are not enforcement.
/// Only `Enforced` (installed) and `Verified` (installed plus
/// host-observed confirmation) count toward PASS. `Unsupported` means the
/// backend has no mechanism here; `Failed` means preparation/installation
/// was attempted and did not succeed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnforcementState {
    Requested,
    Configured,
    Enforced,
    Verified,
    Unsupported,
    Failed,
}

impl EnforcementState {
    pub fn label(self) -> &'static str {
        match self {
            EnforcementState::Requested => "requested",
            EnforcementState::Configured => "configured",
            EnforcementState::Enforced => "enforced",
            EnforcementState::Verified => "verified",
            EnforcementState::Unsupported => "unsupported",
            EnforcementState::Failed => "failed",
        }
    }

    /// True only for installed enforcement. Everything else (including
    /// `Requested`/`Configured`) is NOT enforcement.
    pub fn is_enforced(self) -> bool {
        matches!(
            self,
            EnforcementState::Enforced | EnforcementState::Verified
        )
    }
}

/// Typed reason for a `Failed` enforcement state. No free-form strings:
/// security state stays deterministic and suitable for oracle input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PreparationFailureKind {
    UnsupportedOnPlatform,
    PlatformUnavailable,
    SpawnRefused,
    VerificationUnavailable,
}

impl PreparationFailureKind {
    pub fn label(self) -> &'static str {
        match self {
            PreparationFailureKind::UnsupportedOnPlatform => "unsupported-on-platform",
            PreparationFailureKind::PlatformUnavailable => "platform-unavailable",
            PreparationFailureKind::SpawnRefused => "spawn-refused",
            PreparationFailureKind::VerificationUnavailable => "verification-unavailable",
        }
    }
}

/// Which backend implementation a report or matrix entry refers to.
/// `Direct` is the pre-existing direct-exec plumbing (explicitly
/// non-contained); the other three are Stage 3A placeholders whose
/// containment stays `Unsupported` until Stage 3B+.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Direct,
    Linux,
    Macos,
    Windows,
}

impl BackendKind {
    pub fn label(self) -> &'static str {
        match self {
            BackendKind::Direct => "direct",
            BackendKind::Linux => "linux",
            BackendKind::Macos => "macos",
            BackendKind::Windows => "windows",
        }
    }

    pub fn all() -> [BackendKind; 4] {
        [
            BackendKind::Direct,
            BackendKind::Linux,
            BackendKind::Macos,
            BackendKind::Windows,
        ]
    }

    /// Backend backing this platform's placeholder. Used for diagnostics
    /// and matrix defaults; never implies enforcement.
    pub fn current_platform() -> BackendKind {
        #[cfg(target_os = "linux")]
        {
            BackendKind::Linux
        }
        #[cfg(target_os = "macos")]
        {
            BackendKind::Macos
        }
        #[cfg(target_os = "windows")]
        {
            BackendKind::Windows
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            BackendKind::Direct
        }
    }
}

/// Platform-independent enforcement intent derived from a [`FrozenSpec`].
///
/// Built by a pure function ([`CanonicalPolicy::from_frozen`]) with no
/// platform branches, so the same frozen spec always yields the same
/// canonical policy on every OS. Platform details stay behind the
/// [`SandboxBackend`] boundary; backends must not mutate this value to
/// smuggle OS specifics into the verifier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalPolicy {
    pub scenario_id: String,
    pub registry_hash: String,
    pub session_nonce: String,
    pub frozen_hash: String,
    pub net_mode: String,
    pub tier: String,
    pub backend_hint: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub policy_bytes: Vec<u8>,
    pub policy_hash: String,
}

impl CanonicalPolicy {
    /// Pure, platform-independent projection of a frozen spec. No `cfg`
    /// branches: identical input yields identical output on every target.
    pub fn from_frozen(spec: &FrozenSpec) -> Self {
        let policy_hash = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&spec.policy_bytes);
            super::frozen::hex_encode(&hasher.finalize())
        };
        CanonicalPolicy {
            scenario_id: spec.scenario_id.clone(),
            registry_hash: spec.registry_hash.clone(),
            session_nonce: spec.nonce.clone(),
            frozen_hash: spec.hash(),
            net_mode: spec.net_mode.clone(),
            tier: spec.tier.clone(),
            backend_hint: spec.backend.clone(),
            argv: spec.argv.clone(),
            env: spec.env.clone(),
            cwd: spec.cwd.clone(),
            policy_bytes: spec.policy_bytes.clone(),
            policy_hash,
        }
    }
}

/// One capability row inside an [`EnforcementReport`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRecord {
    pub capability: SecurityCapability,
    pub requested: bool,
    pub state: EnforcementState,
    pub failure: Option<PreparationFailureKind>,
}

/// Structured preparation outcome: what was requested, supported,
/// installed, failed, or unsupported. Deterministic (records sorted by
/// capability) and suitable as oracle input via [`allows_pass`] and
/// [`apply_backend_ceiling`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementReport {
    pub backend: BackendKind,
    pub scenario_id: String,
    pub session_nonce: String,
    pub registry_hash: String,
    pub frozen_hash: String,
    pub policy_hash: String,
    pub preparation_ok: bool,
    pub records: Vec<CapabilityRecord>,
}

impl EnforcementReport {
    /// Build a deterministic report from per-capability states. `states`
    /// maps every capability the backend considered; missing entries
    /// default to `Unsupported` so partial maps fail closed, never open.
    pub fn build(
        backend: BackendKind,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        states: &BTreeMap<SecurityCapability, EnforcementState>,
        failures: &BTreeMap<SecurityCapability, PreparationFailureKind>,
        preparation_ok: bool,
    ) -> Self {
        let mut records = Vec::new();
        for cap in SecurityCapability::all() {
            let state = states
                .get(&cap)
                .copied()
                .unwrap_or(EnforcementState::Unsupported);
            let failure = failures.get(&cap).copied();
            records.push(CapabilityRecord {
                capability: cap,
                requested: true,
                state,
                failure,
            });
        }
        EnforcementReport {
            backend,
            scenario_id: identity.scenario_id.clone(),
            session_nonce: identity.session_nonce.clone(),
            registry_hash: identity.registry_hash.clone(),
            frozen_hash: identity.frozen_hash.clone(),
            policy_hash: policy.policy_hash.clone(),
            preparation_ok,
            records,
        }
    }

    pub fn state(&self, capability: SecurityCapability) -> EnforcementState {
        self.records
            .iter()
            .find(|r| r.capability == capability)
            .map(|r| r.state)
            .unwrap_or(EnforcementState::Unsupported)
    }

    /// True only when preparation succeeded AND the capability reached
    /// `Enforced`/`Verified`. `Requested`/`Configured` never count.
    pub fn is_enforced(&self, capability: SecurityCapability) -> bool {
        self.preparation_ok && self.state(capability).is_enforced()
    }

    pub fn requested(&self) -> Vec<SecurityCapability> {
        self.records
            .iter()
            .filter(|r| r.requested)
            .map(|r| r.capability)
            .collect()
    }

    pub fn enforced(&self) -> Vec<SecurityCapability> {
        SecurityCapability::all()
            .into_iter()
            .filter(|c| self.is_enforced(*c))
            .collect()
    }

    pub fn unsupported(&self) -> Vec<SecurityCapability> {
        self.records
            .iter()
            .filter(|r| r.state == EnforcementState::Unsupported)
            .map(|r| r.capability)
            .collect()
    }

    pub fn failed(&self) -> Vec<(SecurityCapability, Option<PreparationFailureKind>)> {
        self.records
            .iter()
            .filter(|r| r.state == EnforcementState::Failed)
            .map(|r| (r.capability, r.failure))
            .collect()
    }

    /// Fail-closed gate: PASS is allowed only when preparation succeeded
    /// and every mandatory capability is actually enforced.
    pub fn allows_pass(&self, required: &[SecurityCapability]) -> bool {
        if !self.preparation_ok {
            return false;
        }
        required.iter().all(|c| self.is_enforced(*c))
    }

    /// True only when this report is bound to exactly `identity` (scenario
    /// + session nonce + registry hash + frozen hash). Any drift rejects.
    pub fn binds_identity(&self, identity: &ExecutionIdentity) -> bool {
        self.scenario_id == identity.scenario_id
            && self.session_nonce == identity.session_nonce
            && self.registry_hash == identity.registry_hash
            && self.frozen_hash == identity.frozen_hash
    }

    /// Deterministic rendering for logs and oracle-adjacent diagnostics.
    /// No free-form security strings: backend, per-capability states, and
    /// the preparation flag in a fixed order.
    pub fn render_deterministic(&self) -> String {
        let mut parts = vec![format!("backend={}", self.backend.label())];
        for record in &self.records {
            parts.push(format!(
                "{}={}",
                record.capability.label(),
                record.state.label()
            ));
        }
        parts.push(format!("preparation_ok={}", self.preparation_ok));
        parts.join("|")
    }
}

/// Host-observable enforcement evidence derived from a report. Typed
/// (capability + state + backend); never a free-form string claim. Stage
/// 3A placeholders emit an entry per capability with its honest state, so
/// consumers can distinguish `Unsupported` from `Enforced` structurally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementFact {
    pub capability: SecurityCapability,
    pub state: EnforcementState,
    pub backend: BackendKind,
}

/// Extra host-side context for preparation that is transport, not policy:
/// paths the child legitimately needs (e.g. the host-owned control-channel
/// directory) which the canonical policy must not absorb. Bound to the run
/// via the execution identity like everything else.
#[derive(Debug, Clone, Default)]
pub struct PrepareContext {
    pub extra_rw: Vec<std::path::PathBuf>,
}

/// Child-side enforcement plan built by `prepare` (parent-side, where
/// allocation is safe) and installed by the forked child before `exec`.
///
/// Pure data: the runner applies it through `Command::pre_exec`, so the
/// spawn itself is backend-controlled — a backend can only reach `Enforced`
/// for a child that actually ran this plan. `None` (via
/// [`SandboxBackend::pre_exec_plan`]) means no child-side enforcement.
#[derive(Debug, Clone)]
pub struct ChildEnforcementPlan {
    /// Landlock ruleset available on this kernel.
    pub landlock: bool,
    /// Execution root confined read/write (the fixture root).
    pub exec_root: std::path::PathBuf,
    /// Extra read/write roots (host control-channel dir).
    pub extra_rw: Vec<std::path::PathBuf>,
    /// System roots confined read-only (interpreter, loader, configs).
    pub system_ro: Vec<std::path::PathBuf>,
    /// Deny non-`AF_UNIX` sockets (`--net=off` only).
    pub net_deny: bool,
    /// Install the seccomp hardening denylist.
    pub harden_syscalls: bool,
    /// `setrlimit` ceilings (lowering only).
    pub rlimit_as: Option<u64>,
    pub rlimit_nproc: Option<u64>,
    pub rlimit_cpu: Option<u64>,
    pub rlimit_fsize: Option<u64>,
    /// Join a new process group for tree-wide signalling.
    pub new_pgroup: bool,
}

/// Host-observed verification of a live confined child, read from `/proc`
/// without trusting any child output. Any flag the host could not observe
/// stays false: the capability remains `Enforced`, never `Verified`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostVerification {
    pub seccomp_filter: bool,
    pub no_new_privs: bool,
    pub pgroup_separate: bool,
    pub rlimit_as_ok: bool,
    pub rlimit_nproc_ok: bool,
    pub rlimit_cpu_ok: bool,
    pub rlimit_fsize_ok: bool,
    pub subreaper_ok: bool,
}

impl HostVerification {
    pub fn none() -> Self {
        HostVerification {
            seccomp_filter: false,
            no_new_privs: false,
            pgroup_separate: false,
            rlimit_as_ok: false,
            rlimit_nproc_ok: false,
            rlimit_cpu_ok: false,
            rlimit_fsize_ok: false,
            subreaper_ok: false,
        }
    }

    /// True when every installed mechanism was host-observed.
    pub fn all_observed(&self) -> bool {
        self.seccomp_filter
            && self.no_new_privs
            && self.pgroup_separate
            && self.rlimit_as_ok
            && self.rlimit_nproc_ok
            && self.rlimit_cpu_ok
            && self.rlimit_fsize_ok
            && self.subreaper_ok
    }
}

/// Minimal backend contract for Stage 3B Linux enforcement and later
/// macOS/Windows implementations. Every security-relevant operation has a
/// clear failure mode: [`prepare`](SandboxBackend::prepare) reports
/// per-capability states instead of error strings, and
/// [`teardown`](SandboxBackend::teardown) is idempotent best-effort
/// cleanup.
///
/// Spawn-authority rule (Stage 3B): enforcement lives in the
/// [`ChildEnforcementPlan`] the runner installs via `pre_exec`. `prepare`
/// reports at most `Configured`; only [`note_spawned`](SandboxBackend::note_spawned)
/// (spawn succeeded, so the plan ran without error) promotes to `Enforced`,
/// and only [`note_host_verified`](SandboxBackend::note_host_verified)
/// (host-observed proof) promotes to `Verified`.
/// `Send` is required: production executions cross thread boundaries
/// (multi-agent dashboards share one `SpawnedProductionExecution` with the
/// wait thread). All backends are plain data (reports/plans/strings), so
/// the bound is structural, not behavioral.
pub trait SandboxBackend: Send {
    /// Which implementation this is (matrix row + report attribution).
    fn kind(&self) -> BackendKind;

    /// Human-readable name. Placeholders name their unimplemented status
    /// explicitly so logs can never be mistaken for enforcement claims.
    fn name(&self) -> &'static str;

    /// Static support: whether this backend type has a mechanism for the
    /// capability at all. Distinct from per-run enforcement.
    fn supports(&self, capability: SecurityCapability) -> bool;

    /// All statically supported capabilities, in [`SecurityCapability::all`]
    /// order.
    fn supported_capabilities(&self) -> Vec<SecurityCapability> {
        SecurityCapability::all()
            .into_iter()
            .filter(|c| self.supports(*c))
            .collect()
    }

    /// Record intent, probe the kernel, build the child-side plan, and
    /// return the structured outcome. Reports at most `Configured` for
    /// available mechanisms (`Unsupported` otherwise); must never return
    /// `Enforced`/`Verified` — nothing is installed yet. Read-only probing
    /// only (no confinement of the calling process).
    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport;

    /// Same as [`prepare`](SandboxBackend::prepare) with extra host-side
    /// transport context (control-channel dir). Defaults to ignoring the
    /// context; the Linux backend honors it.
    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        ctx: &PrepareContext,
    ) -> EnforcementReport {
        let _ = ctx;
        self.prepare(policy, identity)
    }

    /// Child-side plan to install via `pre_exec`, if any. `None` means the
    /// spawn path carries no backend enforcement.
    fn pre_exec_plan(&self) -> Option<ChildEnforcementPlan> {
        None
    }

    /// Record a successful spawn: the `pre_exec` plan ran without error, so
    /// `Configured` capabilities promote to `Enforced`.
    fn note_spawned(&mut self, _pid: u32) {}

    /// Record host-observed verification: matching capabilities promote
    /// from `Enforced` to `Verified`. Unobserved stays `Enforced`.
    fn note_host_verified(&mut self, _verification: &HostVerification) {}

    /// Record a setup failure: affected capabilities become `Failed` and
    /// the report fails closed (`preparation_ok == false`).
    fn note_failed(&mut self, _kind: PreparationFailureKind) {}

    /// Record the post-run tree-sweep outcome: a clean sweep promotes
    /// `ProcessTreeContainment` to `Verified`; residuals fail it closed.
    fn note_tree_clean(&mut self, _clean: bool) {}

    /// Store a one-line diagnostic for the run detail string (sweep
    /// counts, never verdict input). Defaults to ignoring it.
    fn note_diagnostic(&mut self, _diag: String) {}

    /// Optional one-line diagnostic for the run detail string (sweep
    /// counts, never verdict input). Defaults to none.
    fn diagnostic(&self) -> Option<String> {
        None
    }

    /// Last preparation outcome, if any.
    fn enforcement(&self) -> Option<&EnforcementReport>;

    /// Convenience over [`enforcement`]: false when never prepared.
    fn is_enforced(&self, capability: SecurityCapability) -> bool {
        self.enforcement()
            .map(|r| r.is_enforced(capability))
            .unwrap_or(false)
    }

    /// Host-observable enforcement evidence for this preparation. Typed
    /// facts only; empty when nothing is enforced.
    fn enforcement_evidence(&self) -> Vec<EnforcementFact> {
        match self.enforcement() {
            Some(report) => report
                .records
                .iter()
                .map(|r| EnforcementFact {
                    capability: r.capability,
                    state: r.state,
                    backend: report.backend,
                })
                .collect(),
            None => Vec::new(),
        }
    }

    /// Release any held enforcement state. Idempotent; never fails the
    /// verdict by itself (a failed preparation already fails closed via
    /// the report).
    fn teardown(&mut self);
}

/// Direct-exec plumbing backend: the pre-existing harness spawn path,
/// explicitly non-contained. Enforces only [`SecurityCapability::HostEvidence`]
/// (wait-status/kill/sentinel observation by the host); every containment
/// capability stays `Unsupported` by construction.
#[derive(Debug, Clone, Default)]
pub struct DirectBackend {
    report: Option<EnforcementReport>,
}

impl DirectBackend {
    pub fn new() -> Self {
        DirectBackend { report: None }
    }
}

impl SandboxBackend for DirectBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Direct
    }

    fn name(&self) -> &'static str {
        "direct-exec (no sandbox; plumbing only)"
    }

    fn supports(&self, capability: SecurityCapability) -> bool {
        matches!(capability, SecurityCapability::HostEvidence)
    }

    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport {
        let mut states = BTreeMap::new();
        for cap in SecurityCapability::all() {
            let state = if cap == SecurityCapability::HostEvidence {
                EnforcementState::Enforced
            } else {
                EnforcementState::Unsupported
            };
            states.insert(cap, state);
        }
        let report = EnforcementReport::build(
            BackendKind::Direct,
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

/// Stage 3B Linux backend: real unprivileged enforcement (Landlock
/// filesystem allowlist, seccomp-BPF socket policy + hardening denylist,
/// `setrlimit` ceilings, `NO_NEW_PRIVS`, new process group, nonce-targeted
/// tree sweep). No namespaces, no cgroups, no mounts: anything requiring
/// privilege stays `Unsupported`, never faked.
///
/// State machine per run: `prepare` probes and reports at most `Configured`;
/// a successful backend-controlled spawn promotes to `Enforced`;
/// host-observed `/proc` evidence promotes to `Verified`. Off Linux every
/// capability stays `Unsupported`.
#[derive(Debug, Clone, Default)]
pub struct LinuxBackend {
    report: Option<EnforcementReport>,
    plan: Option<ChildEnforcementPlan>,
    tree_diag: Option<String>,
    subreaper_prepare: Option<String>,
}

impl LinuxBackend {
    pub fn new() -> Self {
        LinuxBackend {
            report: None,
            plan: None,
            tree_diag: None,
            subreaper_prepare: None,
        }
    }

    /// Upgrade every `Configured` record to `Enforced` in the stored report.
    fn promote_configured_to_enforced(&mut self) {
        if let Some(report) = self.report.as_mut() {
            for record in &mut report.records {
                if record.state == EnforcementState::Configured {
                    record.state = EnforcementState::Enforced;
                }
            }
        }
    }

    /// Fail every installed-or-planned record with `kind` and fail closed.
    fn fail_installed(&mut self, kind: PreparationFailureKind) {
        if let Some(report) = self.report.as_mut() {
            for record in &mut report.records {
                match record.state {
                    EnforcementState::Configured
                    | EnforcementState::Enforced
                    | EnforcementState::Verified => {
                        record.state = EnforcementState::Failed;
                        record.failure = Some(kind);
                    }
                    _ => {}
                }
            }
            report.preparation_ok = false;
        }
    }

    /// Production honesty hook (Stage 3C, additive only): the Seccomp tier
    /// installs no filesystem isolation even on Landlock-capable kernels
    /// (forced-tier configurations; release tier selection never picks it
    /// there). Demotes those two capabilities to `Unsupported` on the
    /// STORED report so a later `note_spawned` cannot promote an
    /// uninstalled mechanism to `Enforced`. Trait, states, transitions,
    /// ceiling and oracle are untouched.
    pub fn restrict_to_seccomp_tier(&mut self) {
        if let Some(report) = self.report.as_mut() {
            for record in &mut report.records {
                if matches!(
                    record.capability,
                    SecurityCapability::FilesystemIsolation
                        | SecurityCapability::ExecutionRootIsolation
                ) {
                    record.state = EnforcementState::Unsupported;
                    record.failure = None;
                }
            }
        }
    }
}

impl SandboxBackend for LinuxBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Linux
    }

    fn name(&self) -> &'static str {
        "linux (landlock+seccomp+rlimit+pgroup; no userns)"
    }

    fn supports(&self, capability: SecurityCapability) -> bool {
        #[cfg(target_os = "linux")]
        {
            match capability {
                SecurityCapability::FilesystemIsolation
                | SecurityCapability::NetworkIsolation
                | SecurityCapability::ProcessIsolation
                | SecurityCapability::ProcessTreeContainment
                | SecurityCapability::ResourceLimits
                | SecurityCapability::SyscallRestriction
                | SecurityCapability::ExecutionRootIsolation
                | SecurityCapability::HostEvidence => true,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = capability;
            false
        }
    }

    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport {
        self.prepare_with_context(policy, identity, &PrepareContext::default())
    }

    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        ctx: &PrepareContext,
    ) -> EnforcementReport {
        self.plan = None;
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ctx;
            let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
                .into_iter()
                .map(|c| (c, EnforcementState::Unsupported))
                .collect();
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
        #[cfg(target_os = "linux")]
        {
            self.prepare_linux(policy, identity, ctx)
        }
    }

    fn pre_exec_plan(&self) -> Option<ChildEnforcementPlan> {
        self.plan.clone()
    }

    fn note_spawned(&mut self, _pid: u32) {
        self.promote_configured_to_enforced();
    }

    fn note_host_verified(&mut self, verification: &HostVerification) {
        let Some(report) = self.report.as_mut() else {
            return;
        };
        let mut verified = |cap: SecurityCapability, observed: bool| {
            if observed {
                if let Some(record) = report.records.iter_mut().find(|r| r.capability == cap) {
                    if record.state == EnforcementState::Enforced {
                        record.state = EnforcementState::Verified;
                    }
                }
            }
        };
        verified(
            SecurityCapability::SyscallRestriction,
            verification.seccomp_filter,
        );
        verified(
            SecurityCapability::ProcessIsolation,
            verification.no_new_privs && verification.pgroup_separate,
        );
        verified(
            SecurityCapability::ResourceLimits,
            verification.rlimit_as_ok
                && verification.rlimit_nproc_ok
                && verification.rlimit_cpu_ok
                && verification.rlimit_fsize_ok,
        );
    }

    fn note_failed(&mut self, kind: PreparationFailureKind) {
        self.fail_installed(kind);
    }

    fn note_tree_clean(&mut self, clean: bool) {
        let Some(report) = self.report.as_mut() else {
            return;
        };
        if let Some(record) = report
            .records
            .iter_mut()
            .find(|r| r.capability == SecurityCapability::ProcessTreeContainment)
        {
            match record.state {
                EnforcementState::Enforced if clean => {
                    record.state = EnforcementState::Verified;
                }
                EnforcementState::Enforced | EnforcementState::Configured if !clean => {
                    // Post-run sweep outcome, not a preparation failure:
                    // only the tree capability fails. `preparation_ok`
                    // stays untouched so one dirty tree cannot demote
                    // unrelated enforced caps; Proc scenarios still fail
                    // closed via `tree == Failed` in the PASS ceiling.
                    record.state = EnforcementState::Failed;
                    record.failure = Some(PreparationFailureKind::VerificationUnavailable);
                }
                _ => {}
            }
        }
    }

    fn note_diagnostic(&mut self, diag: String) {
        let diag = match &self.subreaper_prepare {
            Some(st) => format!("prepare-subreaper={st} {diag}"),
            None => diag,
        };
        self.tree_diag = Some(diag);
    }

    fn diagnostic(&self) -> Option<String> {
        self.tree_diag.clone()
    }

    fn enforcement(&self) -> Option<&EnforcementReport> {
        self.report.as_ref()
    }

    fn teardown(&mut self) {
        self.report = None;
        self.plan = None;
        self.tree_diag = None;
        self.subreaper_prepare = None;
    }
}

/// Linux-only preparation: probe, plan, report at most `Configured`.
#[cfg(target_os = "linux")]
impl LinuxBackend {
    fn prepare_linux(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        ctx: &PrepareContext,
    ) -> EnforcementReport {
        // Best-effort sub-reaper so post-run orphans reparent to us where
        // the targeted sweep can see them. Failure is not fatal here: the
        // sweep reports not-clean and the run fails closed instead. The
        // outcome is recorded for the tree-sweep diagnostic string.
        self.subreaper_prepare = Some(match crate::multi::isolation::set_subreaper() {
            Ok(()) => {
                format!(
                    "ok/subreaper={}",
                    super::linux_enforce::is_child_subreaper()
                )
            }
            Err(e) => format!("ERR:{e:?}"),
        });

        let landlock_ok = crate::sandbox::linux::landlock::abi_version().is_some();
        let seccomp_ok = crate::sandbox::linux::seccomp_netblock::probe_available();
        // Only `--net=off` is isolatable without a relay backend; any other
        // mode keeps NetworkIsolation honestly Unsupported.
        let net_off = policy.net_mode == "off";

        let mut states = BTreeMap::new();
        let mut set = |cap: SecurityCapability, ok: bool| {
            states.insert(
                cap,
                if ok {
                    EnforcementState::Configured
                } else {
                    EnforcementState::Unsupported
                },
            );
        };
        set(SecurityCapability::FilesystemIsolation, landlock_ok);
        set(SecurityCapability::ExecutionRootIsolation, landlock_ok);
        set(SecurityCapability::NetworkIsolation, net_off && seccomp_ok);
        set(SecurityCapability::SyscallRestriction, seccomp_ok);
        // Process group + NO_NEW_PRIVS need no kernel features beyond
        // baseline Linux; the tree sweep additionally needs our sub-reaper,
        // which is attempted above and re-checked at sweep time.
        set(SecurityCapability::ProcessIsolation, true);
        set(SecurityCapability::ProcessTreeContainment, true);
        set(SecurityCapability::ResourceLimits, true);
        states.insert(SecurityCapability::HostEvidence, EnforcementState::Enforced);

        // Child-side plan mirrors the report: disabled mechanisms are
        // omitted, never stubbed. Without Landlock there is no filesystem
        // plan at all (fail-closed per capability, not a fake filter).
        let system_ro: Vec<std::path::PathBuf> = if landlock_ok {
            super::linux_enforce::SYSTEM_ROOTS
                .iter()
                .map(std::path::PathBuf::from)
                .collect()
        } else {
            Vec::new()
        };
        self.plan = Some(ChildEnforcementPlan {
            landlock: landlock_ok,
            exec_root: policy.cwd.clone(),
            extra_rw: ctx.extra_rw.clone(),
            system_ro,
            net_deny: net_off,
            harden_syscalls: seccomp_ok,
            rlimit_as: Some(super::linux_enforce::DEFAULT_RLIMIT_AS_BYTES),
            rlimit_nproc: Some(super::linux_enforce::DEFAULT_RLIMIT_NPROC),
            rlimit_cpu: Some(super::linux_enforce::DEFAULT_RLIMIT_CPU_SECS),
            rlimit_fsize: Some(super::linux_enforce::DEFAULT_RLIMIT_FSIZE_BYTES),
            new_pgroup: true,
        });

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
}

/// Stage 3C macOS backend: real Seatbelt enforcement (SBPL write isolation
/// + `--net=off` network denial via `sandbox_init_with_parameters`,
/// `setrlimit` ceilings, new process group, kqueue parent-death watchdog).
///
/// State machine per run, mirroring `LinuxBackend`: `prepare` probes and
/// reports at most `Configured` (`HostEvidence` is `Enforced` by
/// construction); a successful Seatbelt-confined spawn promotes to
/// `Enforced`; host-observed `getpgid` / group-death evidence promotes
/// process/tree containment to `Verified`.
///
/// Honest scope (partial, documented, never faked):
/// - `FilesystemIsolation` = WRITE isolation only (SBPL write roots +
///   secret tail-denies). Reads are broad by platform necessity, so
///   `ExecutionRootIsolation` stays `Unsupported`.
/// - `SyscallRestriction` stays `Unsupported`: Seatbelt is not a syscall
///   filter and macOS has no seccomp equivalent; nothing is emulated.
/// - `ResourceLimits` are best-effort (`setrlimit` refusals are surfaced on
///   the child stderr, never fatal): promoted to `Enforced` on a successful
///   spawn, never to `Verified` (no remote-rlimit observation API).
/// - Filesystem/network isolation likewise stay at `Enforced`: installed
///   without error, effect proven behaviorally by adversarial tests; only
///   host-observed process/tree state promotes to `Verified`.
/// - Relay network modes (`allowlist`/`strict`/`ask`) have no macOS
///   mechanism and fail preparation closed (`preparation_ok == false`,
///   `NetworkIsolation` = `Failed`).
///
/// Off macOS every capability stays `Unsupported` (no portability hacks).
#[derive(Debug, Clone, Default)]
pub struct MacosBackend {
    report: Option<EnforcementReport>,
    tree_diag: Option<String>,
}

impl MacosBackend {
    pub fn new() -> Self {
        MacosBackend {
            report: None,
            tree_diag: None,
        }
    }

    /// Upgrade every `Configured` record to `Enforced` in the stored report.
    fn promote_configured_to_enforced(&mut self) {
        if let Some(report) = self.report.as_mut() {
            for record in &mut report.records {
                if record.state == EnforcementState::Configured {
                    record.state = EnforcementState::Enforced;
                }
            }
        }
    }

    /// Fail every installed-or-planned record with `kind` and fail closed.
    fn fail_installed(&mut self, kind: PreparationFailureKind) {
        if let Some(report) = self.report.as_mut() {
            for record in &mut report.records {
                match record.state {
                    EnforcementState::Configured
                    | EnforcementState::Enforced
                    | EnforcementState::Verified => {
                        record.state = EnforcementState::Failed;
                        record.failure = Some(kind);
                    }
                    _ => {}
                }
            }
            report.preparation_ok = false;
        }
    }
}

impl SandboxBackend for MacosBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Macos
    }

    fn name(&self) -> &'static str {
        "macos (seatbelt write+net-off+rlimit+pgroup; no seccomp, reads broad)"
    }

    fn supports(&self, capability: SecurityCapability) -> bool {
        #[cfg(target_os = "macos")]
        {
            matches!(
                capability,
                SecurityCapability::FilesystemIsolation
                    | SecurityCapability::NetworkIsolation
                    | SecurityCapability::ProcessIsolation
                    | SecurityCapability::ProcessTreeContainment
                    | SecurityCapability::ResourceLimits
                    | SecurityCapability::HostEvidence
            )
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = capability;
            false
        }
    }

    fn prepare(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
    ) -> EnforcementReport {
        self.prepare_with_context(policy, identity, &PrepareContext::default())
    }

    fn prepare_with_context(
        &mut self,
        policy: &CanonicalPolicy,
        identity: &ExecutionIdentity,
        ctx: &PrepareContext,
    ) -> EnforcementReport {
        let _ = ctx;
        self.tree_diag = None;
        #[cfg(not(target_os = "macos"))]
        {
            let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
                .into_iter()
                .map(|c| (c, EnforcementState::Unsupported))
                .collect();
            let report = EnforcementReport::build(
                BackendKind::Macos,
                policy,
                identity,
                &states,
                &BTreeMap::new(),
                true,
            );
            self.report = Some(report.clone());
            report
        }
        #[cfg(target_os = "macos")]
        {
            // Only `--net=off` is isolatable without a relay backend; any
            // other mode fails preparation closed (no spawn possible).
            if policy.net_mode != "off" {
                let mut states: BTreeMap<SecurityCapability, EnforcementState> =
                    SecurityCapability::all()
                        .into_iter()
                        .map(|c| (c, EnforcementState::Unsupported))
                        .collect();
                states.insert(
                    SecurityCapability::NetworkIsolation,
                    EnforcementState::Failed,
                );
                let mut failures = BTreeMap::new();
                failures.insert(
                    SecurityCapability::NetworkIsolation,
                    PreparationFailureKind::UnsupportedOnPlatform,
                );
                let report = EnforcementReport::build(
                    BackendKind::Macos,
                    policy,
                    identity,
                    &states,
                    &failures,
                    false,
                );
                self.report = Some(report.clone());
                return report;
            }
            let mut states = BTreeMap::new();
            let mut set = |cap: SecurityCapability, ok: bool| {
                states.insert(
                    cap,
                    if ok {
                        EnforcementState::Configured
                    } else {
                        EnforcementState::Unsupported
                    },
                );
            };
            set(SecurityCapability::FilesystemIsolation, true);
            set(SecurityCapability::NetworkIsolation, true);
            set(SecurityCapability::ProcessIsolation, true);
            set(SecurityCapability::ProcessTreeContainment, true);
            set(SecurityCapability::ResourceLimits, true);
            // No syscall filter on macOS; reads are broad by platform
            // necessity (write isolation is the enforced boundary).
            set(SecurityCapability::SyscallRestriction, false);
            set(SecurityCapability::ExecutionRootIsolation, false);
            states.insert(SecurityCapability::HostEvidence, EnforcementState::Enforced);
            let report = EnforcementReport::build(
                BackendKind::Macos,
                policy,
                identity,
                &states,
                &BTreeMap::new(),
                true,
            );
            self.report = Some(report.clone());
            report
        }
    }

    fn note_spawned(&mut self, _pid: u32) {
        self.promote_configured_to_enforced();
    }

    fn note_host_verified(&mut self, verification: &HostVerification) {
        let Some(report) = self.report.as_mut() else {
            return;
        };
        // macOS has no `NoNewPrivs`/seccomp/remote-rlimit indicators: the
        // only host-observable installation proof is the separate process
        // group. Everything else stays `Enforced`, honestly unverified.
        if verification.pgroup_separate {
            if let Some(record) = report
                .records
                .iter_mut()
                .find(|r| r.capability == SecurityCapability::ProcessIsolation)
            {
                if record.state == EnforcementState::Enforced {
                    record.state = EnforcementState::Verified;
                }
            }
        }
    }

    fn note_failed(&mut self, kind: PreparationFailureKind) {
        self.fail_installed(kind);
    }

    fn note_tree_clean(&mut self, clean: bool) {
        let Some(report) = self.report.as_mut() else {
            return;
        };
        if let Some(record) = report
            .records
            .iter_mut()
            .find(|r| r.capability == SecurityCapability::ProcessTreeContainment)
        {
            match record.state {
                EnforcementState::Enforced if clean => {
                    record.state = EnforcementState::Verified;
                }
                EnforcementState::Enforced | EnforcementState::Configured if !clean => {
                    // Post-run sweep outcome, not a preparation failure:
                    // only the tree capability fails. `preparation_ok`
                    // stays untouched so one dirty tree cannot demote
                    // unrelated enforced caps.
                    record.state = EnforcementState::Failed;
                    record.failure = Some(PreparationFailureKind::VerificationUnavailable);
                }
                _ => {}
            }
        }
    }

    fn note_diagnostic(&mut self, diag: String) {
        self.tree_diag = Some(diag);
    }

    fn diagnostic(&self) -> Option<String> {
        self.tree_diag.clone()
    }

    fn enforcement(&self) -> Option<&EnforcementReport> {
        self.report.as_ref()
    }

    fn teardown(&mut self) {
        self.report = None;
        self.tree_diag = None;
    }
}

/// Stage 3A Windows placeholder. No Job Object, AppContainer, network, or
/// filesystem containment is claimed; every capability stays `Unsupported`.
/// Environment variables, HOME changes, working directories, and
/// application conventions are never represented as containment.
#[derive(Debug, Clone, Default)]
pub struct WindowsBackend {
    report: Option<EnforcementReport>,
}

impl WindowsBackend {
    pub fn new() -> Self {
        WindowsBackend { report: None }
    }
}

impl SandboxBackend for WindowsBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Windows
    }

    fn name(&self) -> &'static str {
        "windows (Stage 3A placeholder; no enforcement yet)"
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
            .map(|c| (c, EnforcementState::Unsupported))
            .collect();
        let report = EnforcementReport::build(
            BackendKind::Windows,
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

/// Select a backend implementation by kind. Stage 3B wires real Linux
/// enforcement behind this boundary; Stage 3C-macOS wires real Seatbelt
/// enforcement; Windows stays a placeholder.
pub fn select_backend(kind: BackendKind) -> Box<dyn SandboxBackend> {
    match kind {
        BackendKind::Direct => Box::new(DirectBackend::new()),
        BackendKind::Linux => Box::new(LinuxBackend::new()),
        BackendKind::Macos => Box::new(MacosBackend::new()),
        BackendKind::Windows => Box::new(WindowsBackend::new()),
    }
}

/// One machine-readable matrix cell: static support for a
/// (backend, capability) pair. `supported=false` is the honest Stage 3A
/// default for every containment cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixEntry {
    pub backend: BackendKind,
    pub capability: SecurityCapability,
    pub supported: bool,
}

/// Typed platform security matrix. At Stage 3A most cells are
/// `supported=false`; the purpose is architectural correctness, not a
/// claim that Stage 3 is complete.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformMatrix {
    pub entries: Vec<MatrixEntry>,
}

impl PlatformMatrix {
    /// Build the matrix from each backend's static [`supports`] report, in
    /// a fixed (backend, capability) order.
    pub fn current() -> Self {
        let mut entries = Vec::new();
        for kind in BackendKind::all() {
            let backend = select_backend(kind);
            for capability in SecurityCapability::all() {
                entries.push(MatrixEntry {
                    backend: kind,
                    capability,
                    supported: backend.supports(capability),
                });
            }
        }
        PlatformMatrix { entries }
    }

    pub fn supports(&self, backend: BackendKind, capability: SecurityCapability) -> bool {
        self.entries
            .iter()
            .find(|e| e.backend == backend && e.capability == capability)
            .map(|e| e.supported)
            .unwrap_or(false)
    }

    /// Deterministic text rendering (`backend capability supported`) with
    /// one row per cell, for logs and machine consumers.
    pub fn render(&self) -> String {
        let mut rows: Vec<String> = self
            .entries
            .iter()
            .map(|e| {
                format!(
                    "{} {} {}",
                    e.backend.label(),
                    e.capability.label(),
                    if e.supported {
                        "supported"
                    } else {
                        "unsupported"
                    }
                )
            })
            .collect();
        rows.sort();
        rows.join("\n")
    }
}

/// Mandatory capabilities for a scenario's category. Blocker categories
/// require their primary containment capability plus [`HostEvidence`];
/// `Aux` plumbing scenarios require only [`HostEvidence`], preserving the
/// Stage 2 Unix Aux live-protocol PASS while every containment claim stays
/// fail-closed on unimplemented backends. `ResourceLimits` and
/// `SyscallRestriction` are really enforced and host-verified on Linux
/// (Stage 3B) and asserted per-test; the PASS gate stays on the primary
/// containment caps plus `HostEvidence` because blocker verdicts additionally
/// require Aux-only bound nonces and can never PASS off-Aux regardless.
pub fn required_capabilities(scenario: &Scenario) -> Vec<SecurityCapability> {
    match scenario.category {
        Category::Aux => vec![SecurityCapability::HostEvidence],
        Category::Spawn => vec![
            SecurityCapability::ProcessIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::FsRead | Category::FsWrite => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::ExecutionRootIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::Net => vec![
            SecurityCapability::NetworkIsolation,
            SecurityCapability::HostEvidence,
        ],
        Category::Proc => vec![
            SecurityCapability::ProcessIsolation,
            SecurityCapability::ProcessTreeContainment,
            SecurityCapability::HostEvidence,
        ],
        Category::Secrets => vec![
            SecurityCapability::FilesystemIsolation,
            SecurityCapability::HostEvidence,
        ],
    }
}

/// Pure fail-closed gate: true only when the report's preparation
/// succeeded and every mandatory capability for `scenario` is actually
/// enforced. Never consults child output.
pub fn allows_pass(report: &EnforcementReport, scenario: &Scenario) -> bool {
    report.allows_pass(&required_capabilities(scenario))
}

/// Pure backend ceiling over an oracle verdict: a `PASS` without actual
/// enforcement of the scenario's mandatory capabilities demotes to
/// `INCONCLUSIVE`. Never upgrades (`Unsupported` cannot become `Partial`
/// or `Strong` here); non-`PASS` verdicts pass through unchanged so the
/// correct `FAIL`/`INCONCLUSIVE`/`NOT_APPLICABLE` semantics stay intact.
pub fn apply_backend_ceiling(
    verdict: Verdict,
    report: &EnforcementReport,
    scenario: &Scenario,
) -> Verdict {
    match verdict {
        Verdict::Pass if !allows_pass(report, scenario) => Verdict::Inconclusive,
        other => other,
    }
}

#[cfg(test)]
mod backend_arch_tests {
    use super::*;
    use crate::verify_ng::model::ClaimStrength;
    use crate::verify_ng::registry::Severity;
    use std::collections::BTreeMap;

    fn test_scenario(id: &str, category: Category) -> Scenario {
        Scenario {
            id: id.to_string(),
            category,
            severity: Severity::High,
            required_caps: Vec::new(),
            strength: BTreeMap::from([("linux-full".to_string(), ClaimStrength::Strong)]),
            quorum: 1,
            known_limitation: "backend-arch unit test".to_string(),
            residual_risk: String::new(),
        }
    }

    fn test_policy_and_identity() -> (CanonicalPolicy, ExecutionIdentity) {
        let spec = FrozenSpec {
            scenario_id: "TEST-BACKEND-001".to_string(),
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
        };
        let policy = CanonicalPolicy::from_frozen(&spec);
        let identity = ExecutionIdentity::new(
            "TEST-BACKEND-001",
            "nonce-test",
            "reg-test",
            policy.frozen_hash.as_str(),
        );
        (policy, identity)
    }

    /// TEST-BACKEND-CAPABILITY-001: backends report capabilities explicitly.
    #[test]
    fn test_backend_capability_001_reports_explicitly() {
        for kind in BackendKind::all() {
            let backend = select_backend(kind);
            assert_eq!(backend.kind(), kind);
            assert!(!backend.name().is_empty());
            let mut seen = std::collections::BTreeSet::new();
            for cap in SecurityCapability::all() {
                let supported = backend.supports(cap);
                let _ = supported;
                assert!(seen.insert(cap), "each capability reported once");
            }
            assert_eq!(seen.len(), SecurityCapability::all().len());
            let listed = backend.supported_capabilities();
            for cap in &listed {
                assert!(backend.supports(*cap));
            }
            assert_eq!(
                listed.len(),
                listed
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
            );
        }
        let matrix = PlatformMatrix::current();
        assert_eq!(
            matrix.entries.len(),
            BackendKind::all().len() * SecurityCapability::all().len()
        );
        assert!(matrix.render().contains("direct host-evidence supported"));
    }

    /// TEST-BACKEND-UNSUPPORTED-001: unsupported mandatory capability cannot PASS.
    #[test]
    fn test_backend_unsupported_001_cannot_pass() {
        let scenario = test_scenario("TEST-BACKEND-UNSUPPORTED-001", Category::FsRead);
        let (policy, identity) = test_policy_and_identity();
        let mut backend = LinuxBackend::new();
        let report = backend.prepare(&policy, &identity);
        assert!(!report.is_enforced(SecurityCapability::FilesystemIsolation));
        assert!(!allows_pass(&report, &scenario));
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

    /// TEST-BACKEND-POLICY-001: canonical policy crosses the boundary unmutated.
    #[test]
    fn test_backend_policy_001_no_platform_mutation() {
        let (policy, identity) = test_policy_and_identity();
        let policy_before = policy.clone();
        let mut backend = LinuxBackend::new();
        let report = backend.prepare(&policy, &identity);
        assert_eq!(policy, policy_before, "backend must not mutate policy");
        assert_eq!(report.policy_hash, policy.policy_hash);
        assert_eq!(report.frozen_hash, policy.frozen_hash);
        let again = CanonicalPolicy::from_frozen(&FrozenSpec {
            scenario_id: policy.scenario_id.clone(),
            registry_hash: policy.registry_hash.clone(),
            tier: policy.tier.clone(),
            net_mode: policy.net_mode.clone(),
            backend: policy.backend_hint.clone(),
            argv: policy.argv.clone(),
            env: policy.env.clone(),
            cwd: policy.cwd.clone(),
            allow_read: Vec::new(),
            allow_write: Vec::new(),
            deny_read: Vec::new(),
            deny_write: Vec::new(),
            deny_resolved: Vec::new(),
            nonce: policy.session_nonce.clone(),
            policy_bytes: policy.policy_bytes.clone(),
        });
        assert_eq!(policy, again, "same frozen input is stable");
    }

    /// TEST-BACKEND-IDENTITY-001: execution state binds scenario/session/registry/frozen.
    #[test]
    fn test_backend_identity_001_binds_execution() {
        let (policy, identity) = test_policy_and_identity();
        let mut backend = DirectBackend::new();
        let report = backend.prepare(&policy, &identity);
        assert!(report.binds_identity(&identity));
        let mut foreign = identity.clone();
        foreign.session_nonce = "other-nonce".to_string();
        assert!(!report.binds_identity(&foreign));
        let mut foreign = identity.clone();
        foreign.scenario_id = "OTHER".to_string();
        assert!(!report.binds_identity(&foreign));
        let mut foreign = identity.clone();
        foreign.registry_hash = "other-reg".to_string();
        assert!(!report.binds_identity(&foreign));
        let mut foreign = identity.clone();
        foreign.frozen_hash = "other-frozen".to_string();
        assert!(!report.binds_identity(&foreign));
    }

    /// TEST-BACKEND-FAIL-CLOSED-001: preparation failure cannot become success.
    #[test]
    fn test_backend_fail_closed_001_failure_never_passes() {
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
        let scenario = test_scenario("TEST-BACKEND-FAIL-CLOSED-001", Category::Aux);
        let (policy, identity) = test_policy_and_identity();
        let mut backend = FailingBackend { report: None };
        let report = backend.prepare(&policy, &identity);
        assert!(!report.preparation_ok);
        assert!(!report.failed().is_empty());
        assert!(!allows_pass(&report, &scenario));
        assert_eq!(
            apply_backend_ceiling(Verdict::Pass, &report, &scenario),
            Verdict::Inconclusive
        );
    }

    /// TEST-BACKEND-NO-FAKE-ENFORCEMENT-001: unsupported is never enforced.
    /// Stage 3B: `prepare` reports at most `Configured` (never `Enforced`
    /// or `Verified` — nothing is installed until a backend-controlled
    /// spawn); macOS/Windows placeholders stay fully `Unsupported`.
    #[test]
    fn test_backend_no_fake_enforcement_001() {
        let (policy, identity) = test_policy_and_identity();
        for kind in [BackendKind::Macos, BackendKind::Windows] {
            let mut backend = select_backend(kind);
            let report = backend.prepare(&policy, &identity);
            for cap in SecurityCapability::all() {
                assert!(
                    !report.is_enforced(cap),
                    "{kind:?} {cap:?} must not be enforced"
                );
                assert_ne!(report.state(cap), EnforcementState::Enforced);
                assert_ne!(report.state(cap), EnforcementState::Verified);
            }
            assert_eq!(
                report.state(SecurityCapability::FilesystemIsolation),
                EnforcementState::Unsupported
            );
        }
        // Linux `prepare` probes and plans but installs no confinement:
        // containment states are `Configured` or `Unsupported`, never
        // `Enforced`/`Verified`, so no PASS is possible before a real
        // spawn. `HostEvidence` (wait/kill/sentinel observation machinery)
        // is `Enforced` at prepare like on Direct — it needs no child
        // setup to exist.
        {
            let mut backend = select_backend(BackendKind::Linux);
            let report = backend.prepare(&policy, &identity);
            for cap in SecurityCapability::all() {
                if cap == SecurityCapability::HostEvidence {
                    continue;
                }
                assert!(
                    !report.is_enforced(cap),
                    "Linux {cap:?} must not be enforced before spawn"
                );
                assert_ne!(report.state(cap), EnforcementState::Enforced);
                assert_ne!(report.state(cap), EnforcementState::Verified);
            }
            #[cfg(target_os = "linux")]
            {
                assert!(report.preparation_ok);
            }
        }
        let mut direct = DirectBackend::new();
        let report = direct.prepare(&policy, &identity);
        assert!(report.is_enforced(SecurityCapability::HostEvidence));
        for cap in SecurityCapability::all() {
            if cap != SecurityCapability::HostEvidence {
                assert!(!report.is_enforced(cap));
            }
        }
    }

    /// TEST-BACKEND-ORACLE-PURITY-001: oracle stays pure; backend gate is pure.
    #[test]
    fn test_backend_oracle_purity_001() {
        use crate::verify_ng::evidence::Evidence;
        use crate::verify_ng::oracle::{judge, OracleInput};
        let scenario = test_scenario("TEST-BACKEND-ORACLE-PURITY-001", Category::Aux);
        let id = ExecutionIdentity::new(
            "TEST-BACKEND-ORACLE-PURITY-001",
            "nonce-1",
            "reg-test",
            "frozen-test",
        );
        let expected =
            crate::verify_ng::evidence::derive_expected_response("test-challenge", "nonce-1");
        let verified =
            crate::verify_ng::evidence::attest_control(&id, &expected, expected.as_bytes())
                .expect("mint");
        let mut evidence = Evidence::default();
        evidence.host_fact("wait-status", "exit=0".to_string());
        evidence.host_control_fact(&verified);
        let input = OracleInput {
            scenario: &scenario,
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
        let first = judge(&input);
        let second = judge(&input);
        assert_eq!(
            first, second,
            "oracle is deterministic over structured input"
        );
        assert_eq!(first, Verdict::Pass);
        let (policy, _) = test_policy_and_identity();
        let policy_identity = ExecutionIdentity::new(
            "TEST-BACKEND-ORACLE-PURITY-001",
            "nonce-1",
            "reg-test",
            "frozen-test",
        );
        let mut backend = DirectBackend::new();
        let report = backend.prepare(&policy, &policy_identity);
        let gated = apply_backend_ceiling(first, &report, &scenario);
        assert_eq!(apply_backend_ceiling(first, &report, &scenario), gated);
    }
}
