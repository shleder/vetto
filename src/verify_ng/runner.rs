//! Engine -> Policy -> SandboxBackend -> Execution -> Oracle pipeline.
//!
//! Minimal real runner: one [`run_one`] call executes exactly one scenario
//! as exactly one spawned child and hands host-observed facts to the
//! existing oracle. Pipeline order per scenario (Stage 3A backend boundary):
//!
//! ```text
//! poison check (no spawn when poisoned)
//! -> fixture + isolated HOME + FrozenSpec (full-registry hash)
//! -> CanonicalPolicy (platform-independent projection of FrozenSpec)
//! -> control channel (host-owned, before prepare so its dir is confinable)
//! -> SandboxBackend::prepare_with_context (structured report, fail-closed)
//! -> backend-controlled spawn exactly once (pre_exec plan, single site)
//! -> host verification from /proc while the child lives
//! -> killer: deadline poll via `kill_on_deadline_with` (never blocking wait)
//! -> collector: drain stdio with deadline, re-observe exit status
//! -> tree sweep (confined runs: nonce-targeted sub-reaper sweep)
//! -> post-mortem: payload integrity, sentinel sweep (host reads)
//! -> teardown (backend cleanup, idempotent)
//! -> host evidence -> oracle (pure) + backend ceiling -> redacted ScenarioResult
//! ```
//!
//! [`run_one`] runs through [`super::sandbox_backend::DirectBackend`]
//! (explicitly non-contained); [`run_one_with_backend`] accepts any
//! [`super::sandbox_backend::SandboxBackend`]. Stage 3B wires real Linux
//! enforcement (landlock + seccomp + rlimit + process-group/tree sweep)
//! behind the same trait; macOS/Windows stay placeholders. The oracle stays
//! pure throughout: every Linux fact is collected host-side and judged as
//! structured data.
//!
//! Provenance rules (Blocker 1 audit + Stage 2 challenge-response):
//! - HOST_FACT is only what the host observes independently of
//!   attacker-controlled reporting: wait status (kernel), kill outcome
//!   (own poll loop), payload/sentinel hashes (host-held pre-images), and
//!   the verified challenge response (exact rotated response arriving on
//!   the host-held uplink end, see [`super::host_evidence`]).
//! - NOT HOST_FACT: stdout, stderr, child env, files created by the child
//!   (including any `control.txt` the child writes anywhere it can reach),
//!   child-written markers, hashes over attacker-only post-run data, the
//!   control FIFO path capabilities on their own, and the challenge echoed
//!   back unrotated — echoing verifier material anywhere is ignored.
//! - Non-self-authorization invariant: the host NEVER issues a value whose
//!   echo counts as control. The expected response derives from a fresh
//!   per-execution challenge the child only obtains by reading the host
//!   downlink, plus a rotation the child must apply. Only a successful
//!   verification mints a `VerifiedControl` and stamps the identity-bound
//!   `control` HOST_FACT; the oracle then requires that fact's provenance
//!   to equal the current [`super::evidence::ExecutionIdentity`].
//!   `probe_nonce`/`control_nonce` are `Some` only on that verified path
//!   (and only for `Aux` pipeline scenarios — see below); otherwise they
//!   stay `None` and PASS is structurally unreachable: the best honest
//!   outcome is INCONCLUSIVE, or FAIL on host-observed violation.
//! - PASS-capability gate: the protocol proves live challenge-response
//!   execution, never containment. PASS-capable oracle input (bound nonces
//!   and the quorum vector) is assembled from a verified response for
//!   `Aux` scenarios only. Blocker categories keep `probe_nonce` and
//!   `control_nonce` at `None` with `agreeing_vectors` at 0 on direct-exec,
//!   so they stay INCONCLUSIVE (or FAIL on violation) no matter what the
//!   child writes. Direct execution is not a sandbox and claims no
//!   containment.
//!
//! Hard rules:
//! - No retries: a failed collection stays INCONCLUSIVE (or FAIL when the
//!   oracle already holds host-observed violation proof). Never spawn again
//!   to turn a failure into a PASS. Suite-level ownership lives in
//!   [`SuiteRunner`]: one scenario id executes at most once per suite.
//! - stdout/stderr are attacker-controlled: stored as `SELF_REPORT` only,
//!   never `HOST_FACT`. No verdict branch reads child text.
//! - PASS additionally requires complete collection (`eof && !truncated`);
//!   the oracle enforces this itself via `stdio_complete`.
//! - Direct-exec backend: the child runs without sandbox enforcement. There
//!   is no tree kill and no sweep here: orphaned grandchildren are a
//!   documented residual in the same class as the FS-ONLY BestEffort
//!   residual. The drain deadline still bounds collection, so a grandchild
//!   holding the pipe cannot hang us.
//! - Linux backend (Stage 3B): the child installs the backend plan in
//!   `pre_exec` (landlock + seccomp + rlimits + new process group) and the
//!   host group-kills plus nonce-sweeps after reaping, so lingering
//!   grandchildren are killed and observed instead of documented away.
//! - Env base passes through the existing `envfilter` boundary; `HOME` is
//!   always a fresh per-run directory, never shared. That is distinctness,
//!   not filesystem isolation: direct execution proves no containment.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::collector::collect_child_stdio;
use super::engine;
use super::evidence::{Evidence, ExecutionIdentity};
use super::fixture::{hash_bytes, Fixture};
use super::frozen;
use super::host_evidence::{ControlChannel, CONTROL_READ_BUDGET};
use super::killer::{self, KillOutcome, WaitKill};
use super::model::{Category, ScenarioResult};
use super::oracle;
use super::redact;
use super::sandbox_backend::{BackendKind, CanonicalPolicy, EnforcementReport, SandboxBackend};

/// Backend label for direct (unsandboxed) plumbing runs.
pub const DIRECT_BACKEND: &str = "direct-exec (no sandbox; plumbing only)";
/// Tier label for direct runs: no enforcement tier applies.
pub const DIRECT_TIER: &str = "direct";
/// Default per-scenario execution deadline.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(30);
/// Poll interval for non-blocking exit observation.
pub const EXIT_POLL: Duration = Duration::from_millis(10);
/// Budget for draining stdio after termination.
pub const DRAIN_BUDGET: Duration = Duration::from_secs(5);
/// Per-stream capture cap.
pub const MAX_STDIO_BYTES: usize = 1 << 20;
/// Harness <-> child contract: env names (see `harness_env` below).
/// `VETTO_VNG_NONCE` is a run label, not a secret and not proof: nothing
/// host-side trusts a child-presented nonce on this backend. The Stage 2
/// control capabilities (`VETTO_VNG_CONTROL_DOWNLINK` /
/// `VETTO_VNG_CONTROL_UPLINK`, see [`super::host_evidence`]) are transport,
/// not proof either: no child-reachable pathname or env value is
/// authoritative for the verdict — only arrival of the exact rotated
/// challenge response on the host-held uplink end counts, after host-side
/// verification. No PASS-capable value is ever issued via env.
pub const ENV_NONCE: &str = "VETTO_VNG_NONCE";
pub const ENV_HOME: &str = "VETTO_VNG_HOME";
pub const ENV_ROOT: &str = "VETTO_VNG_ROOT";
/// Fixture-relative path of the staged payload script.
pub const PAYLOAD_REL: &str = "run.sh";
/// HOME-relative path the child uses for the distinctness marker probe.
/// Host-read for plumbing diagnostics only; never evidence.
pub const HOME_MARKER_REL: &str = "marker.txt";

/// Host-observable count of runner spawns in this process (ops counter).
/// The per-run single-spawn proof is the caller-owned [`SpawnLog`], which
/// stays exact under parallel test threads; this counter is informational.
pub static RUNNER_SPAWN_COUNT: AtomicU64 = AtomicU64::new(0);

/// One spawn event, appended to the caller-owned log at the single spawn
/// site. `run_id` equals the run nonce, binding the event to the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnEvent {
    pub run_id: String,
    pub pid: u32,
}

/// Caller-owned spawn ledger: exactly one entry per [`run_one`] call proves
/// the one-spawn invariant without trusting child output.
pub type SpawnLog = Vec<SpawnEvent>;

/// What to execute for one scenario. The payload script is staged into the
/// fixture and executed by path (never via `sh -c` inline text), so the
/// pre/post hash actually covers what ran.
pub struct ExecutionRequest<'a> {
    pub scenario: &'a super::registry::Scenario,
    pub policy: &'a crate::policy::Policy,
    pub net_mode: &'a crate::config::NetMode,
    /// Interpreter argv prefix, e.g. `["sh"]` or `["sh", "-e"]`.
    pub interpreter: Vec<String>,
    /// Extra args appended after the staged script path.
    pub script_args: Vec<String>,
    /// Payload script bytes, staged at [`PAYLOAD_REL`] and hashed.
    pub script: Vec<u8>,
    /// Protected fixture files `(rel, bytes)`: staged under the fixture
    /// root with pre-hashes; any post-run mismatch is host-observed
    /// violation evidence (-> FAIL via the oracle).
    pub sentinels: Vec<(String, Vec<u8>)>,
    /// Extra env over the filtered base + harness contract.
    pub env_extra: BTreeMap<String, String>,
    /// Execution deadline for the wait/kill stage.
    pub deadline: Duration,
    /// Opt in to the host-owned challenge-response channel (Stage 2). When
    /// true, the host creates a per-execution downlink/uplink FIFO pair +
    /// fresh challenge before spawn and verifies the rotated response after
    /// collection. The child is expected to read `$VETTO_VNG_CONTROL_DOWNLINK`,
    /// rotate per the documented transform, and answer via
    /// `$VETTO_VNG_CONTROL_UPLINK`; echoing verifier material via any medium
    /// is ignored. PASS-capable oracle input is assembled from a verified
    /// response for `Aux` pipeline scenarios only — blocker categories stay
    /// INCONCLUSIVE/FAIL on direct-exec by construction.
    pub enable_host_control: bool,
}

/// Host-observed outcome of one scenario run.
#[derive(Debug)]
pub struct ExecutionOutcome {
    pub result: ScenarioResult,
    pub nonce: String,
    /// Session identity for this execution: scenario, session nonce,
    /// registry hash and frozen-spec hash; immutable since before spawn.
    /// Verified control facts in [`ExecutionOutcome::evidence`] are
    /// stamped against exactly this identity.
    pub execution_identity: ExecutionIdentity,
    /// Structured backend preparation outcome for this execution, when a
    /// backend was prepared. `None` only on pre-preparation failures
    /// (poison, fixture errors) and duplicate rejections.
    pub backend_report: Option<EnforcementReport>,
    /// Which backend implementation prepared this execution.
    pub backend_kind: BackendKind,
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub kill: Option<KillOutcome>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdio_eof: bool,
    pub stdio_truncated: bool,
    /// Collection completeness as fed to the oracle: `eof && !truncated`.
    pub stdio_complete: bool,
    pub evidence: Evidence,
    pub payload_intact: bool,
    pub sentinel_mutated: Vec<String>,
    /// True only when the exact rotated challenge response arrived on the
    /// host-held uplink end before the deadline (Stage 2). False when the
    /// channel is disabled, creation failed, or verification failed.
    /// For non-`Aux` scenarios a `true` here still never yields PASS on
    /// direct-exec (no containment proof); it records observed liveness.
    pub control_observed: bool,
    pub violation_observed: bool,
    /// Content of `$HOME/marker.txt` as host-read after the run, if present.
    /// Plumbing diagnostic only; never evidence.
    pub home_marker: Option<Vec<u8>>,
    pub home: PathBuf,
    pub spawn_pid: Option<u32>,
    /// True when a [`SuiteRunner`] rejected this run as a duplicate without
    /// spawning. A rejected run never upgrades an earlier verdict.
    pub duplicate_rejected: bool,
}

/// Child handle: owns `std::process::Child`. Pipes are taken at spawn so
/// the collector stage owns them outright. `pgid` is `Some` only for
/// backend-confined runs (Stage 3B Linux joins a new process group in
/// `pre_exec`): termination then signals the whole group, and the caller
/// re-issues it after a clean exit so lingering children cannot hold the
/// pipes or survive the run. `None` keeps the historical single-process
/// behavior (documented residual, same class as FS-ONLY BestEffort).
struct DirectChild {
    child: std::process::Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
    pgid: Option<i32>,
}

impl WaitKill for DirectChild {
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

/// Harness contract env: fresh per-run HOME plus run-label nonce and the
/// fixture root pointer. Built on top of [`engine::run_env`]; the caller
/// merges it over the `envfilter`-scrubbed base. No control pathname is
/// exposed: there is no child-reachable location the verdict trusts.
fn harness_env(
    home: &std::path::Path,
    root: &std::path::Path,
    nonce: &str,
) -> BTreeMap<String, String> {
    let mut env = engine::run_env(home, nonce);
    env.insert(ENV_ROOT.to_string(), root.display().to_string());
    env
}

/// Run one scenario as exactly one child process through the direct-exec
/// plumbing backend. See module docs for the stage order and hard rules.
/// Never panics on harness failures: setup or spawn errors degrade to
/// INCONCLUSIVE with no spawn logged.
pub fn run_one(req: &ExecutionRequest<'_>, spawn_log: &mut SpawnLog) -> ExecutionOutcome {
    let mut backend = super::sandbox_backend::DirectBackend::new();
    run_one_with_backend(req, spawn_log, &mut backend)
}

/// Run one scenario through an explicit [`SandboxBackend`]:
/// Engine -> Policy/FrozenSpec -> CanonicalPolicy -> `backend.prepare` ->
/// backend-controlled spawn -> collect -> teardown -> host evidence ->
/// Oracle + backend ceiling. The child-side plan (when the backend provides
/// one) is installed via `pre_exec`, so `Enforced` is unreachable for a
/// child that bypassed setup. Preparation or spawn-setup failure fails
/// closed with no spawn logged and no PASS.
pub fn run_one_with_backend(
    req: &ExecutionRequest<'_>,
    spawn_log: &mut SpawnLog,
    backend: &mut dyn SandboxBackend,
) -> ExecutionOutcome {
    let target = engine::current_target(None);
    // FM-08: poisoned diagnostic env invalidates before any spawn.
    let poison = engine::detect_env_poison(false);
    if !poison.is_empty() {
        let result = engine::poisoned_result(req.scenario, target, &poison);
        return ExecutionOutcome {
            result,
            nonce: String::new(),
            // Malformed by construction (no session ran): can never PASS.
            execution_identity: ExecutionIdentity::new(&req.scenario.id, "", "", ""),
            backend_report: None,
            backend_kind: backend.kind(),
            exit_code: None,
            timed_out: false,
            kill: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdio_eof: false,
            stdio_truncated: false,
            stdio_complete: false,
            evidence: Evidence::default(),
            payload_intact: true,
            sentinel_mutated: Vec::new(),
            control_observed: false,
            violation_observed: false,
            home_marker: None,
            home: PathBuf::new(),
            spawn_pid: None,
            duplicate_rejected: false,
        };
    }

    let nonce = engine::new_nonce();
    let backend_kind_snapshot = backend.kind();
    let fail_closed = |detail: String, home: PathBuf| ExecutionOutcome {
        result: ScenarioResult {
            id: req.scenario.id.clone(),
            category: req.scenario.category,
            strength: req.scenario.strength_for(target),
            verdict: super::model::Verdict::Inconclusive,
            detail: redact::redact_text(&redact::mask_home(&detail, &home.display().to_string())),
        },
        nonce: nonce.clone(),
        // Setup/spawn never completed: malformed identity, never PASS-capable.
        execution_identity: ExecutionIdentity::new(&req.scenario.id, nonce.as_str(), "", ""),
        backend_report: None,
        backend_kind: backend_kind_snapshot,
        exit_code: None,
        timed_out: false,
        kill: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
        stdio_eof: false,
        stdio_truncated: false,
        stdio_complete: false,
        evidence: Evidence::default(),
        payload_intact: false,
        sentinel_mutated: Vec::new(),
        control_observed: false,
        violation_observed: false,
        home_marker: None,
        home,
        spawn_pid: None,
        duplicate_rejected: false,
    };

    // Prepare: fixture (isolated HOME), staged payload + sentinels.
    let mut fixture = match Fixture::create("exec") {
        Ok(f) => f,
        Err(e) => return fail_closed(format!("fixture create failed: {e}"), PathBuf::new()),
    };
    let home = fixture.home().to_path_buf();
    let staged = match fixture.stage(PAYLOAD_REL, &req.script) {
        Ok(p) => p,
        Err(e) => return fail_closed(format!("payload stage failed: {e}"), home),
    };
    let mut sentinel_pre: Vec<(PathBuf, String)> = Vec::new();
    for (rel, bytes) in &req.sentinels {
        let abs = fixture.root().join(rel);
        if let Some(parent) = abs.parent() {
            if std::fs::create_dir_all(parent).is_err() {
                return fail_closed(format!("sentinel dir failed: {rel}"), home);
            }
        }
        if std::fs::write(&abs, bytes).is_err() {
            return fail_closed(format!("sentinel stage failed: {rel}"), home);
        }
        sentinel_pre.push((abs, hash_bytes(bytes)));
    }

    // Env: filtered base -> isolated HOME -> harness contract -> extras.
    let base = crate::sandbox::envfilter::filter_env(std::env::vars(), true);
    let mut env: BTreeMap<String, String> = base.into_iter().collect();
    env.insert("HOME".to_string(), home.display().to_string());
    #[cfg(target_os = "windows")]
    env.insert("USERPROFILE".to_string(), home.display().to_string());
    for (k, v) in harness_env(&home, fixture.root(), &nonce) {
        env.insert(k, v);
    }
    for (k, v) in &req.env_extra {
        env.insert(k.clone(), v.clone());
    }

    // FrozenSpec over the exact argv/env/cwd about to spawn (FM-03).
    // The backend label binds which backend was requested without making
    // FrozenSpec OS-specific (still plain strings); the canonical policy
    // below stays platform-independent.
    let mut argv = req.interpreter.clone();
    if argv.is_empty() || req.script.is_empty() {
        return fail_closed(
            "empty interpreter or script; refusing spawn".to_string(),
            home,
        );
    }
    argv.push(staged.display().to_string());
    argv.extend(req.script_args.iter().cloned());
    let cwd = fixture.root().to_path_buf();
    let backend_label = backend.name().to_string();
    let tier_label = DIRECT_TIER.to_string();
    // Full-registry binding (Blocker 3): the hash covers the complete
    // compiled registry semantics, never just this scenario's id.
    let registry_hash = super::registry::registry_hash_full(&super::registry::registry());
    let spec = frozen::freeze_spec(
        &req.scenario.id,
        &registry_hash,
        req.policy,
        &tier_label,
        req.net_mode,
        &backend_label,
        &argv,
        &env,
        &cwd,
        &nonce,
    );

    // Stage 2 session identity, immutable from here on (never mutated after
    // spawn): scenario + session nonce + registry hash + frozen-spec hash.
    let identity = ExecutionIdentity::new(
        &req.scenario.id,
        nonce.as_str(),
        registry_hash.as_str(),
        spec.hash().as_str(),
    );
    // Backend boundary: project FrozenSpec into the platform-independent
    // CanonicalPolicy and prepare the backend. The preparation report is
    // the only enforcement claim the verifier trusts; policy text alone
    // never implies containment. The host-owned control channel is created
    // BEFORE preparation so its directory can join the confinement
    // allowlist (transport, bound via the identity — never via policy).
    let canonical = CanonicalPolicy::from_frozen(&spec);
    let control_channel: Option<ControlChannel> = if req.enable_host_control {
        ControlChannel::create(&identity).ok()
    } else {
        None
    };
    let mut extra_rw = Vec::new();
    if let Some(channel) = control_channel.as_ref() {
        for (k, v) in channel.env_entries() {
            if k == super::host_evidence::ENV_CONTROL_UPLINK {
                let path = std::path::Path::new(&v);
                if let Some(parent) = path.parent() {
                    extra_rw.push(parent.to_path_buf());
                }
            }
        }
    }
    let prepare_ctx = super::sandbox_backend::PrepareContext { extra_rw };
    backend.prepare_with_context(&canonical, &identity, &prepare_ctx);
    let backend_kind = backend.kind();
    let prepared_ok = backend
        .enforcement()
        .map(|report| report.preparation_ok && report.binds_identity(&identity))
        .unwrap_or(false);
    if !prepared_ok {
        let detail = format!(
            "backend preparation failed (fail-closed, no spawn): backend={} {}",
            backend_kind.label(),
            req.scenario.known_limitation,
        );
        let mut outcome = fail_closed(detail, home);
        outcome.backend_report = backend.enforcement().cloned();
        outcome.backend_kind = backend_kind;
        backend.teardown();
        return outcome;
    }
    // Frozen env snapshot for the FM-03 continuity re-freeze below: the
    // control path capabilities are transport merged AFTER the freeze, so
    // both freezes cover the same pre-channel launch context while the
    // response binds the session nonce and the stamped provenance binds
    // the frozen hash in the other direction.
    let spec_env = env.clone();
    // Merge the control transport now (host holds the read end across the
    // spawn; creation failure degrades to control-unobserved, never PASS).
    // Dropping the channel here would remove the FIFOs, so it is moved
    // into the post-spawn stage below.
    if let Some(channel) = control_channel.as_ref() {
        for (k, v) in channel.env_entries() {
            env.insert(k, v);
        }
    }
    // Backend-controlled spawn plan: installed in the forked child before
    // exec, so `Enforced` is unreachable for a child that bypassed setup.
    let child_plan = backend.pre_exec_plan();
    #[cfg(not(unix))]
    if child_plan.is_some() {
        let detail = format!(
            "backend plan without unix spawn support (fail-closed): backend={} {}",
            backend_kind.label(),
            req.scenario.known_limitation,
        );
        let mut outcome = fail_closed(detail, home);
        outcome.backend_report = backend.enforcement().cloned();
        outcome.backend_kind = backend_kind;
        backend.teardown();
        return outcome;
    }

    // THE single spawn site for this pipeline: one run_one = one spawn.
    // No retry path exists below; every failure after this point degrades
    // the verdict, never re-spawns.
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
        if let Some(plan) = child_plan {
            // SAFETY: the hook runs in the forked child before exec and
            // performs syscalls only (plus small transient buffers); it
            // never spawns threads. Any error aborts the spawn fail-closed.
            unsafe {
                cmd.pre_exec(move || super::linux_enforce::apply_child_plan(&plan));
            }
        }
    }
    let spawn_res = {
        let _serial = engine::spawn_serial().lock().unwrap();
        cmd.spawn()
    };
    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            backend.note_failed(super::sandbox_backend::PreparationFailureKind::SpawnRefused);
            let mut outcome = fail_closed(format!("spawn failed (no retry): {e}"), home);
            outcome.backend_report = backend.enforcement().cloned();
            outcome.backend_kind = backend_kind;
            backend.teardown();
            return outcome;
        }
    };
    let pid = child.id();
    spawn_log.push(SpawnEvent {
        run_id: nonce.clone(),
        pid,
    });
    RUNNER_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);
    // Spawn succeeded, so the child-side plan ran without error: promote
    // `Configured` to `Enforced`. Then verify host-observable state from
    // /proc while the child lives (unobserved stays `Enforced`).
    backend.note_spawned(pid);
    let verification = super::linux_enforce::verify_child_host(pid);
    backend.note_host_verified(&verification);

    // FM-03 continuity: the spec re-frozen from the same policy reference
    // after fork-return must hash identically; drift fails closed. Both
    // freezes cover the pre-channel launch context (`spec_env`); the
    // per-execution control capabilities are transport outside the frozen
    // env and are bound via the identity token instead.
    let spec_after = frozen::freeze_spec(
        &req.scenario.id,
        &registry_hash,
        req.policy,
        &tier_label,
        req.net_mode,
        &backend_label,
        &argv,
        &spec_env,
        &cwd,
        &nonce,
    );
    let spec_ok = engine::verify_spec_continuity(&spec, &spec_after);

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    // The confined child joins a new process group in `pre_exec`, so its
    // pgid equals its pid; otherwise no group kill applies. Off unix no
    // plan ever exists, so this is always `None` there.
    let confined_pgroup = backend.pre_exec_plan().is_some();
    let direct = DirectChild {
        child,
        stdout,
        stderr,
        pgid: if confined_pgroup {
            Some(pid as i32)
        } else {
            None
        },
    };

    let outcome = finish_run(
        req,
        target,
        nonce,
        identity,
        control_channel,
        home,
        fixture,
        sentinel_pre,
        spec_ok,
        direct,
        pid,
        backend,
    );
    // Teardown releases backend-held state (idempotent). The cloned report
    // stays on the outcome for audit; teardown never upgrades the verdict.
    backend.teardown();
    outcome
}

/// Stages after spawn: killer -> collector -> tree sweep -> post-mortem ->
/// oracle + backend ceiling. The oracle stays pure; the backend report
/// (pure data, final state after the sweep) demotes any PASS whose
/// mandatory capabilities are not actually enforced.
#[allow(clippy::too_many_arguments)]
fn finish_run(
    req: &ExecutionRequest<'_>,
    target: super::registry::Target,
    nonce: String,
    identity: ExecutionIdentity,
    control_channel: Option<ControlChannel>,
    home: PathBuf,
    fixture: Fixture,
    sentinel_pre: Vec<(PathBuf, String)>,
    spec_ok: bool,
    mut direct: DirectChild,
    pid: u32,
    backend: &mut dyn SandboxBackend,
) -> ExecutionOutcome {
    // Killer stage: deadline poll, terminate once on expiry (no blocking wait).
    let deadline = Instant::now() + req.deadline;
    let (kill, code) = killer::kill_on_deadline_with(&mut direct, deadline, EXIT_POLL);
    let timed_out = kill == KillOutcome::KilledOnDeadline;
    // Confined runs joined a private process group: re-signal it after the
    // root is reaped so lingering children release the pipes and die here
    // instead of outliving the run. Single-process runs skip this.
    if direct.pgid.is_some() {
        direct.terminate();
    }

    // Collector stage: drain stdio with a post-termination budget.
    let stdout = direct.stdout.take();
    let stderr = direct.stderr.take();
    let drain_deadline = Instant::now() + DRAIN_BUDGET;
    let collected = match (stdout, stderr) {
        (Some(o), Some(e)) => collect_child_stdio(o, e, drain_deadline, MAX_STDIO_BYTES),
        _ => super::collector::CollectedStdio {
            stdout: Vec::new(),
            stderr: Vec::new(),
            eof: false,
            truncated: false,
        },
    };

    // Re-observe the exit status after the drain (never blocking).
    let exit_code = direct.try_wait().or(Some(code));

    // Tree sweep (confined runs only): kill nonce-matching orphans the
    // group signal could not reach (setsid escapers) and record whether
    // the tree is observably clean. Unconfined runs keep the historical
    // behavior exactly (no sweep). `None` off Linux: no claim either way.
    // The diagnostic joins the detail string so a dirty tree is debuggable
    // from the report alone.
    if direct.pgid.is_some() {
        if let Some(outcome) = super::linux_enforce::sweep_tree_by_nonce(nonce.as_str(), pid) {
            backend.note_tree_clean(outcome.clean);
            backend.note_diagnostic(format!(
                "tree-sweep clean={} killed={} residual={:?} subreaper={}",
                outcome.clean, outcome.killed, outcome.residual, outcome.subreaper
            ));
        }
    }

    // Post-mortem, all host-side: payload integrity and sentinels.
    // Provenance audit per HOST_FACT below:
    // - payload hash: pre-image held by the host (stage), post-image read
    //   by the host. Genuinely host-observed either way the bit falls.
    // - sentinel hashes: same; the child is EXPECTED to be able to reach
    //   the tripwire (that is what makes it a tripwire); the mismatch
    //   against the host-held pre-image is host-observed violation proof.
    // - wait-status/kill: kernel wait / own poll loop. Host-observed.
    // - stdio bytes: attacker-controlled transport AND content ->
    //   SELF_REPORT only, forever.
    // Deliberately absent: any control file. A child-writable pathname can
    // never be authoritative, so none is read for the verdict.
    let payload_intact = fixture.verify_untouched().is_ok() && spec_ok;
    let mut sentinel_mutated = Vec::new();
    for (abs, before) in &sentinel_pre {
        let after = std::fs::read(abs)
            .map(|b| hash_bytes(&b))
            .unwrap_or_else(|_| "unreadable".to_string());
        if &after != before {
            let rel = abs
                .strip_prefix(fixture.root())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| abs.display().to_string());
            sentinel_mutated.push(rel);
        }
    }
    let violation_observed = !sentinel_mutated.is_empty();
    let home_marker = std::fs::read(home.join(HOME_MARKER_REL)).ok();

    // Evidence: stdio is SELF_REPORT only. HOST_FACT comes solely from
    // host-observed state (wait status, kill outcome, sentinel hashes).
    // No branch below inspects child text for judging.
    let mut evidence = Evidence::default();
    if let Some(c) = exit_code {
        evidence.host_fact("wait-status", format!("exit={c}"));
    }
    if timed_out {
        evidence.host_fact("kill", "killed-on-deadline".to_string());
    }
    evidence.self_report(
        "stdout",
        String::from_utf8_lossy(&collected.stdout).into_owned(),
    );
    evidence.self_report(
        "stderr",
        String::from_utf8_lossy(&collected.stderr).into_owned(),
    );
    for rel in &sentinel_mutated {
        evidence.host_fact("sentinel", format!("mutated:{rel}"));
    }

    // Stage 2 challenge-response verification. All channel I/O stays here
    // on the host side; the oracle only ever sees the stamped fact plus the
    // identity, never the channel. Provenance: `verify` reads the host-held
    // uplink end and mints the capability only on exact arrival of the
    // rotated challenge response — never issued via env, so echoing
    // verifier material cannot verify. Child bytes anywhere else
    // (HOME/fixture files, stdio, env echo, exit code, challenge echo)
    // are not consulted and cannot stamp a fact.
    // PASS-capability gate: the protocol proves live challenge-response
    // execution, never containment, so bound nonces + the quorum vector are
    // assembled from a verified response for `Aux` scenarios only. Without
    // a verified Aux response both nonce slots stay None and
    // agreeing_vectors stays 0, and the oracle structurally yields
    // INCONCLUSIVE (or FAIL on host-observed violation) — PASS is
    // unreachable there by construction, not by luck.
    // Blocker 2: completeness is structured oracle input, not a detail
    // string.
    let pass_capable = req.enable_host_control && req.scenario.category == Category::Aux;
    let mut control_observed = false;
    let mut control_state = if req.enable_host_control {
        "challenge:unverified"
    } else {
        "disabled"
    };
    if let Some(channel) = control_channel {
        if let Some(verified) = channel.verify(&identity, Instant::now() + CONTROL_READ_BUDGET) {
            evidence.host_control_fact(&verified);
            control_observed = true;
            control_state = if pass_capable {
                "challenge:verified"
            } else {
                // Liveness observed, but direct-exec proves no containment:
                // blocker verdicts stay INCONCLUSIVE/FAIL below regardless.
                "challenge:verified(non-aux,no-pass)"
            };
        }
    }
    let stdio_complete = collected.eof && !collected.truncated;
    let bound_nonce: Option<String> = if control_observed && pass_capable {
        Some(nonce.clone())
    } else {
        None
    };
    let agreeing_vectors: usize = if bound_nonce.is_some() { 1 } else { 0 };
    let input = oracle::OracleInput {
        scenario: req.scenario,
        evidence: &evidence,
        nonce: Some(nonce.as_str()),
        probe_nonce: bound_nonce.as_deref(),
        control_nonce: bound_nonce.as_deref(),
        payload_intact,
        env_poisoned: false,
        agreeing_vectors,
        violation_observed,
        control_observed,
        stdio_complete,
        execution_identity: Some(&identity),
    };
    let strength = req.scenario.strength_for(target);
    let judged = oracle::judge_with_ceiling(&input, strength, None);
    // Fail-closed ceiling over the FINAL report (post-sweep): PASS without
    // actually enforced mandatory backend capabilities demotes to
    // INCONCLUSIVE. Never upgrades; FAIL/INCONCLUSIVE/NOT_APPLICABLE pass
    // through unchanged.
    let backend_kind = backend.kind();
    let backend_report = backend.enforcement().cloned().unwrap_or_else(|| {
        super::sandbox_backend::EnforcementReport {
            backend: backend_kind,
            scenario_id: identity.scenario_id.clone(),
            session_nonce: nonce.clone(),
            registry_hash: identity.registry_hash.clone(),
            frozen_hash: identity.frozen_hash.clone(),
            policy_hash: String::new(),
            preparation_ok: false,
            records: Vec::new(),
        }
    });
    let verdict =
        super::sandbox_backend::apply_backend_ceiling(judged, &backend_report, req.scenario);
    let mut backend_summary = backend_report.render_deterministic();
    if let Some(diag) = backend.diagnostic() {
        backend_summary.push('|');
        backend_summary.push_str(&diag);
    }

    let detail = redact::redact_text(&redact::mask_home(
        &format!(
            "backend={} run exit={} timeout={} stdout={}B stderr={}B eof={} trunc={} complete={} control={} sentinel_mut={} payload_intact={} spec_ok={} backend=[{}] — {}",
            backend_kind.label(),
            exit_code.map_or("-".to_string(), |c| c.to_string()),
            timed_out,
            collected.stdout.len(),
            collected.stderr.len(),
            collected.eof,
            collected.truncated,
            stdio_complete,
            control_state,
            sentinel_mutated.len(),
            payload_intact,
            spec_ok,
            backend_summary,
            req.scenario.known_limitation,
        ),
        &home.display().to_string(),
    ));

    ExecutionOutcome {
        result: ScenarioResult {
            id: req.scenario.id.clone(),
            category: req.scenario.category,
            strength,
            verdict,
            detail,
        },
        nonce,
        execution_identity: identity,
        backend_report: Some(backend_report),
        backend_kind,
        exit_code,
        timed_out,
        kill: Some(kill),
        stdout: collected.stdout,
        stderr: collected.stderr,
        stdio_eof: collected.eof,
        stdio_truncated: collected.truncated,
        stdio_complete,
        evidence,
        payload_intact,
        sentinel_mutated,
        control_observed,
        violation_observed,
        home_marker,
        home,
        spawn_pid: Some(pid),
        duplicate_rejected: false,
    }
}

/// Suite-level execution owner (Blocker 5): the smallest practical ledger
/// proving `one scenario -> at most one execution` per suite invocation.
///
/// - Owns the spawn ledger: every accepted run appends its [`SpawnEvent`]
///   (run nonce + pid) here; nothing else in the suite path spawns.
/// - The FIRST call for a scenario id executes via [`run_one`]; any further
///   call for the same id is rejected BEFORE any fixture/spawn work with an
///   INCONCLUSIVE outcome marked [`ExecutionOutcome::duplicate_rejected`].
///   Rejection is recorded in `results()` (fail-closed for blockers).
/// - There is no retry API: a rejected duplicate can never upgrade an
///   earlier FAIL/INCONCLUSIVE into a PASS, because it never executes.
pub struct SuiteRunner {
    executed: std::collections::HashSet<String>,
    ledger: SpawnLog,
    results: Vec<ScenarioResult>,
}

impl SuiteRunner {
    pub fn new() -> Self {
        SuiteRunner {
            executed: std::collections::HashSet::new(),
            ledger: Vec::new(),
            results: Vec::new(),
        }
    }

    /// Execute one scenario unless it already ran in this suite.
    pub fn run(&mut self, req: &ExecutionRequest<'_>) -> ExecutionOutcome {
        let mut backend = super::sandbox_backend::DirectBackend::new();
        self.run_with_backend(req, &mut backend)
    }

    /// Suite execution through an explicit backend. The first call for a
    /// scenario id executes via [`run_one_with_backend`]; duplicates are
    /// rejected pre-spawn exactly like [`SuiteRunner::run`].
    pub fn run_with_backend(
        &mut self,
        req: &ExecutionRequest<'_>,
        backend: &mut dyn SandboxBackend,
    ) -> ExecutionOutcome {
        if !self.executed.insert(req.scenario.id.clone()) {
            let target = engine::current_target(None);
            let strength = req.scenario.strength_for(target);
            let detail = redact::redact_text(&format!(
                "duplicate execution rejected, no spawn; earlier verdict stands — {}",
                req.scenario.known_limitation,
            ));
            let outcome = ExecutionOutcome {
                result: ScenarioResult {
                    id: req.scenario.id.clone(),
                    category: req.scenario.category,
                    strength,
                    verdict: super::model::Verdict::Inconclusive,
                    detail,
                },
                nonce: String::new(),
                // Rejected pre-spawn: malformed identity, never PASS-capable.
                execution_identity: ExecutionIdentity::new(&req.scenario.id, "", "", ""),
                backend_report: None,
                backend_kind: backend.kind(),
                exit_code: None,
                timed_out: false,
                kill: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
                stdio_eof: false,
                stdio_truncated: false,
                stdio_complete: false,
                evidence: Evidence::default(),
                payload_intact: true,
                sentinel_mutated: Vec::new(),
                control_observed: false,
                violation_observed: false,
                home_marker: None,
                home: PathBuf::new(),
                spawn_pid: None,
                duplicate_rejected: true,
            };
            self.results.push(outcome.result.clone());
            return outcome;
        }
        let outcome = run_one_with_backend(req, &mut self.ledger, backend);
        self.results.push(outcome.result.clone());
        outcome
    }

    /// Suite-owned spawn ledger: one entry per accepted execution.
    pub fn ledger(&self) -> &[SpawnEvent] {
        &self.ledger
    }

    /// Per-scenario results in execution order, rejections included.
    pub fn results(&self) -> &[ScenarioResult] {
        &self.results
    }
}

impl Default for SuiteRunner {
    fn default() -> Self {
        SuiteRunner::new()
    }
}
