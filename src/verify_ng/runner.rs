//! Engine -> Killer -> Collector -> Oracle execution pipeline.
//!
//! Minimal real runner: one [`run_one`] call executes exactly one scenario
//! as exactly one spawned child and hands host-observed facts to the
//! existing oracle. Pipeline order per scenario:
//!
//! ```text
//! poison check (no spawn when poisoned)
//! -> fixture + isolated HOME + FrozenSpec (full-registry hash)
//! -> spawn exactly once (single call site below)
//! -> killer: deadline poll via `kill_on_deadline_with` (never blocking wait)
//! -> collector: drain stdio with deadline, re-observe exit status
//! -> post-mortem: payload integrity, sentinel sweep (host reads)
//! -> oracle (pure) -> redacted ScenarioResult
//! ```
//!
//! Provenance rules (Blocker 1 audit):
//! - HOST_FACT is only what the host observes independently of
//!   attacker-controlled reporting: wait status (kernel), kill outcome
//!   (own poll loop), payload/sentinel hashes (host-held pre-images).
//! - NOT HOST_FACT: stdout, stderr, child env, files created by the child,
//!   child-written markers, hashes over attacker-only post-run data.
//! - The direct backend has NO host-owned control channel: the child could
//!   write any nonce anywhere it can reach, so no child-presented value can
//!   bind the positive control. `probe_nonce`/`control_nonce` are therefore
//!   always `None` here and PASS is structurally unreachable on direct-exec:
//!   the best honest outcome is INCONCLUSIVE, or FAIL on host-observed
//!   violation. A future sandboxed backend with a supervisor-observed
//!   channel supplies real nonces; the oracle already knows how to judge
//!   them (untouched).
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
//! - Direct-exec backend: the child runs without sandbox enforcement (that
//!   binding lands with the backend-wired suite). There is no tree kill and
//!   no sweep here: orphaned grandchildren are a documented residual in the
//!   same class as the FS-ONLY BestEffort residual. The drain deadline still
//!   bounds collection, so a grandchild holding the pipe cannot hang us.
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
use super::evidence::Evidence;
use super::fixture::{hash_bytes, Fixture};
use super::frozen;
use super::killer::{self, KillOutcome, WaitKill};
use super::model::ScenarioResult;
use super::oracle;
use super::redact;

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
/// host-side trusts a child-presented nonce on this backend. There is
/// deliberately NO control-path variable: no child-reachable pathname is
/// authoritative for the verdict.
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
}

/// Host-observed outcome of one scenario run.
#[derive(Debug)]
pub struct ExecutionOutcome {
    pub result: ScenarioResult,
    pub nonce: String,
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
    /// Always false on direct-exec: no host-owned control source exists,
    /// so there is no positive control to observe. Retained as an explicit
    /// field so the absence is machine-visible, not implicit.
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

/// Direct-exec child handle: owns `std::process::Child`, single process
/// only (no tree kill — documented residual). Pipes are taken at spawn so
/// the collector stage owns them outright.
struct DirectChild {
    child: std::process::Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
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

/// Run one scenario as exactly one child process. See module docs for the
/// stage order and hard rules. Never panics on harness failures: setup or
/// spawn errors degrade to INCONCLUSIVE with no spawn logged.
pub fn run_one(req: &ExecutionRequest<'_>, spawn_log: &mut SpawnLog) -> ExecutionOutcome {
    let target = engine::current_target(None);
    // FM-08: poisoned diagnostic env invalidates before any spawn.
    let poison = engine::detect_env_poison(false);
    if !poison.is_empty() {
        let result = engine::poisoned_result(req.scenario, target, &poison);
        return ExecutionOutcome {
            result,
            nonce: String::new(),
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
    let fail_closed = |detail: String, home: PathBuf| ExecutionOutcome {
        result: ScenarioResult {
            id: req.scenario.id.clone(),
            category: req.scenario.category,
            strength: req.scenario.strength_for(target),
            verdict: super::model::Verdict::Inconclusive,
            detail: redact::redact_text(&redact::mask_home(&detail, &home.display().to_string())),
        },
        nonce: nonce.clone(),
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
    // Full-registry binding (Blocker 3): the hash covers the complete
    // compiled registry semantics, never just this scenario's id.
    let registry_hash = super::registry::registry_hash_full(&super::registry::registry());
    let spec = frozen::freeze_spec(
        &req.scenario.id,
        &registry_hash,
        req.policy,
        DIRECT_TIER,
        req.net_mode,
        DIRECT_BACKEND,
        &argv,
        &env,
        &cwd,
        &nonce,
    );

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
    let spawn_res = {
        let _serial = engine::spawn_serial().lock().unwrap();
        cmd.spawn()
    };
    let mut child = match spawn_res {
        Ok(c) => c,
        Err(e) => {
            return fail_closed(format!("spawn failed (no retry): {e}"), home);
        }
    };
    let pid = child.id();
    spawn_log.push(SpawnEvent {
        run_id: nonce.clone(),
        pid,
    });
    RUNNER_SPAWN_COUNT.fetch_add(1, Ordering::SeqCst);

    // FM-03 continuity: the spec re-frozen from the same policy reference
    // after fork-return must hash identically; drift fails closed.
    let spec_after = frozen::freeze_spec(
        &req.scenario.id,
        &registry_hash,
        req.policy,
        DIRECT_TIER,
        req.net_mode,
        DIRECT_BACKEND,
        &argv,
        &env,
        &cwd,
        &nonce,
    );
    let spec_ok = engine::verify_spec_continuity(&spec, &spec_after);

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let direct = DirectChild {
        child,
        stdout,
        stderr,
    };

    finish_run(
        req,
        target,
        nonce,
        home,
        fixture,
        sentinel_pre,
        spec_ok,
        direct,
        pid,
    )
}

/// Stages after spawn: killer -> collector -> post-mortem -> oracle.
#[allow(clippy::too_many_arguments)]
fn finish_run(
    req: &ExecutionRequest<'_>,
    target: super::registry::Target,
    nonce: String,
    home: PathBuf,
    fixture: Fixture,
    sentinel_pre: Vec<(PathBuf, String)>,
    spec_ok: bool,
    mut direct: DirectChild,
    pid: u32,
) -> ExecutionOutcome {
    // Killer stage: deadline poll, terminate once on expiry (no blocking wait).
    let deadline = Instant::now() + req.deadline;
    let (kill, code) = killer::kill_on_deadline_with(&mut direct, deadline, EXIT_POLL);
    let timed_out = kill == KillOutcome::KilledOnDeadline;

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

    // Blocker 1: no host-owned control source exists on direct-exec, so
    // both nonce slots stay None and agreeing_vectors stays 0. The oracle's
    // nonce-binding rule then structurally yields INCONCLUSIVE (or FAIL on
    // violation) — PASS is unreachable here, by construction, not by luck.
    // Blocker 2: completeness is structured oracle input, not a detail
    // string.
    let stdio_complete = collected.eof && !collected.truncated;
    let input = oracle::OracleInput {
        scenario: req.scenario,
        evidence: &evidence,
        nonce: Some(nonce.as_str()),
        probe_nonce: None,
        control_nonce: None,
        payload_intact,
        env_poisoned: false,
        agreeing_vectors: 0,
        violation_observed,
        control_observed: false,
        stdio_complete,
    };
    let strength = req.scenario.strength_for(target);
    let verdict = oracle::judge_with_ceiling(&input, strength, None);

    let detail = redact::redact_text(&redact::mask_home(
        &format!(
            "direct-exec run exit={} timeout={} stdout={}B stderr={}B eof={} trunc={} complete={} control=unavailable(direct-backend) sentinel_mut={} payload_intact={} spec_ok={} — {}",
            exit_code.map_or("-".to_string(), |c| c.to_string()),
            timed_out,
            collected.stdout.len(),
            collected.stderr.len(),
            collected.eof,
            collected.truncated,
            stdio_complete,
            sentinel_mutated.len(),
            payload_intact,
            spec_ok,
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
        control_observed: false,
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
        let outcome = run_one(req, &mut self.ledger);
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
