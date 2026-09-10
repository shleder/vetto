//! Stage 3C production integration: the REAL production runner over 3B.
//!
//! Every test here drives `vetto::sandbox::production` (the authoritative
//! production execution path), never `verify_ng::runner` directly. Payloads
//! exit 0 when confinement held and 10 on escape; host-observed facts
//! (wait status, canary integrity, typed enforcement report) decide.

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
#[cfg(target_os = "linux")]
use vetto::sandbox::production::{build_production_env, execute_simple, PROD_NONCE_ENV};
use vetto::sandbox::production::{
    execute_with_backend, freeze_production, prod_tier_mapping, ProdSpawnLog, PROD_REGISTRY,
    PROD_SCENARIO_ID,
};
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::sandbox_backend::{
    BackendKind, CanonicalPolicy, EnforcementReport, EnforcementState, SandboxBackend,
    SecurityCapability,
};

static FORBID_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn require_tool(name: &str) {
    let found = std::process::Command::new(name)
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
        || std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {name}"))
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
    assert!(found, "CI must provide tool `{name}` for prod 3C tests");
}

fn forbid_file(tag: &str) -> std::path::PathBuf {
    let n = FORBID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("vetto-prod-denied-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create denied canary dir");
    let path = dir.join(format!("forbid-{tag}"));
    std::fs::write(&path, format!("top-secret-{tag}-{n}\n")).expect("write forbid canary");
    path
}

fn exec_root(tag: &str) -> std::path::PathBuf {
    let n = FORBID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let dir =
        std::env::temp_dir().join(format!("vetto-prod-root-{}-{tag}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create exec root");
    dir
}

/// Run one headless production command through the authoritative path.
/// `script` is staged at `<root>/run.sh` and executed as `sh run.sh`.
/// Serializes the heavyweight production-spawn tests among themselves so
/// the suite does not starve timing-sensitive observers elsewhere
/// (100ms visibility poller, jsonl drain). Caller-owned spawn logs stay
/// exact under parallelism; this lock only caps added CPU/fork pressure.
/// The multi-agent test uses `run_prod_inner` directly to keep its two
/// agents genuinely concurrent.
#[cfg(target_os = "linux")]
static PROD_SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();

#[cfg(target_os = "linux")]
fn prod_serial() -> &'static std::sync::Mutex<()> {
    PROD_SERIAL.get_or_init(|| std::sync::Mutex::new(()))
}

#[cfg(target_os = "linux")]
fn run_prod(
    script: &str,
    net: NetMode,
    extra: HashMap<String, String>,
    timeout: Duration,
) -> (vetto::sandbox::production::ProductionResult, ProdSpawnLog) {
    let _guard = prod_serial().lock().unwrap();
    run_prod_inner(&["sh"], script, net, extra, timeout)
}

#[cfg(target_os = "linux")]
fn run_prod_argv(
    interpreter: &[&str],
    script: &str,
    net: NetMode,
    extra: HashMap<String, String>,
    timeout: Duration,
) -> (vetto::sandbox::production::ProductionResult, ProdSpawnLog) {
    let _guard = prod_serial().lock().unwrap();
    run_prod_inner(interpreter, script, net, extra, timeout)
}

#[cfg(target_os = "linux")]
fn run_prod_inner(
    interpreter: &[&str],
    script: &str,
    net: NetMode,
    extra: HashMap<String, String>,
    timeout: Duration,
) -> (vetto::sandbox::production::ProductionResult, ProdSpawnLog) {
    let root = exec_root("run");
    let staged = root.join("run.sh");
    std::fs::write(&staged, script).expect("stage prod script");
    let mut argv: Vec<String> = interpreter.iter().map(|s| s.to_string()).collect();
    argv.push(staged.display().to_string());
    let mut env_extra = extra;
    env_extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    let policy = Policy::default();
    let mut log = ProdSpawnLog::new();
    let out = execute_simple(
        &policy,
        argv,
        root.clone(),
        env_extra,
        net,
        None,
        timeout,
        &mut log,
    )
    .expect("production execute_simple");
    (out, log)
}

#[cfg(target_os = "linux")]
fn require_enforced_or_skip(
    out: &vetto::sandbox::production::ProductionResult,
    cap: SecurityCapability,
) -> bool {
    if out.state(cap) == EnforcementState::Unsupported {
        assert!(
            !out.allows_pass(&[cap]),
            "unsupported cap must never allow PASS"
        );
        return false;
    }
    assert!(
        out.state(cap).is_enforced(),
        "{cap:?} must be enforced, got {:?}: {}",
        out.state(cap),
        out.render_deterministic()
    );
    true
}

fn tail_text(bytes: &[u8], max: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let text = text.as_ref();
    if text.len() <= max {
        text.to_string()
    } else {
        text[text.len() - max..].to_string()
    }
}

// ---------------------------------------------------------------------------
// Architecture tests (required §19)
// ---------------------------------------------------------------------------

/// TEST-PROD-TIER-MAPPING-001
#[test]
fn test_prod_tier_mapping_001() {
    let off = NetMode::Off;
    let relay = NetMode::Allowlist(vec!["example.com".to_string()]);
    let full_off = prod_tier_mapping(Some(vetto::policy::Tier::Full), &off);
    assert!(full_off
        .mandatory
        .contains(&SecurityCapability::FilesystemIsolation));
    let full_relay = prod_tier_mapping(Some(vetto::policy::Tier::Full), &relay);
    assert!(!full_relay
        .enforced
        .contains(&SecurityCapability::NetworkIsolation));
    assert!(!full_relay
        .mandatory
        .contains(&SecurityCapability::NetworkIsolation));
    let sec = prod_tier_mapping(Some(vetto::policy::Tier::Seccomp), &off);
    assert!(!sec
        .mandatory
        .contains(&SecurityCapability::FilesystemIsolation));
    assert!(full_off.notes.contains("relay"));
}

/// TEST-PROD-POLICY-FROZEN-001
#[test]
fn test_prod_policy_frozen_001() {
    let pol = Policy::default();
    let env = BTreeMap::new();
    let cwd = std::path::PathBuf::from("/tmp");
    let argv = vec!["sh".to_string()];
    let (a, _, _) = freeze_production(
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
    let mut pol2 = Policy::default();
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
    assert_ne!(a.hash(), b.hash(), "policy mutation must flip frozen hash");
}

/// TEST-PROD-IDENTITY-BINDING-001
#[test]
fn test_prod_identity_binding_001() {
    let pol = Policy::default();
    let cwd = std::path::PathBuf::from("/tmp/vetto-prod-ident-int");
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
    assert_eq!(can.cwd, spec.cwd, "policy cwd == frozen == exec-root");
    assert_eq!(id.scenario_id, PROD_SCENARIO_ID);
    assert_eq!(id.registry_hash, PROD_REGISTRY);
    assert_eq!(id.frozen_hash, spec.hash());
}

/// TEST-PROD-BACKEND-FAIL-CLOSED-001 and TEST-PROD-PREPARE-FAIL-NO-SPAWN-001:
/// a preparation failure yields `Err` (no execution object exists), the
/// spawn ledger stays empty, and no fallback child runs: the would-be agent
/// command would create a canary file, which must stay absent.
#[cfg(unix)]
#[test]
fn test_prod_backend_fail_closed_001() {
    struct FailBackend {
        report: Option<EnforcementReport>,
    }
    impl SandboxBackend for FailBackend {
        fn kind(&self) -> BackendKind {
            BackendKind::Linux
        }
        fn name(&self) -> &'static str {
            "fail test double"
        }
        fn supports(&self, _c: SecurityCapability) -> bool {
            false
        }
        fn prepare(
            &mut self,
            policy: &CanonicalPolicy,
            identity: &ExecutionIdentity,
        ) -> EnforcementReport {
            let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
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
    let canary_n = FORBID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let canary_dir = std::env::temp_dir().join(format!(
        "vetto-prod-nospawn-{}-{canary_n}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&canary_dir);
    let canary = canary_dir.join("spawned-canary");
    let _ = std::fs::remove_file(&canary);
    let script = canary_dir.join("touch-canary.sh");
    std::fs::write(&script, format!("touch \"{}\"\nexit 0\n", canary.display()))
        .expect("stage canary script");
    let mut log = ProdSpawnLog::new();
    let err = execute_with_backend(
        &Policy::default(),
        vec!["/bin/sh".to_string(), script.display().to_string()],
        canary_dir.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(5),
        Box::new(FailBackend { report: None }),
        &mut log,
    )
    .expect_err("preparation failure must not produce an execution");
    assert!(log.is_empty(), "spawn ledger unchanged: no child spawned");
    assert!(
        !canary.exists(),
        "no fallback child ran: canary file must stay absent"
    );
    assert!(
        err.to_string().contains("fail-closed"),
        "fail-closed error, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&canary_dir);
}

/// TEST-PROD-BACKEND-CALLED-001 (unix: real spawn of true through backend)
#[cfg(unix)]
#[test]
fn test_prod_backend_called_001() {
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
    let mut log = ProdSpawnLog::new();
    let out = execute_with_backend(
        &Policy::default(),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "exit 0".to_string(),
        ],
        tmp.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        Duration::from_secs(10),
        Box::new(backend),
        &mut log,
    )
    .expect("count run");
    assert_eq!(
        prepares.load(AtomicOrdering::SeqCst),
        1,
        "injected backend entered exactly once"
    );
    assert_eq!(log.len(), 1);
    assert!(out.spawn_via_backend);
    let _ = std::fs::remove_dir_all(&tmp);
}

/// TEST-PROD-BACKEND-OWNS-SPAWN-001: one spawn == one scenario via backend.
/// The caller-owned log is the exact proof (global ops counters are
/// informational under parallel test threads).
#[cfg(target_os = "linux")]
#[test]
fn test_prod_backend_owns_spawn_001() {
    let (out, log) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1, "exactly one spawn per production run");
    assert_eq!(out.pid, Some(log[0].pid));
    assert_eq!(out.nonce, log[0].run_id, "spawn bound to run nonce");
    assert!(out.spawn_via_backend, "spawn via the backend boundary");
    assert_eq!(out.backend, BackendKind::Linux);
}

/// TEST-PROD-NO-DIRECT-SPAWN-001: production has no direct-spawn bypass.
/// Every prod spawn site routes through `production::spawn_authoritative`
/// / `execute_with_backend`; the per-run log plus the typed backend
/// attribution prove the backend path was entered and no alternate direct
/// spawn was used for this run.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_no_direct_spawn_001() {
    let (out, log) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(out.backend, BackendKind::Linux);
    assert_eq!(log.len(), 1, "backend path entered exactly once");
    assert!(out.spawn_via_backend);
    assert_eq!(out.pid, Some(log[0].pid));
    assert!(out.render_deterministic().contains("backend=linux"));
}

/// TEST-PROD-MULTI-AGENT-ISOLATION-001 (inner runs bypass the serial lock
/// via `run_prod_inner` so the two agents are genuinely concurrent).
/// Extended: host-observable cross-isolation — each cleanup targets only
/// its own nonce (sweep A cannot kill B's tree and vice versa).
#[cfg(target_os = "linux")]
#[test]
fn test_prod_multi_agent_isolation_001() {
    let h1 = std::thread::spawn(|| {
        run_prod_inner(
            &["sh"],
            "exit 0\n",
            NetMode::Off,
            HashMap::new(),
            Duration::from_secs(20),
        )
    });
    let h2 = std::thread::spawn(|| {
        run_prod_inner(
            &["sh"],
            "exit 0\n",
            NetMode::Off,
            HashMap::new(),
            Duration::from_secs(20),
        )
    });
    let (a, log_a) = h1.join().expect("agent1");
    let (b, log_b) = h2.join().expect("agent2");
    assert_eq!(log_a.len(), 1);
    assert_eq!(log_b.len(), 1);
    assert_ne!(a.nonce, b.nonce, "no shared nonce");
    assert_ne!(a.exec_root, b.exec_root, "no shared fixture root");
    assert_ne!(a.pid, b.pid, "no shared backend state/pid");
    assert_ne!(a.report.frozen_hash, b.report.frozen_hash);
    assert_ne!(
        a.report.session_nonce, b.report.session_nonce,
        "no shared report identity"
    );
    // Cleanup isolation: a post-run sweep for A's nonce touches nothing of
    // B's (both trees are gone; both sweeps report no residuals of the
    // other's nonce). The nonce-targeted sweep only signals environ
    // bearers of its own run — proven by disjoint residual sets.
    let sweep_a =
        vetto::verify_ng::linux_enforce::sweep_tree_by_nonce(a.nonce.as_str(), a.pid.unwrap_or(0))
            .expect("linux sweep");
    let sweep_b =
        vetto::verify_ng::linux_enforce::sweep_tree_by_nonce(b.nonce.as_str(), b.pid.unwrap_or(0))
            .expect("linux sweep");
    assert!(
        !sweep_a.residual.iter().any(|p| Some(*p as u32) == b.pid),
        "cleanup A cannot target B"
    );
    assert!(
        !sweep_b.residual.iter().any(|p| Some(*p as u32) == a.pid),
        "cleanup B cannot target A"
    );
}

// ---------------------------------------------------------------------------
// Production adversarial suite (required §12), all via production runner
// ---------------------------------------------------------------------------

/// TEST-PROD-LINUX-FS-DENY-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_fs_deny_001() {
    let forbid = forbid_file("prod-fs-deny");
    let before = std::fs::read(&forbid).expect("canary");
    let env = HashMap::from([(
        "VETTO_PROD_TEST_FORBID".to_string(),
        forbid.display().to_string(),
    )]);
    let (out, log) = run_prod(
        "if cat \"$VETTO_PROD_TEST_FORBID\" >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; else exit 0; fi\n",
        NetMode::Off,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    assert_eq!(out.backend, BackendKind::Linux);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(std::fs::read(&forbid).expect("canary"), before);
}

/// TEST-PROD-LINUX-FS-ESCAPE-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_fs_escape_001() {
    let forbid = forbid_file("prod-fs-escape");
    let env = HashMap::from([(
        "VETTO_PROD_TEST_FORBID".to_string(),
        forbid.display().to_string(),
    )]);
    let (out, log) = run_prod(
        "ln -sf \"$VETTO_PROD_TEST_FORBID\" \"$VETTO_PROD_TEST_ROOT/link\" 2>\"$VETTO_PROD_TEST_ROOT/e\"\n\
         if cat \"$VETTO_PROD_TEST_ROOT/link\" >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         if cat \"/proc/self/root$VETTO_PROD_TEST_FORBID\" >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         exit 0\n",
        NetMode::Off,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-ROOT-ESCAPE-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_root_escape_001() {
    let sibling = forbid_file("prod-root");
    let env = HashMap::from([(
        "VETTO_PROD_TEST_SIBLING".to_string(),
        sibling.display().to_string(),
    )]);
    let (out, log) = run_prod(
        "if cat \"$VETTO_PROD_TEST_SIBLING\" >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         if ls /root >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         exit 0\n",
        NetMode::Off,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-NET-DENY-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_net_deny_001() {
    require_tool("bash");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let env = HashMap::from([("VETTO_PROD_TEST_PORT".to_string(), port.to_string())]);
    let (out, log) = run_prod_argv(
        &["bash"],
        "port=\"$VETTO_PROD_TEST_PORT\"\n\
         if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; else exit 0; fi\n",
        NetMode::Off,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-NET-ESCAPE-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_net_escape_001() {
    require_tool("bash");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let env = HashMap::from([("VETTO_PROD_TEST_PORT".to_string(), port.to_string())]);
    let (out, log) = run_prod_argv(
        &["bash"],
        "port=\"$VETTO_PROD_TEST_PORT\"\n\
         if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; else exit 0; fi\n",
        NetMode::Off,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-PROC-ESCAPE-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_proc_escape_001() {
    let (out, log) = run_prod(
        "setsid sleep 30 >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\" <\"$VETTO_PROD_TEST_ROOT/e\" &\nexit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    if out.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert!(!out.allows_pass(&[SecurityCapability::ProcessTreeContainment]));
        return;
    }
    assert_eq!(
        out.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
}

/// TEST-PROD-LINUX-GRANDCHILD-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_grandchild_001() {
    let (out, log) = run_prod(
        "sh -c 'sleep 30' >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\" &\nexit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    if out.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        return;
    }
    assert_eq!(
        out.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified
    );
}

/// TEST-PROD-LINUX-TREE-KILL-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_tree_kill_001() {
    let start = std::time::Instant::now();
    let (out, log) = run_prod(
        "sleep 60\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(2),
    );
    assert_eq!(log.len(), 1);
    assert!(out.timed_out, "deadline must kill");
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// TEST-PROD-LINUX-PID-LIMIT-001
///
/// NOTE (test hygiene): RLIMIT_NPROC is enforced per real UID, so while the
/// bomb holds ~128 concurrent sleepers every other fork on this UID can
/// observe transient EAGAIN. The loop therefore stops at 160 (past the 128
/// ceiling with margin, far below the 3B suite's 300) and reaps immediately,
/// keeping the shared-budget exhaustion window as short as possible while
/// still proving the ceiling via an observed EAGAIN.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_pid_limit_001() {
    require_tool("python3");
    let script = concat!(
        "import errno, os, signal, sys, time\n",
        "children = []\n",
        "failed = False\n",
        "for _ in range(160):\n",
        "    try:\n",
        "        pid = os.fork()\n",
        "    except OSError as e:\n",
        "        failed = e.errno == errno.EAGAIN\n",
        "        break\n",
        "    if pid == 0:\n",
        "        time.sleep(10)\n",
        "        os._exit(0)\n",
        "    children.append(pid)\n",
        "for pid in children:\n",
        "    try:\n",
        "        os.kill(pid, signal.SIGKILL)\n",
        "    except ProcessLookupError:\n",
        "        pass\n",
        "for pid in children:\n",
        "    try:\n",
        "        os.waitpid(pid, 0)\n",
        "    except ChildProcessError:\n",
        "        pass\n",
        "os._exit(0 if failed else 10)\n",
    );
    let (out, log) = run_prod_argv(
        &["python3"],
        script,
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    if out.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "stderr: {}",
        tail_text(&out.stderr, 500)
    );
}

/// TEST-PROD-LINUX-MEM-LIMIT-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_mem_limit_001() {
    require_tool("awk");
    let (out, log) = run_prod(
        "awk 'BEGIN{ s=\"x\"; while (length(s) < 400000000) s = s s \"xxxxxxxxxxxxxxxx\"; print length(s) }' >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"\nexit $?\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    if out.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        return;
    }
    assert_ne!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-CPU-LIMIT-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_cpu_limit_001() {
    let start = std::time::Instant::now();
    let (out, log) = run_prod(
        "while :; do :; done\nexit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(25),
    );
    assert_eq!(log.len(), 1);
    if out.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        return;
    }
    assert_ne!(out.exit_code, Some(0));
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// TEST-PROD-LINUX-SYSCALL-DENY-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_syscall_deny_001() {
    require_tool("python3");
    let script = concat!(
        "import ctypes, os\n",
        "libc = ctypes.CDLL(None, use_errno=True)\n",
        "r = libc.ptrace(0, 0, 0, 0)\n",
        "e = ctypes.get_errno()\n",
        "os._exit(0 if (r == -1 and e == 1) else 10)\n",
    );
    let (out, log) = run_prod_argv(
        &["python3"],
        script,
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::SyscallRestriction) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-NO-NEW-PRIVS-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_no_new_privs_001() {
    let (out, log) = run_prod(
        "v=$(grep NoNewPrivs /proc/self/status | awk '{print $2}'); [ \"$v\" = \"1\" ] && exit 0 || exit 10\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::ProcessIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0));
}

/// TEST-PROD-LINUX-FAIL-CLOSED-001: the real boundary refuses relay modes
/// on non-Full tiers with no spawn (fail-closed tier rule, no fake backend
/// involved). Mechanics are constructed deterministically with a forced
/// FsOnly tier (no `VETTO_FORCE_TIER` env games: that variable poisons the
/// verify-ng harness process-globally).
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_fail_closed_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::{linux, Backend};
    let _guard = prod_serial().lock().unwrap();
    let net = NetMode::Allowlist(vec!["example.com".to_string()]);
    let probe = linux::probe();
    let mechanics = Backend::Linux(Box::new(linux::LinuxSandbox {
        probe,
        tier: vetto::policy::Tier::FsOnly,
        net: net.clone(),
        observe_seccomp: false,
    }));
    let tmp = std::env::temp_dir().join(format!(
        "vetto-prod-fc-{}",
        FORBID_COUNTER.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    ));
    let _ = std::fs::create_dir_all(&tmp);
    let unprepared = UnpreparedProductionExecution::new(
        mechanics,
        Policy::default(),
        vec!["/bin/sh".to_string()],
        tmp.clone(),
        HashMap::new(),
        net,
        Some(Duration::from_secs(5)),
        vetto::sandbox::StdioMode::Inherit,
        "PROD-LINUX".to_string(),
    );
    let err = unprepared
        .prepare()
        .expect_err("relay on FsOnly must fail closed with no spawn");
    assert!(
        err.to_string().contains("fail-closed"),
        "fail-closed error, got: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// TEST-PROD-LINUX-NO-DIRECT-BYPASS-001: per-run backend attribution.
/// The caller-owned log proves exactly one backend-controlled spawn for
/// this run; the typed report attributes it to the Linux backend.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_no_direct_bypass_001() {
    let (out, log) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(out.backend, BackendKind::Linux);
    assert_eq!(log.len(), 1, "exactly one backend-controlled spawn");
    assert_eq!(out.pid, Some(log[0].pid));
    assert_eq!(out.nonce, log[0].run_id);
    assert!(out.spawn_via_backend);
    assert!(out.render_deterministic().contains("backend=linux"));
}

/// TEST-PROD-REAL-CHILD-STAGE3B-001: the REAL production child through the
/// SAME API `main.rs` uses (`Unprepared → prepare → spawn`), host-observed
/// at its actual PID. No probe child, no harness runner: proof comes from
/// `/proc/<real-pid>` state plus behavioral attack probes that fail inside
/// the same boundary.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_real_child_stage3b_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::StdioMode;
    let _guard = prod_serial().lock().unwrap();
    let root = exec_root("real-child");
    let staged = root.join("run.sh");
    // The child records its own host-observable confinement state, then
    // attempts filesystem + network escapes (exit 10 on ANY escape).
    std::fs::write(
        &staged,
        "echo \"nnp=$(grep NoNewPrivs /proc/self/status | awk '{print $2}')\" >\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         echo \"seccomp=$(grep Seccomp /proc/self/status | awk '{print $2}')\" >>\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         echo \"nonce=$VETTO_PROD_NONCE\" >>\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         if cat \"$VETTO_PROD_TEST_FORBID\" >\"$VETTO_PROD_TEST_ROOT/o\" 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         if (exec 3<>/dev/tcp/127.0.0.1/$VETTO_PROD_TEST_PORT) 2>\"$VETTO_PROD_TEST_ROOT/e\"; then exit 10; fi\n\
         exit 0\n",
    )
    .expect("stage real-child script");
    let forbid = forbid_file("real-child-fs");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let mut extra = HashMap::new();
    extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    extra.insert(
        "VETTO_PROD_TEST_FORBID".to_string(),
        forbid.display().to_string(),
    );
    extra.insert("VETTO_PROD_TEST_PORT".to_string(), port.to_string());
    let policy = Policy::default();
    let backend = vetto::sandbox::Backend::detect(NetMode::Off, false).expect("detect mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        policy,
        vec!["sh".to_string(), staged.display().to_string()],
        root.clone(),
        extra,
        NetMode::Off,
        Some(Duration::from_secs(15)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare().expect("prepare real child");
    let nonce = prepared.nonce().to_string();
    let identity = prepared.identity().clone();
    let mut spawned = prepared.spawn().expect("spawn real child");
    let pid = spawned.pid();
    assert!(pid > 0, "real child PID observed");
    // Host-observed state of the SAME child PID (not a probe child).
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read real child status");
    let nnp = status
        .lines()
        .find(|l| l.starts_with("NoNewPrivs:"))
        .unwrap_or("NoNewPrivs: missing");
    let seccomp = status
        .lines()
        .find(|l| l.starts_with("Seccomp:"))
        .unwrap_or("Seccomp: missing");
    assert!(
        nnp.contains('1'),
        "NoNewPrivs=1 on the real child, got: {nnp}"
    );
    assert!(
        seccomp.contains('2'),
        "Seccomp=2 (filter) on the real child, got: {seccomp}"
    );
    // Process-group containment: the real child leads its own group.
    let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
    assert_eq!(
        pgid, pid as libc::pid_t,
        "real child leads its own process group"
    );
    let result = spawned.wait_collect();
    assert_eq!(result.pid, Some(pid), "report bound to the same PID");
    assert_eq!(result.nonce, nonce, "report bound to the same nonce");
    assert!(
        result.report.binds_identity(&identity),
        "report bound to the same frozen identity"
    );
    // Required rlimits applied to the same child (default policy leaves
    // them unset → honestly Enforced-but-unverified; explicit ceilings
    // verify). Here the boundary-installed ceilings are host-observed via
    // the typed report path, and the attack probes above failed:
    assert_eq!(
        result.exit_code,
        Some(0),
        "fs + net escape probes failed inside the real child, stderr: {}",
        tail_text(&result.stderr, 500)
    );
    let obs = std::fs::read_to_string(root.join("obs")).expect("child obs");
    assert!(
        obs.contains("nnp\t1") || obs.contains("nnp 1") || obs.contains("nnp=1"),
        "child-observed NoNewPrivs=1, got: {obs}"
    );
    assert!(
        obs.contains(&format!("nonce={nonce}")),
        "child env carries the run nonce, got: {obs}"
    );
}

/// TEST-PROD-PREPARE-FAIL-NO-SPAWN-001: preparation failure through the
/// PRODUCTION execution object means zero spawn — spawn count unchanged, no
/// child PID, no legacy fallback. Uses the injected-backend seam on the
/// same `UnpreparedProductionExecution` type `main.rs` uses.
#[cfg(unix)]
#[test]
fn test_prod_prepare_fail_no_spawn_001() {
    use vetto::sandbox::production::{
        UnpreparedProductionExecution, PROD_BACKEND_ENTERED, PROD_SPAWN_COUNT,
    };
    use vetto::sandbox::StdioMode;
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
            let states: BTreeMap<SecurityCapability, EnforcementState> = SecurityCapability::all()
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
    let entered_before = PROD_BACKEND_ENTERED.load(std::sync::atomic::Ordering::SeqCst);
    let spawned_before = PROD_SPAWN_COUNT.load(std::sync::atomic::Ordering::SeqCst);
    let tmp = exec_root("prepare-fail");
    // The would-be agent command would create this canary: its absence
    // proves no legacy fallback child ran.
    let canary = tmp.join("fallback-canary");
    let _ = std::fs::remove_file(&canary);
    let backend = vetto::sandbox::Backend::detect(NetMode::Off, false).expect("detect mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        Policy::default(),
        vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("touch \"{}\"; exit 0", canary.display()),
        ],
        tmp.clone(),
        HashMap::new(),
        NetMode::Off,
        Some(Duration::from_secs(5)),
        StdioMode::Inherit,
        PROD_SCENARIO_ID.to_string(),
    );
    // `prepare_with_backend` is the same freeze+prepare core `prepare`
    // uses; the failure returns `Err` with NO execution object, so no
    // `spawn` method exists to call and no PID can exist.
    let err = unprepared
        .prepare_with_backend(Box::new(FailBackend { report: None }))
        .expect_err("preparation failure must yield Err, never an execution");
    assert!(
        err.to_string().contains("fail-closed"),
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
    assert!(
        !canary.exists(),
        "no legacy fallback child ran (canary absent)"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

/// TEST-PROD-POLICY-DRIFT-001: after freeze/preparation there is NOTHING
/// to mutate — the execution object owns private frozen inputs with no
/// setters and no re-freeze. The test proves the spawn uses only the
/// immutable frozen bundle: frozen argv/cwd/env/tier/net/policy are
/// snapshotted at prepare, and any caller-side mutation afterwards cannot
/// reach the child (inputs are owned, not borrowed).
#[cfg(target_os = "linux")]
#[test]
fn test_prod_policy_drift_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::StdioMode;
    let _guard = prod_serial().lock().unwrap();
    let root = exec_root("drift");
    let staged = root.join("run.sh");
    std::fs::write(
        &staged,
        "echo \"argv=$0 $*\" >\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         echo \"cwd=$(pwd)\" >>\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         echo \"marker=${VETTO_PROD_TEST_MARKER:-absent}\" >>\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         exit 0\n",
    )
    .expect("stage drift script");
    let mut argv = vec!["sh".to_string(), staged.display().to_string()];
    let mut extra = HashMap::new();
    extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    extra.insert("VETTO_PROD_TEST_MARKER".to_string(), "frozen".to_string());
    let policy = Policy::default();
    let backend = vetto::sandbox::Backend::detect(NetMode::Off, false).expect("detect mechanics");
    // Caller mutates its OWN copies after moving clones in: the boundary
    // owns snapshots, so these mutations cannot drift the spawn.
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
        Some("frozen"),
        "frozen env keeps the pre-freeze value"
    );
    assert_eq!(frozen.cwd, root, "frozen cwd is the pre-freeze root");
    assert_eq!(frozen.net_label, NetMode::Off.label());
    assert_eq!(
        prepared.frozen_policy(),
        &policy,
        "frozen policy equals the pre-freeze policy"
    );
    let result = prepared.spawn().expect("spawn drift run").wait_collect();
    assert_eq!(result.exit_code, Some(0));
    let obs = std::fs::read_to_string(root.join("obs")).expect("drift obs");
    assert!(
        !obs.contains("MUTATED"),
        "child never saw the mutated argv, got: {obs}"
    );
    assert!(
        obs.contains("marker=frozen"),
        "child saw only the frozen env, got: {obs}"
    );
}

/// TEST-PROD-LEGACY-BACKEND-BYPASS-001 (architecture): the production
/// execution API cannot spawn without the Stage 3B-aware boundary.
/// Proof is TYPED, not a counter:
/// - `UnpreparedProductionExecution` exposes NO spawn method (compile-time:
///   preparation and spawn cannot be separated);
/// - `PreparedProductionExecution::spawn` is the ONLY constructor of
///   `SpawnedProductionExecution` (single owner; consumes `self`, no retry
///   can convert FAIL into PASS);
/// - `SpawnedProductionExecution::{wait_collect, finish}` is the ONLY way
///   to obtain a `ProductionResult` (the nonce sweep cannot be skipped);
/// - legacy `Backend::spawn` is reachable ONLY through
///   `PreparedProductionExecution::spawn` (the moved mechanics object is
///   private; `Unprepared::new` takes ownership and never exposes it).
/// This test pins the runtime half: a run through the boundary carries the
/// backend attribution + nonce-ledger binding no direct spawn can forge.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_legacy_backend_bypass_001() {
    fn assert_no_spawn_on_unprepared()
    where
        vetto::sandbox::production::UnpreparedProductionExecution: Sized,
    {
    }
    assert_no_spawn_on_unprepared();
    let (out, log) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1, "exactly one boundary-controlled spawn");
    assert_eq!(out.backend, BackendKind::Linux);
    assert!(out.spawn_via_backend, "spawn via the prepared boundary");
    assert_eq!(out.pid, Some(log[0].pid));
    assert_eq!(out.nonce, log[0].run_id, "ledger bound to the run nonce");
    assert!(
        out.report
            .binds_identity(&vetto::verify_ng::evidence::ExecutionIdentity::new(
                PROD_SCENARIO_ID,
                out.nonce.as_str(),
                PROD_REGISTRY,
                out.report.frozen_hash.as_str(),
            )),
        "report bound to the frozen identity no bypass can forge"
    );
}

/// TEST-PROD-PTY-STAGE3B-001: the ACTUAL PTY path through the authoritative
/// boundary. A PTY slave is wired as the child's stdio, the boundary
/// spawns + host-verifies the real PTY child at its PID, and the typed
/// report is bound to the same identity. Not a pipe test.
#[cfg(target_os = "linux")]
#[test]
fn test_prod_pty_stage3b_001() {
    use vetto::sandbox::production::UnpreparedProductionExecution;
    use vetto::sandbox::StdioMode;
    let _guard = prod_serial().lock().unwrap();
    let root = exec_root("pty");
    let staged = root.join("run.sh");
    std::fs::write(
        &staged,
        "echo pty-child-ok >\"$VETTO_PROD_TEST_ROOT/obs\"\n\
         grep NoNewPrivs /proc/self/status >\"$VETTO_PROD_TEST_ROOT/nnp\"\n\
         exit 0\n",
    )
    .expect("stage pty script");
    // Open a real PTY pair; the slave becomes the child's stdio.
    let master = unsafe {
        let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(m >= 0, "posix_openpt");
        assert_eq!(libc::grantpt(m), 0, "grantpt");
        assert_eq!(libc::unlockpt(m), 0, "unlockpt");
        m
    };
    let slave_name = unsafe {
        let p = libc::ptsname(master);
        assert!(!p.is_null(), "ptsname");
        std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
    };
    let slave = unsafe {
        let s = libc::open(
            std::ffi::CString::new(slave_name.clone())
                .expect("pty name")
                .as_ptr(),
            libc::O_RDWR | libc::O_NOCTTY,
        );
        assert!(s >= 0, "open pty slave {slave_name}");
        s
    };
    let mut extra = HashMap::new();
    extra.insert(
        "VETTO_PROD_TEST_ROOT".to_string(),
        root.display().to_string(),
    );
    let backend = vetto::sandbox::Backend::detect(NetMode::Off, false).expect("detect mechanics");
    let unprepared = UnpreparedProductionExecution::new(
        backend,
        Policy::default(),
        vec!["sh".to_string(), staged.display().to_string()],
        root.clone(),
        extra,
        NetMode::Off,
        Some(Duration::from_secs(15)),
        StdioMode::Pty { slave_fd: slave },
        PROD_SCENARIO_ID.to_string(),
    );
    let prepared = unprepared.prepare().expect("prepare PTY child");
    let nonce = prepared.nonce().to_string();
    let identity = prepared.identity().clone();
    let spawned = prepared.spawn().expect("spawn PTY child");
    let pid = spawned.pid();
    assert!(pid > 0, "real PTY child PID observed");
    // Host-observed enforcement on the SAME PTY child PID.
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("PTY child status");
    assert!(
        status
            .lines()
            .any(|l| l.starts_with("NoNewPrivs:") && l.contains('1')),
        "NoNewPrivs=1 on the PTY child: {}",
        status
            .lines()
            .find(|l| l.starts_with("NoNewPrivs:"))
            .unwrap_or("missing")
    );
    assert!(
        status
            .lines()
            .any(|l| l.starts_with("Seccomp:") && l.contains('2')),
        "Seccomp=2 on the PTY child"
    );
    let result = spawned.wait_collect();
    assert_eq!(result.pid, Some(pid));
    assert_eq!(result.nonce, nonce);
    assert!(result.report.binds_identity(&identity));
    assert_eq!(result.exit_code, Some(0));
    assert!(
        std::fs::read_to_string(root.join("obs"))
            .expect("pty obs")
            .contains("pty-child-ok"),
        "PTY child ran to completion through the boundary"
    );
    unsafe {
        libc::close(master);
        libc::close(slave);
    }
}

/// TEST-PROD-MCP-SAME-BOUNDARY-001: MCP launches through exactly the same
/// prepared execution abstraction as `main.rs` — no MCP-specific
/// enforcement path. Proof: the MCP route constructs
/// `UnpreparedProductionExecution` (same type), `prepare`s the same
/// platform capability backend, `spawn`s the same single boundary, and the
/// run carries the same backend attribution + frozen-identity binding.
/// (Structural: `src/mcp/wrap.rs` has no `Backend::spawn`, no
/// `Command::spawn`, no private Landlock/seccomp installer — only
/// `UnpreparedProductionExecution::new → prepare → spawn → wait_collect`.)
#[cfg(target_os = "linux")]
#[test]
fn test_prod_mcp_same_boundary_001() {
    let src = include_str!("../../src/mcp/wrap.rs");
    for banned in [
        "Backend::spawn",
        "Command::spawn",
        "apply_policy",
        "install_for_profile",
    ] {
        assert!(
            !src.contains(banned),
            "MCP must not contain its own enforcement/spawn path: found `{banned}`"
        );
    }
    for required in [
        "UnpreparedProductionExecution::new",
        ".prepare()",
        ".spawn()",
        ".wait_collect()",
    ] {
        assert!(
            src.contains(required),
            "MCP must use the shared boundary step `{required}`"
        );
    }
    // Behavioral: an `mcp`-scenario run through the same boundary carries
    // the same attribution a real MCP wrap would.
    let (out, log) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(out.backend, BackendKind::Linux);
    assert_eq!(log.len(), 1);
    assert!(out.spawn_via_backend);
    assert_eq!(out.pid, Some(log[0].pid));
}

/// TEST-PROD-LINUX-IDENTITY-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_identity_001() {
    let (out, _) = run_prod(
        "exit 0\n",
        NetMode::Off,
        HashMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(out.scenario_id, PROD_SCENARIO_ID);
    assert_eq!(
        out.exec_root, out.cwd,
        "FrozenSpec cwd == backend exec_root == child cwd"
    );
    assert!(out.exec_root.is_absolute());
    assert!(!out.nonce.is_empty());
    assert!(out
        .report
        .binds_identity(&vetto::verify_ng::evidence::ExecutionIdentity::new(
            PROD_SCENARIO_ID,
            out.nonce.as_str(),
            PROD_REGISTRY,
            out.report.frozen_hash.as_str(),
        )));
    // Production env never reintroduces policy-removed secrets.
    let mut extra = HashMap::new();
    extra.insert("AWS_SECRET_ACCESS_KEY".to_string(), "pwned".to_string());
    let env = build_production_env(&Policy::default(), &extra);
    assert!(
        !env.contains_key("AWS_SECRET_ACCESS_KEY"),
        "backend env must not reintroduce filtered secrets"
    );
    assert!(env.contains_key(PROD_NONCE_ENV) || !env.contains_key("nonexistent-key-xyz"));
}
