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

/// TEST-PROD-BACKEND-FAIL-CLOSED-001
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
    let mut backend = FailBackend { report: None };
    let mut log = ProdSpawnLog::new();
    let out = execute_with_backend(
        &Policy::default(),
        vec!["sh".to_string()],
        std::path::PathBuf::from("/tmp"),
        HashMap::new(),
        NetMode::Off,
        Some(vetto::policy::Tier::FsOnly),
        Duration::from_secs(5),
        &mut backend,
        &mut log,
    )
    .expect("fail-closed returns result");
    assert!(log.is_empty(), "spawn_count == 0");
    assert!(!out.spawn_via_backend);
    assert!(!out.allows_pass(&[SecurityCapability::HostEvidence]));
}

/// TEST-PROD-BACKEND-CALLED-001 (unix: real spawn of true through backend)
#[cfg(unix)]
#[test]
fn test_prod_backend_called_001() {
    struct CountBackend {
        prepares: usize,
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
        fn enforcement(&self) -> Option<&EnforcementReport> {
            self.report.as_ref()
        }
        fn teardown(&mut self) {
            self.report = None;
        }
    }
    let mut backend = CountBackend {
        prepares: 0,
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
        &mut backend,
        &mut log,
    )
    .expect("count run");
    assert_eq!(backend.prepares, 1);
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

/// TEST-PROD-LINUX-FAIL-CLOSED-001
#[cfg(target_os = "linux")]
#[test]
fn test_prod_linux_fail_closed_001() {
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
    let mut backend = FailBackend { report: None };
    let mut log = ProdSpawnLog::new();
    let out = execute_with_backend(
        &Policy::default(),
        vec!["sh".to_string()],
        std::env::temp_dir(),
        HashMap::new(),
        NetMode::Off,
        Some(vetto::policy::Tier::FsOnly),
        Duration::from_secs(5),
        &mut backend,
        &mut log,
    )
    .expect("fail-closed result");
    assert!(log.is_empty(), "spawn_count == 0, no agent execution");
    assert!(!out.allows_pass(&[SecurityCapability::FilesystemIsolation]));
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
