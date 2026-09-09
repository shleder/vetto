//! Stage 3B real Linux enforcement: adversarial tests with host-observable
//! evidence.
//!
//! Every test drives [`runner::run_one_with_backend`] through a real
//! [`LinuxBackend`](vetto::verify_ng::sandbox_backend::LinuxBackend)
//! (landlock + seccomp + rlimit + process-group/tree sweep, no namespaces).
//! Payloads attack the boundary; verdicts come from host-observed facts
//! (wait status, file integrity, `/proc` verification reflected in the
//! backend report) — never from child self-reports.
//!
//! Convention: payloads exit `0` when confinement held and `10` when the
//! escape succeeded. Exit `10` therefore fails the test loudly (missing
//! enforcement), while exit `0` plus an `Enforced`/`Verified` report proves
//! the mechanism. On kernels without a mechanism the report stays
//! `Unsupported` and the test asserts fail-closed (`!= PASS`) instead.
//!
//! Linux-only: the whole module is compiled on Linux alone (see
//! `tests/integration/main.rs`).

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::verify_ng::evidence::ExecutionIdentity;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{
    allows_pass, apply_backend_ceiling, required_capabilities, BackendKind, CanonicalPolicy,
    EnforcementReport, EnforcementState, LinuxBackend, SandboxBackend, SecurityCapability,
};
use vetto::verify_ng::{engine, runner};

static FORBID_COUNTER: AtomicU64 = AtomicU64::new(0);

fn scenario(id: &str, category: Category) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::High,
        required_caps: Vec::new(),
        strength: BTreeMap::from([(target.label().to_string(), ClaimStrength::Strong)]),
        quorum: 1,
        known_limitation: "linux-enforcement adversarial self-test; proves no cross-platform claim"
            .to_string(),
        residual_risk: String::new(),
    }
}

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
    assert!(
        found,
        "CI must provide tool `{name}` for linux enforcement tests"
    );
}

/// Create a forbidden canary file OUTSIDE any fixture root (sibling temp
/// path, unique per test). The confined child must never read/write it.
fn forbid_file(tag: &str) -> std::path::PathBuf {
    let n = FORBID_COUNTER.fetch_add(1, Ordering::SeqCst);
    let path =
        std::env::temp_dir().join(format!("vetto-vng-forbid-{}-{n}-{tag}", std::process::id()));
    std::fs::write(&path, format!("top-secret-{tag}-{n}\n")).expect("write forbid canary");
    path
}

fn forbid_bytes(path: &std::path::Path) -> Vec<u8> {
    std::fs::read(path).expect("forbid canary must exist")
}

#[allow(clippy::too_many_arguments)]
fn run_linux(
    scen: &Scenario,
    interpreter: &[&str],
    script: &str,
    net_mode: &NetMode,
    env_extra: BTreeMap<String, String>,
    deadline: Duration,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    let policy = Policy::default();
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy: &policy,
        net_mode,
        interpreter: interpreter.iter().map(|s| s.to_string()).collect(),
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels: Vec::new(),
        env_extra,
        deadline,
        enable_host_control: false,
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    // Ownership: the request borrows policy/net/scenario owned by this
    // frame; run synchronously and drop everything together.
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    // `policy` is dropped here with the request; the outcome owns its copy.
    let _ = &policy;
    (out, log)
}

fn test_env_forbid(path: &std::path::Path) -> BTreeMap<String, String> {
    BTreeMap::from([(
        "VETTO_VNG_TEST_FORBID".to_string(),
        path.display().to_string(),
    )])
}

fn assert_no_pass(out: &runner::ExecutionOutcome) {
    assert_ne!(
        out.result.verdict,
        Verdict::Pass,
        "unenforced/missing enforcement must never PASS: {}",
        out.result.detail
    );
}

/// Fetch the backend report or fail the test (every runner path that spans
/// preparation carries one).
fn report_of(out: &runner::ExecutionOutcome) -> &EnforcementReport {
    out.backend_report
        .as_ref()
        .expect("linux run must carry a backend report")
}

/// If `cap` is `Unsupported` on this kernel, assert fail-closed and stop:
/// the honest outcome on weak kernels. Returns true when enforced.
///
/// Uses the raw `state` (not `is_enforced`, which additionally requires
/// `preparation_ok`): a dirty tree in an unrelated capability must not
/// demote this cap's installed state. Tree health is asserted separately
/// by the proc/tree tests.
fn require_enforced_or_skip(out: &runner::ExecutionOutcome, cap: SecurityCapability) -> bool {
    let report = report_of(out);
    if report.state(cap) == EnforcementState::Unsupported {
        assert_no_pass(out);
        return false;
    }
    assert!(
        report.state(cap).is_enforced(),
        "{cap:?} must be enforced, got {:?}: {}",
        report.state(cap),
        report.render_deterministic()
    );
    true
}

fn assert_host_fact_wait(out: &runner::ExecutionOutcome) {
    assert!(
        out.evidence.has_host_fact(),
        "run must carry host-observed facts"
    );
}

/// Last bytes of a stream for failure diagnostics (child text is evidence
/// for debugging only, never for the verdict). Declared before first use
/// so every filesystem assertion can attach child stderr on failure.
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
// Filesystem isolation (Landlock allowlist)
// ---------------------------------------------------------------------------

/// TEST-LINUX-FS-READ-DENY-001: reads outside the allowlist are denied.
#[test]
fn test_linux_fs_read_deny_001() {
    let scen = scenario("TEST-LINUX-FS-READ-DENY-001", Category::FsRead);
    let forbid = forbid_file("read-deny");
    let before = forbid_bytes(&forbid);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "if cat \"$VETTO_VNG_TEST_FORBID\" >/dev/null 2>&1; then exit 10; else exit 0; fi\n",
        &net,
        test_env_forbid(&forbid),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    assert_eq!(out.backend_kind, BackendKind::Linux);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "forbidden read must be denied; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(forbid_bytes(&forbid), before, "canary intact (host-read)");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert_host_fact_wait(&out);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-FS-WRITE-DENY-001: writes outside the allowlist are denied.
#[test]
fn test_linux_fs_write_deny_001() {
    let scen = scenario("TEST-LINUX-FS-WRITE-DENY-001", Category::FsWrite);
    let forbid = forbid_file("write-deny");
    let before = forbid_bytes(&forbid);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "if printf pwned > \"$VETTO_VNG_TEST_FORBID\" 2>/dev/null; then exit 10; fi\n\
         if mkdir \"$VETTO_VNG_TEST_FORBID.dir\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        &net,
        test_env_forbid(&forbid),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(out.exit_code, Some(0), "forbidden write must be denied");
    assert_eq!(forbid_bytes(&forbid), before, "canary intact (host-read)");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-FS-ESCAPE-001: symlink / /proc/self/root / dotdot escapes fail.
#[test]
fn test_linux_fs_escape_001() {
    let scen = scenario("TEST-LINUX-FS-ESCAPE-001", Category::FsRead);
    let forbid = forbid_file("escape");
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "ln -sf \"$VETTO_VNG_TEST_FORBID\" \"$VETTO_VNG_ROOT/link\" 2>/dev/null\n\
         if cat \"$VETTO_VNG_ROOT/link\" >/dev/null 2>&1; then exit 10; fi\n\
         if cat \"/proc/self/root$VETTO_VNG_TEST_FORBID\" >/dev/null 2>&1; then exit 10; fi\n\
         trav=\"$VETTO_VNG_ROOT/../$(basename \"$(dirname \"$VETTO_VNG_TEST_FORBID\")\")/$(basename \"$VETTO_VNG_TEST_FORBID\")\"\n\
         if cat \"$trav\" >/dev/null 2>&1; then exit 10; fi\n\
         exit 0\n",
        &net,
        test_env_forbid(&forbid),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "symlink/proc-root/dotdot escapes must be denied"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-FS-ROOT-ISOLATION-001: host roots outside the allowlist unreadable.
#[test]
fn test_linux_fs_root_isolation_001() {
    let scen = scenario("TEST-LINUX-FS-ROOT-ISOLATION-001", Category::FsRead);
    let sibling = forbid_file("sibling");
    let net = NetMode::Off;
    let mut env = BTreeMap::new();
    env.insert(
        "VETTO_VNG_TEST_SIBLING".to_string(),
        sibling.display().to_string(),
    );
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "for p in /root/.profile /home /opt /srv /mnt \"$VETTO_VNG_TEST_SIBLING\" / /tmp; do\n\
         if ls \"$p\" >/dev/null 2>&1; then exit 10; fi\n\
         done\n\
         exit 0\n",
        &net,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "host roots outside the allowlist must be unreadable"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&sibling);
}

// ---------------------------------------------------------------------------
// Network isolation (seccomp UnixOnly)
// ---------------------------------------------------------------------------

/// TEST-LINUX-NET-DENY-001: TCP connect to a live host listener is blocked.
#[test]
fn test_linux_net_deny_001() {
    require_tool("bash");
    let scen = scenario("TEST-LINUX-NET-DENY-001", Category::Net);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener must bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let net = NetMode::Off;
    let env = BTreeMap::from([("VETTO_VNG_TEST_PORT".to_string(), port.to_string())]);
    let (out, log) = run_linux(
        &scen,
        &["bash"],
        "port=\"$VETTO_VNG_TEST_PORT\"\n\
         if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then printf hi >&3; exec 3>&-; exit 10; else exit 0; fi\n",
        &net,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "TCP connect must be blocked by the socket filter"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-NET-ESCAPE-001: userns + connect still blocked (filter inherited).
#[test]
fn test_linux_net_escape_001() {
    require_tool("bash");
    let scen = scenario("TEST-LINUX-NET-ESCAPE-001", Category::Net);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener must bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let net = NetMode::Off;
    let env = BTreeMap::from([("VETTO_VNG_TEST_PORT".to_string(), port.to_string())]);
    let (out, log) = run_linux(
        &scen,
        &["bash"],
        "port=\"$VETTO_VNG_TEST_PORT\"\n\
         if unshare -Urn bash -c \"(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null\" 2>/dev/null; then exit 10; fi\n\
         if (exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null; then exit 10; else exit 0; fi\n",
        &net,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "namespace escape must not lift the socket filter"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-NET-ALLOW-001: local IPC (FIFO under the exec root) still works.
#[test]
fn test_linux_net_allow_001() {
    let scen = scenario("TEST-LINUX-NET-ALLOW-001", Category::Net);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "mkfifo \"$VETTO_VNG_ROOT/ipc.fifo\" || exit 10\n\
         (echo ping > \"$VETTO_VNG_ROOT/ipc.fifo\" &)\n\
         if read -r line < \"$VETTO_VNG_ROOT/ipc.fifo\"; then [ \"$line\" = ping ] && exit 0 || exit 10; else exit 10; fi\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "AF_UNIX/local IPC must keep working under UnixOnly"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Process isolation + tree containment
// ---------------------------------------------------------------------------

/// TEST-LINUX-PROC-ESCAPE-001: setsid-detached sleep is swept, run completes.
#[test]
fn test_linux_proc_escape_001() {
    let scen = scenario("TEST-LINUX-PROC-ESCAPE-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "setsid sleep 30 >/dev/null 2>&1 < /dev/null &\nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "run must complete without hanging on the escaper"
    );
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "sweep must observably clean the tree: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-GRANDCHILD-001: grandchild holding no pipes is reaped by the tree kill.
#[test]
fn test_linux_grandchild_001() {
    let scen = scenario("TEST-LINUX-GRANDCHILD-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "sh -c 'sleep 30' &\nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "grandchild must not stall the run"
    );
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "tree must be observably clean: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-TREE-KILL-001: deadline fires on the whole group, not just the root.
#[test]
fn test_linux_tree_kill_001() {
    let scen = scenario("TEST-LINUX-TREE-KILL-001", Category::Proc);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "sleep 30 &\nsleep 60\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(4),
    );
    assert_eq!(log.len(), 1);
    assert!(out.timed_out, "deadline must fire");
    assert_ne!(out.exit_code, Some(0));
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "deadline tree kill must leave no residuals: {}",
        report.render_deterministic()
    );
    assert_no_pass(&out);
}

/// TEST-LINUX-ORPHAN-001: instant parent exit with a live orphan still completes clean.
#[test]
fn test_linux_orphan_001() {
    let scen = scenario("TEST-LINUX-ORPHAN-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "(sleep 30 &)\nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "orphan must not stall or succeed the run"
    );
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "orphan must be observably reaped: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Resource limits (setrlimit ceilings, host-verified via /proc/pid/limits)
// ---------------------------------------------------------------------------

/// TEST-LINUX-MEM-LIMIT-001: allocation past RLIMIT_AS fails.
#[test]
fn test_linux_mem_limit_001() {
    require_tool("awk");
    let scen = scenario("TEST-LINUX-MEM-LIMIT-001", Category::Proc);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "awk 'BEGIN{ s=\"x\"; while (length(s) < 400000000) s = s s \"xxxxxxxxxxxxxxxx\"; print length(s) }' >/dev/null 2>&1\nexit $?\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_ne!(
        out.exit_code,
        Some(0),
        "allocation past the address-space ceiling must fail"
    );
    assert_eq!(
        report.state(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "limits must be host-verified: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-PID-LIMIT-001: fork past RLIMIT_NPROC fails with EAGAIN.
#[test]
fn test_linux_pid_limit_001() {
    let scen = scenario("TEST-LINUX-PID-LIMIT-001", Category::Proc);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "n=0\n\
         while [ $n -lt 300 ]; do sleep 20 & n=$((n + 1)); done 2>/dev/null\n\
         c=$(jobs | wc -l | tr -d ' ')\n\
         if [ \"$c\" -ge 300 ]; then exit 10; else exit 0; fi\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "the process ceiling must stop unbounded forking"
    );
    assert_eq!(
        report.state(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "limits must be host-verified: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-CPU-LIMIT-001: busy loop dies by kernel CPU limit, not the deadline.
#[test]
fn test_linux_cpu_limit_001() {
    let scen = scenario("TEST-LINUX-CPU-LIMIT-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "while :; do :; done\nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(25),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::ResourceLimits) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_ne!(
        out.exit_code,
        Some(0),
        "unbounded CPU must be stopped by the kernel limit"
    );
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "kernel limit (5s CPU) must fire well before the 25s deadline"
    );
    assert_eq!(
        report.state(SecurityCapability::ResourceLimits),
        EnforcementState::Verified,
        "limits must be host-verified: {}",
        report.render_deterministic()
    );
    assert_no_pass(&out);
}

// ---------------------------------------------------------------------------
// Syscall restriction (seccomp hardening denylist)
// ---------------------------------------------------------------------------

const PTRACE_TRACEME_PY: &str = "import os, sys\n\
try:\n\
    import ctypes\n\
except Exception as e:\n\
    sys.stderr.write('NO_CTYPES:%r\\n' % (e,))\n\
    os._exit(11)\n\
libc = ctypes.CDLL(None, use_errno=True)\n\
r = libc.ptrace(0, 0, 0, 0)\n\
e = ctypes.get_errno()\n\
sys.stderr.write('PTRACE r=%r errno=%r\\n' % (r, e))\n\
os._exit(0 if (r == -1 and e == 1) else 10)\n";

/// TEST-LINUX-SYSCALL-DENY-001: ptrace(TRACEME) is denied with EPERM.
#[test]
fn test_linux_syscall_deny_001() {
    require_tool("python3");
    let scen = scenario("TEST-LINUX-SYSCALL-DENY-001", Category::Proc);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["python3"],
        PTRACE_TRACEME_PY,
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::SyscallRestriction) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "ptrace must be denied with EPERM by the filter; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(
        report.state(SecurityCapability::SyscallRestriction),
        EnforcementState::Verified,
        "Seccomp: 2 must be host-observed: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-SYSCALL-ESCAPE-001: mount/chroot/ptrace escape attempts denied.
#[test]
fn test_linux_syscall_escape_001() {
    require_tool("python3");
    let scen = scenario("TEST-LINUX-SYSCALL-ESCAPE-001", Category::Proc);
    let net = NetMode::Off;
    let script = "import os, sys\n\
try:\n\
    import ctypes\n\
except Exception as e:\n\
    sys.stderr.write('NO_CTYPES:%r\\n' % (e,))\n\
    os._exit(11)\n\
libc = ctypes.CDLL(None, use_errno=True)\n\
\n\
def denied(fn, name):\n\
    ctypes.set_errno(0)\n\
    r = fn()\n\
    e = ctypes.get_errno()\n\
    sys.stderr.write('%s r=%r errno=%r\\n' % (name, r, e))\n\
    return r == -1 and e == 1\n\
\n\
ok = True\n\
ok = denied(lambda: libc.ptrace(0, 0, 0, 0), 'ptrace') and ok\n\
ok = denied(lambda: libc.mount(b\"none\", b\"/tmp/vetto-mnt-x\", b\"tmpfs\", 0, None), 'mount') and ok\n\
ok = denied(lambda: libc.chroot(b\"/tmp\"), 'chroot') and ok\n\
os._exit(0 if ok else 10)\n";
    let (out, log) = run_linux(
        &scen,
        &["python3"],
        script,
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::SyscallRestriction) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "mount/chroot/ptrace escapes must be denied; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Privilege boundary (NO_NEW_PRIVS, capabilities, uid)
// ---------------------------------------------------------------------------

/// TEST-LINUX-PRIV-ESCAPE-001: su/sudo/userns escalation attempts all fail.
#[test]
fn test_linux_priv_escape_001() {
    let scen = scenario("TEST-LINUX-PRIV-ESCAPE-001", Category::Proc);
    let forbid = forbid_file("priv-escape");
    let net = NetMode::Off;
    let mut env = test_env_forbid(&forbid);
    env.insert(
        "VETTO_VNG_TEST_SIBLING".to_string(),
        forbid.display().to_string(),
    );
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "fail=0\n\
         su root -c true 2>/dev/null && fail=1\n\
         sudo -n true 2>/dev/null && fail=1\n\
         if unshare -rm sh -c \"cat \\\"$VETTO_VNG_TEST_FORBID\\\"\" 2>/dev/null; then fail=1; fi\n\
         if [ \"$(id -u)\" != \"$(id -ru)\" ]; then fail=1; fi\n\
         exit $fail\n",
        &net,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessIsolation) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "privilege escalation must be impossible"
    );
    assert_eq!(
        report.state(SecurityCapability::ProcessIsolation),
        EnforcementState::Verified,
        "NoNewPrivs + pgroup must be host-observed: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-NO-NEW-PRIVS-001: NoNewPrivs flag observably set.
#[test]
fn test_linux_no_new_privs_001() {
    let scen = scenario("TEST-LINUX-NO-NEW-PRIVS-001", Category::Proc);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "if grep -q 'NoNewPrivs:[[:space:]]*1' /proc/self/status 2>/dev/null; then exit 0; else exit 10; fi\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessIsolation) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(out.exit_code, Some(0), "NoNewPrivs must be set");
    assert_eq!(
        report.state(SecurityCapability::ProcessIsolation),
        EnforcementState::Verified,
        "NoNewPrivs must be host-observed: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Fail-closed / partial / fake-enforcement regression
// ---------------------------------------------------------------------------

/// TEST-LINUX-FAIL-CLOSED-001: allowlist net has no relay here -> Unsupported -> no PASS.
#[test]
fn test_linux_fail_closed_001() {
    let scen = scenario("TEST-LINUX-FAIL-CLOSED-001", Category::Net);
    let net = NetMode::Allowlist(vec!["example.com".to_string()]);
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "exit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    assert_eq!(
        report.state(SecurityCapability::NetworkIsolation),
        EnforcementState::Unsupported,
        "allowlist relay does not exist in verify-ng: {}",
        report.render_deterministic()
    );
    assert!(!allows_pass(
        report,
        &scenario("TEST-LINUX-FAIL-CLOSED-001", Category::Net)
    ));
    assert_eq!(
        apply_backend_ceiling(Verdict::Pass, report, &scen),
        Verdict::Inconclusive
    );
    assert_no_pass(&out);
}

/// TEST-LINUX-PARTIAL-ENFORCEMENT-001: mixed Enforced/Unsupported is honest, never PASS.
#[test]
fn test_linux_partial_enforcement_001() {
    let scen = scenario("TEST-LINUX-PARTIAL-ENFORCEMENT-001", Category::FsRead);
    let net = NetMode::Allowlist(vec!["example.com".to_string()]);
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "exit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    let states: Vec<EnforcementState> = report.records.iter().map(|r| r.state).collect();
    assert!(
        states.contains(&EnforcementState::Unsupported),
        "partial run must name what is unsupported: {}",
        report.render_deterministic()
    );
    assert!(
        states.contains(&EnforcementState::Enforced)
            || states.contains(&EnforcementState::Verified),
        "partial run must name what is enforced: {}",
        report.render_deterministic()
    );
    assert!(!allows_pass(report, &scen));
    assert_no_pass(&out);
}

/// TEST-LINUX-FAKE-ENFORCEMENT-001: supports() never implies enforced (no spawn).
#[test]
fn test_linux_fake_enforcement_001() {
    let scen = scenario("TEST-LINUX-FAKE-ENFORCEMENT-001", Category::Aux);
    let backend = LinuxBackend::new();
    // Static support is a mechanism claim, not proof: it must never read
    // as enforcement without a prepared report and a real spawn.
    let _ = backend.supports(SecurityCapability::FilesystemIsolation);
    assert!(
        !backend.is_enforced(SecurityCapability::FilesystemIsolation),
        "unprepared backend enforces nothing"
    );
    assert!(
        required_capabilities(&scen).contains(&SecurityCapability::HostEvidence),
        "aux requires host evidence"
    );
}

// ---------------------------------------------------------------------------
// Adversarial escape suite (boundary attacks, one capability each)
// ---------------------------------------------------------------------------

/// TEST-LINUX-ESCAPE-FS-001: write-escape through a planted symlink denied.
#[test]
fn test_linux_escape_fs_001() {
    let scen = scenario("TEST-LINUX-ESCAPE-FS-001", Category::FsWrite);
    let forbid = forbid_file("escape-fs");
    let before = forbid_bytes(&forbid);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "ln -sf \"$VETTO_VNG_TEST_FORBID\" \"$VETTO_VNG_ROOT/wlink\" 2>/dev/null\n\
         if printf x > \"$VETTO_VNG_ROOT/wlink\" 2>/dev/null; then exit 10; fi\n\
         if printf x >> \"$VETTO_VNG_TEST_FORBID\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        &net,
        test_env_forbid(&forbid),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "symlink write-escape denied; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(forbid_bytes(&forbid), before, "canary intact (host-read)");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-ESCAPE-NET-001: connect from inside a fresh userns still blocked.
#[test]
fn test_linux_escape_net_001() {
    require_tool("bash");
    let scen = scenario("TEST-LINUX-ESCAPE-NET-001", Category::Net);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("host listener must bind");
    let port = listener.local_addr().expect("port").port();
    std::thread::spawn(move || {
        let _ = listener.accept();
    });
    let net = NetMode::Off;
    let env = BTreeMap::from([("VETTO_VNG_TEST_PORT".to_string(), port.to_string())]);
    let (out, log) = run_linux(
        &scen,
        &["bash"],
        "port=\"$VETTO_VNG_TEST_PORT\"\n\
         if unshare -Ur bash -c \"(exec 3<>/dev/tcp/127.0.0.1/$port) 2>/dev/null\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        &net,
        env,
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::NetworkIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "userns connect-escape must stay blocked"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-ESCAPE-PROC-001: double-fork daemon escape still swept.
#[test]
fn test_linux_escape_proc_001() {
    let scen = scenario("TEST-LINUX-ESCAPE-PROC-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "( (setsid sleep 30 >/dev/null 2>&1 < /dev/null &) & )\nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "daemon escape must not stall the run"
    );
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "daemon escape must be observably swept: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-ESCAPE-PRIV-001: root-mapped userns still cannot read the canary.
#[test]
fn test_linux_escape_priv_001() {
    let scen = scenario("TEST-LINUX-ESCAPE-PRIV-001", Category::Secrets);
    let forbid = forbid_file("escape-priv");
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "if unshare -rm cat \"$VETTO_VNG_TEST_FORBID\" >/dev/null 2>&1; then exit 10; else exit 0; fi\n",
        &net,
        test_env_forbid(&forbid),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "root-mapped userns must not pierce the allowlist"
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    let _ = std::fs::remove_file(&forbid);
}

/// TEST-LINUX-ESCAPE-SYSCALL-001: raw-syscall hardening escape denied.
#[test]
fn test_linux_escape_syscall_001() {
    require_tool("python3");
    let scen = scenario("TEST-LINUX-ESCAPE-SYSCALL-001", Category::Proc);
    let net = NetMode::Off;
    let script = "import os, sys\n\
try:\n\
    import ctypes\n\
except Exception as e:\n\
    sys.stderr.write('NO_CTYPES:%r\\n' % (e,))\n\
    os._exit(11)\n\
libc = ctypes.CDLL(None, use_errno=True)\n\
\n\
def denied(fn, name):\n\
    ctypes.set_errno(0)\n\
    r = fn()\n\
    e = ctypes.get_errno()\n\
    sys.stderr.write('%s r=%r errno=%r\\n' % (name, r, e))\n\
    return r == -1 and e == 1\n\
\n\
ok = True\n\
ok = denied(lambda: libc.ptrace(0, 0, 0, 0), 'ptrace') and ok\n\
ok = denied(lambda: libc.mount(b\"none\", b\"/tmp/vetto-mnt-y\", b\"tmpfs\", 0, None), 'mount') and ok\n\
ok = denied(lambda: libc.chroot(b\"/\"), 'chroot') and ok\n\
os._exit(0 if ok else 10)\n";
    let (out, log) = run_linux(
        &scen,
        &["python3"],
        script,
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    if report.state(SecurityCapability::SyscallRestriction) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "hardened syscalls stay denied; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-ESCAPE-ROOT-001: chroot + `/` listing denied.
#[test]
fn test_linux_escape_root_001() {
    require_tool("python3");
    let scen = scenario("TEST-LINUX-ESCAPE-ROOT-001", Category::FsRead);
    let net = NetMode::Off;
    let script = "import os, sys\n\
try:\n\
    import ctypes\n\
except Exception as e:\n\
    sys.stderr.write('NO_CTYPES:%r\\n' % (e,))\n\
    os._exit(11)\n\
libc = ctypes.CDLL(None, use_errno=True)\n\
ctypes.set_errno(0)\n\
r = libc.chroot(b\"/tmp\")\n\
e = ctypes.get_errno()\n\
sys.stderr.write('chroot r=%r errno=%r\\n' % (r, e))\n\
os._exit(0 if (r == -1 and e == 1) else 10)\n";
    let (out, log) = run_linux(
        &scen,
        &["python3"],
        script,
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    if !require_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        return;
    }
    assert_eq!(
        out.exit_code,
        Some(0),
        "chroot escape denied; stderr: {}",
        tail_text(&out.stderr, 500)
    );
    // Belt and braces at the shell level too: `/` itself is not listable.
    let scen2 = scenario("TEST-LINUX-ESCAPE-ROOT-001B", Category::FsRead);
    let (out2, _) = run_linux(
        &scen2,
        &["sh"],
        "if ls / >/dev/null 2>&1; then exit 10; else exit 0; fi\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(
        out2.exit_code,
        Some(0),
        "`/` listing denied; stderr: {}",
        tail_text(&out2.stderr, 500)
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

/// TEST-LINUX-ESCAPE-GRANDCHILD-001: three-level sleep chain fully reaped.
#[test]
fn test_linux_escape_grandchild_001() {
    let scen = scenario("TEST-LINUX-ESCAPE-GRANDCHILD-001", Category::Proc);
    let net = NetMode::Off;
    let start = std::time::Instant::now();
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "sh -c 'sh -c \"sleep 30\" &' \nexit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(20),
    );
    assert_eq!(log.len(), 1);
    assert!(
        start.elapsed() < Duration::from_secs(20),
        "deep chain must not stall the run"
    );
    let report = report_of(&out);
    if report.state(SecurityCapability::ProcessTreeContainment) == EnforcementState::Unsupported {
        assert_no_pass(&out);
        return;
    }
    assert_eq!(
        report.state(SecurityCapability::ProcessTreeContainment),
        EnforcementState::Verified,
        "deep chain observably reaped: {}",
        report.render_deterministic()
    );
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
}

// ---------------------------------------------------------------------------
// Cross-checks: identity, determinism, and Stage 2 preservation on Linux
// ---------------------------------------------------------------------------

/// Linux runs stay bound to scenario/session/registry/frozen identity.
#[test]
fn test_linux_identity_bound_001() {
    let scen = scenario("TEST-LINUX-IDENTITY-BOUND-001", Category::FsRead);
    let net = NetMode::Off;
    let (out, log) = run_linux(
        &scen,
        &["sh"],
        "exit 0\n",
        &net,
        BTreeMap::new(),
        Duration::from_secs(15),
    );
    assert_eq!(log.len(), 1);
    let report = report_of(&out);
    assert!(report.binds_identity(&out.execution_identity));
    assert_eq!(out.backend_kind, BackendKind::Linux);
    let id = ExecutionIdentity::new(
        &out.execution_identity.scenario_id,
        "foreign-nonce",
        &out.execution_identity.registry_hash,
        &out.execution_identity.frozen_hash,
    );
    assert!(!report.binds_identity(&id));
}

/// Canonical policy is stable across repeated runs (no platform mutation).
#[test]
fn test_linux_policy_stable_001() {
    use vetto::verify_ng::frozen::FrozenSpec;
    let mk = || FrozenSpec {
        scenario_id: "TEST-LINUX-POLICY-STABLE-001".to_string(),
        registry_hash: "reg-test".to_string(),
        tier: "direct".to_string(),
        net_mode: "off".to_string(),
        backend: "linux (landlock+seccomp+rlimit+pgroup; no userns)".to_string(),
        argv: vec!["sh".to_string()],
        env: BTreeMap::new(),
        cwd: std::path::PathBuf::from("/tmp"),
        allow_read: Vec::new(),
        allow_write: Vec::new(),
        deny_read: Vec::new(),
        deny_write: Vec::new(),
        deny_resolved: Vec::new(),
        nonce: "nonce-test".to_string(),
        policy_bytes: b"test-policy".to_vec(),
    };
    let a = CanonicalPolicy::from_frozen(&mk());
    let b = CanonicalPolicy::from_frozen(&mk());
    assert_eq!(a, b, "canonical policy must be deterministic");
}
