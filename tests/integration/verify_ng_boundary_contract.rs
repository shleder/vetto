//! Phase 2 authoritative boundary verification tests: Filesystem (Section 4)
//! and Secret Isolation (Section 8) battery against real Linux enforcement.
//!
//! Every test consumes the SAME sealed [`SecurityContract`] used by production
//! execution, verifies contract digest integrity (fail-closed on tampering),
//! and tests actual OS enforcement (Landlock + seccomp + rlimit + pgroup).
//! Verdicts are based strictly on host-observed facts (HOST_FACT), never child
//! self-reports.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::SecurityContract;
use vetto::verify_ng::model::{Category, ClaimStrength, Verdict};
use vetto::verify_ng::registry::{registry, Scenario, Severity};
use vetto::verify_ng::sandbox_backend::{EnforcementState, LinuxBackend, SecurityCapability};
use vetto::verify_ng::{engine, runner};

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_test_id(prefix: &str) -> String {
    let n = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("vetto-bnd-{prefix}-{}-{n}", std::process::id())
}

/// Create a test scenario.
fn test_scenario(id: &str, category: Category, quorum: usize) -> Scenario {
    let target = engine::current_target(None);
    Scenario {
        id: id.to_string(),
        category,
        severity: Severity::Blocker,
        required_caps: vec!["spawn".to_string(), "landlock".to_string()],
        strength: BTreeMap::from([
            (target.label().to_string(), ClaimStrength::Strong),
            ("linux-full".to_string(), ClaimStrength::Strong),
            ("linux-fsonly".to_string(), ClaimStrength::Strong),
        ]),
        quorum,
        known_limitation: "Phase 2 boundary battery test".to_string(),
        residual_risk: String::new(),
    }
}

/// Helper: creates a dedicated temp directory.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(next_test_id(name));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Helper: compile and seal an authoritative SecurityContract for the given
/// workspace and policy. This uses the EXACT production compiler path.
fn seal_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    nonce: &str,
) -> SecurityContract {
    let argv_strings: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let env_vars = BTreeMap::new();
    let input = EffectivePolicyInput {
        policy,
        argv: &argv_strings,
        cwd: workspace,
        env: &env_vars,
        net: &NetMode::Off,
        nonce,
        timeout: Some(Duration::from_secs(30)),
        tier: None,
        backend: "linux-landlock".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    PolicyCompiler::compile_effective(input).expect("compile and seal contract")
}

/// Run a scenario under LinuxBackend using a sealed SecurityContract.
fn run_linux_contract(
    scen: &Scenario,
    contract: &SecurityContract,
    script: &str,
    sentinels: Vec<(String, Vec<u8>)>,
    enable_host_control: bool,
) -> (runner::ExecutionOutcome, runner::SpawnLog) {
    let production = contract
        .production
        .as_ref()
        .expect("production contract in sealed contract");
    let policy = &production.installation_policy;
    let req = runner::ExecutionRequest {
        scenario: scen,
        policy,
        net_mode: &production.net,
        interpreter: vec!["sh".to_string()],
        script_args: Vec::new(),
        script: script.as_bytes().to_vec(),
        sentinels,
        env_extra: BTreeMap::new(),
        deadline: Duration::from_secs(15),
        enable_host_control,
        contract: Some(contract),
        host_env_override: None,
    };
    let mut backend = LinuxBackend::new();
    let mut log = runner::SpawnLog::new();
    let out = runner::run_one_with_backend(&req, &mut log, &mut backend);
    (out, log)
}

fn assert_enforced_or_skip(out: &runner::ExecutionOutcome, cap: SecurityCapability) -> bool {
    if let Some(report) = &out.backend_report {
        if report.state(cap) == EnforcementState::Unsupported {
            assert_ne!(out.result.verdict, Verdict::Pass);
            return false;
        }
        assert!(
            report.state(cap).is_enforced(),
            "{cap:?} must be enforced: {}",
            report.render_deterministic()
        );
        true
    } else {
        false
    }
}

// ---------------------------------------------------------------------------
// 1. Contract Tampering & Digest Integrity
// ---------------------------------------------------------------------------

#[test]
fn test_contract_tamper_rejected_no_spawn() {
    let scen = test_scenario("BND-TAMPER-001", Category::FsRead, 1);
    let ws = temp_dir("ws-tamper");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let mut contract = seal_contract(&ws, &policy, &["sh"], "nonce-tamper-01");
    assert!(contract.verify_digest());

    // Tamper with filesystem allow_write after sealing
    contract.filesystem.allow_write.push(PathBuf::from("/etc"));
    assert!(
        !contract.verify_digest(),
        "tampered contract must fail digest verification"
    );

    let (out, log) = run_linux_contract(&scen, &contract, "exit 0\n", Vec::new(), false);

    assert_eq!(log.len(), 0, "tampered contract must never spawn child");
    assert_eq!(out.result.verdict, Verdict::Inconclusive);
    assert!(out.spawn_pid.is_none());
    assert!(out
        .result
        .detail
        .contains("invalid security contract digest"));

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 2. Traversal and '..' Escapes (Master Task Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_traversal_dotdot_escape_denied() {
    let scen = test_scenario("BND-TRAV-DOTDOT-001", Category::FsRead, 1);
    let parent = temp_dir("parent");
    let ws = parent.join("workspace");
    let outside = parent.join("outside");
    std::fs::create_dir_all(&ws).expect("create ws");
    std::fs::create_dir_all(&outside).expect("create outside");

    let canary_file = outside.join("secret_data.txt");
    let canary_bytes = b"top-secret-traversal-canary\n";
    std::fs::write(&canary_file, canary_bytes).expect("write canary");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trav-01");

    let script = format!(
        "if cat \"$VETTO_VNG_ROOT/../../{}/secret_data.txt\" >/dev/null 2>&1; then exit 10; fi\n\
         if printf pwned >> \"$VETTO_VNG_ROOT/../../{}/secret_data.txt\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        outside.file_name().unwrap().to_str().unwrap(),
        outside.file_name().unwrap().to_str().unwrap()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "dotdot traversal attacks must be denied"
    );
    assert_eq!(
        std::fs::read(&canary_file).unwrap(),
        canary_bytes,
        "host canary intact"
    );

    let _ = std::fs::remove_dir_all(&parent);
}

// ---------------------------------------------------------------------------
// 3. Symlink Escapes: workspace/{allowed/, link -> /outside/} (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_symlink_workspace_allowed_and_link_to_outside() {
    let scen = test_scenario("BND-SYMLINK-WS-001", Category::FsRead, 1);
    let parent = temp_dir("symlink-parent");
    let ws = parent.join("workspace");
    let outside = parent.join("outside");
    let allowed = ws.join("allowed");
    std::fs::create_dir_all(&allowed).expect("create allowed");
    std::fs::create_dir_all(&outside).expect("create outside");

    // Outside canary
    let outside_secret = outside.join("outside_secret.txt");
    let secret_bytes = b"outside-sensitive-bytes\n";
    std::fs::write(&outside_secret, secret_bytes).expect("write secret");

    // workspace/link -> outside
    let link_path = ws.join("link");
    std::os::unix::fs::symlink(&outside, &link_path).expect("create symlink to outside");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-symlink-ws-01");

    // Confined payload attempts access through workspace/{allowed/, link -> /outside/}
    let script = format!(
        "target=\"{}\"\n\
         link_target=\"{}\"\n\
         # Direct read via symlink link/outside_secret.txt\n\
         if cat \"$link_target/outside_secret.txt\" >/dev/null 2>&1; then exit 10; fi\n\
         # Traversal from allowed/ to ../link/outside_secret.txt\n\
         if cat \"$target/../link/outside_secret.txt\" >/dev/null 2>&1; then exit 10; fi\n\
         # Write through symlink\n\
         if printf pwn >> \"$link_target/outside_secret.txt\" 2>/dev/null; then exit 10; fi\n\
         if printf pwn > \"$link_target/new_escape.txt\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        allowed.display(),
        link_path.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "symlink escape must be denied by Landlock"
    );
    assert_eq!(
        std::fs::read(&outside_secret).unwrap(),
        secret_bytes,
        "secret intact"
    );
    assert!(
        !outside.join("new_escape.txt").exists(),
        "new file must not be created"
    );

    let _ = std::fs::remove_dir_all(&parent);
}

// ---------------------------------------------------------------------------
// 4. Symlink / Race (TOCTOU) Variants (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_symlink_race_toctou_denied() {
    let scen = test_scenario("BND-SYMLINK-RACE-001", Category::FsWrite, 1);
    let parent = temp_dir("symlink-race");
    let ws = parent.join("workspace");
    let outside = parent.join("outside");
    std::fs::create_dir_all(&ws).expect("create ws");
    std::fs::create_dir_all(&outside).expect("create outside");

    let victim_file = outside.join("victim.txt");
    let victim_bytes = b"untouched-victim\n";
    std::fs::write(&victim_file, victim_bytes).expect("write victim");

    let safe_file = ws.join("safe.txt");
    std::fs::write(&safe_file, b"safe\n").expect("write safe");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-symlink-race-01");

    // Script creates a symlink pointing to safe file, then swaps it to outside victim
    // and attempts write in rapid succession
    let script = format!(
        "link=\"{}/swap_link\"\n\
         outside_victim=\"{}\"\n\
         safe=\"{}\"\n\
         ln -sf \"$safe\" \"$link\"\n\
         # Rapid swap\n\
         for i in $(seq 1 50); do\n\
           ln -sf \"$outside_victim\" \"$link.tmp\" && mv -T -f \"$link.tmp\" \"$link\" 2>/dev/null\n\
           if printf pwn >> \"$link\" 2>/dev/null; then exit 10; fi\n\
           ln -sf \"$safe\" \"$link.tmp\" && mv -T -f \"$link.tmp\" \"$link\" 2>/dev/null\n\
         done\n\
         exit 0\n",
        ws.display(),
        victim_file.display(),
        safe_file.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "symlink race attacks must not breach boundary"
    );
    assert_eq!(
        std::fs::read(&victim_file).unwrap(),
        victim_bytes,
        "victim intact"
    );

    let _ = std::fs::remove_dir_all(&parent);
}

// ---------------------------------------------------------------------------
// 5. Absolute Path Escape (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_absolute_path_escape_denied() {
    let scen = test_scenario("BND-ABS-PATH-001", Category::FsRead, 1);
    let ws = temp_dir("ws-abs");
    let outside_dir = temp_dir("outside-abs");
    let outside_file = outside_dir.join("absolute_target.txt");
    std::fs::write(&outside_file, b"absolute-secret\n").expect("write secret");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-abs-01");

    let script = format!(
        "if cat \"{}\" >/dev/null 2>&1; then exit 10; fi\n\
         if cat /etc/shadow >/dev/null 2>&1; then exit 10; fi\n\
         exit 0\n",
        outside_file.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside_dir);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "absolute path escape must be denied"
    );
    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside_dir);
}

// ---------------------------------------------------------------------------
// 6. Forbidden Read, Write, Create, Delete (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_forbidden_read_write_create_delete() {
    let scen = test_scenario("BND-FORBID-OPS-001", Category::FsWrite, 1);
    let ws = temp_dir("ws-ops");
    let outside = temp_dir("outside-ops");

    let outside_file = outside.join("canary.txt");
    let before_bytes = b"immutable-canary-content\n";
    std::fs::write(&outside_file, before_bytes).expect("write canary");

    let outside_subdir = outside.join("subdir");
    std::fs::create_dir_all(&outside_subdir).expect("create subdir");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-ops-01");

    let script = format!(
        "target_f=\"{}\"\n\
         target_d=\"{}\"\n\
         # 1. Forbidden READ\n\
         if cat \"$target_f\" >/dev/null 2>&1; then exit 10; fi\n\
         # 2. Forbidden WRITE\n\
         if printf pwn >> \"$target_f\" 2>/dev/null; then exit 10; fi\n\
         # 3. Forbidden CREATE regular file\n\
         if touch \"{}/new_file.txt\" 2>/dev/null; then exit 10; fi\n\
         # 4. Forbidden CREATE directory\n\
         if mkdir \"{}/new_dir\" 2>/dev/null; then exit 10; fi\n\
         # 5. Forbidden DELETE file\n\
         if rm \"$target_f\" 2>/dev/null; then exit 10; fi\n\
         # 6. Forbidden DELETE directory\n\
         if rmdir \"$target_d\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        outside_file.display(),
        outside_subdir.display(),
        outside.display(),
        outside.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "read/write/create/delete outside workspace must be denied"
    );
    assert_eq!(
        std::fs::read(&outside_file).unwrap(),
        before_bytes,
        "canary unchanged"
    );
    assert!(outside_subdir.exists(), "subdir was not deleted");
    assert!(
        !outside.join("new_file.txt").exists(),
        "new file was not created"
    );
    assert!(!outside.join("new_dir").exists(), "new dir was not created");

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside);
}

// ---------------------------------------------------------------------------
// 7. Rename / Move Across Boundary (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_rename_across_boundary_denied() {
    let scen = test_scenario("BND-RENAME-001", Category::FsWrite, 1);
    let ws = temp_dir("ws-rename");
    let outside = temp_dir("outside-rename");

    let ws_file = ws.join("local.txt");
    std::fs::write(&ws_file, b"local-content\n").expect("write local");

    let outside_file = outside.join("outside.txt");
    std::fs::write(&outside_file, b"outside-content\n").expect("write outside");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-rename-01");

    let script = format!(
        "# Move out of workspace\n\
         if mv \"{}\" \"{}/stolen_out.txt\" 2>/dev/null; then exit 10; fi\n\
         # Move into workspace\n\
         if mv \"{}\" \"{}/stolen_in.txt\" 2>/dev/null; then exit 10; fi\n\
         exit 0\n",
        ws_file.display(),
        outside.display(),
        outside_file.display(),
        ws.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "rename across boundary must be denied"
    );
    assert!(ws_file.exists(), "local file remained in workspace");
    assert!(outside_file.exists(), "outside file remained outside");
    assert!(!outside.join("stolen_out.txt").exists());
    assert!(!ws.join("stolen_in.txt").exists());

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside);
}

// ---------------------------------------------------------------------------
// 8. Alternate Filesystem Representations (Section 4)
// ---------------------------------------------------------------------------

#[test]
fn test_boundary_alternate_representations_denied() {
    let scen = test_scenario("BND-ALT-REPR-001", Category::FsRead, 1);
    let parent = temp_dir("alt-repr");
    let ws = parent.join("workspace");
    let outside = parent.join("outside");
    std::fs::create_dir_all(&ws).expect("create ws");
    std::fs::create_dir_all(&outside).expect("create outside");

    let outside_file = outside.join("canary.txt");
    std::fs::write(&outside_file, b"secret\n").expect("write secret");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-alt-01");

    let script = format!(
        "# Redundant slashes and dots\n\
         if cat \"/{}/..//..//{}/canary.txt\" >/dev/null 2>&1; then exit 10; fi\n\
         # Via /proc/self/cwd\n\
         if cat \"/proc/self/cwd/../outside/canary.txt\" >/dev/null 2>&1; then exit 10; fi\n\
         # Via /proc/self/root\n\
         if cat \"/proc/self/root{}\" >/dev/null 2>&1; then exit 10; fi\n\
         exit 0\n",
        ws.display(),
        outside.display(),
        outside_file.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&parent);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "alternate representations must not evade Landlock"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

// ---------------------------------------------------------------------------
// 9. Secret Isolation: Known secret paths, symlinks, relative traversal, alternate spellings (Section 8)
// ---------------------------------------------------------------------------

#[test]
fn test_secret_isolation_symlink_traversal_spelling() {
    let scen = test_scenario("BND-SECRET-ISO-001", Category::Secrets, 1);
    let ws = temp_dir("ws-secret");
    let secrets_dir = temp_dir("secrets-root");

    let ssh_key = secrets_dir.join("id_ed25519");
    let key_bytes =
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-data\n-----END OPENSSH PRIVATE KEY-----\n";
    std::fs::write(&ssh_key, key_bytes).expect("write ssh key");

    // Symlink inside workspace pointing to secret
    let symlink_to_secret = ws.join("secret_symlink");
    std::os::unix::fs::symlink(&ssh_key, &symlink_to_secret).expect("create symlink to secret");

    let mut policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    policy.deny_read.push(ssh_key.clone());
    policy.deny_resolved.push(vetto::policy::DenyEntry {
        path: ssh_key.clone(),
        is_dir: false,
    });

    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-secret-01");

    let script = format!(
        "key=\"{}\"\n\
         symlink=\"{}\"\n\
         # 1. Direct read of known secret path\n\
         if cat \"$key\" >/dev/null 2>&1; then exit 10; fi\n\
         # 2. Symlink to secret\n\
         if cat \"$symlink\" >/dev/null 2>&1; then exit 10; fi\n\
         # 3. Relative traversal to secret\n\
         if cat \"$VETTO_VNG_ROOT/../../{}/id_ed25519\" >/dev/null 2>&1; then exit 10; fi\n\
         # 4. Alternate path spelling (double slashes, dot slashes)\n\
         if cat \"/{}/.///id_ed25519\" >/dev/null 2>&1; then exit 10; fi\n\
         exit 0\n",
        ssh_key.display(),
        symlink_to_secret.display(),
        secrets_dir.file_name().unwrap().to_str().unwrap(),
        secrets_dir.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&secrets_dir);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "all secret read vectors must be denied"
    );
    assert_eq!(
        std::fs::read(&ssh_key).unwrap(),
        key_bytes,
        "secret key intact"
    );

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&secrets_dir);
}

// ---------------------------------------------------------------------------
// 10. Secret copied into accessible location prior to execution (Section 8)
// ---------------------------------------------------------------------------

#[test]
fn test_secret_copied_prior_to_execution_contract_semantics() {
    let scen = test_scenario("BND-SECRET-PRECOPY-001", Category::Secrets, 1);
    let ws = temp_dir("ws-precopy");

    // Clean project subdirectory for unmasked user code
    let src = ws.join("src");
    std::fs::create_dir_all(&src).expect("create src dir");

    // Case A: File inside workspace declared in mask_paths/deny_resolved (.env)
    let masked_file = ws.join(".env");
    std::fs::write(&masked_file, b"API_KEY=secret-token\n").expect("write masked file");

    // Case B: Ordinary user file inside clean subdirectory
    let user_file = src.join("user_code.py");
    std::fs::write(&user_file, b"print('hello')\n").expect("write user file");

    let mut policy = Policy {
        allow_read: vec![src.clone()],
        allow_write: vec![],
        ..Default::default()
    };
    policy.deny_read.push(masked_file.clone());
    policy.deny_resolved.push(vetto::policy::DenyEntry {
        path: masked_file.clone(),
        is_dir: false,
    });

    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-precopy-01");

    // Contract semantics test:
    // - masked_file must be denied (EACCES) despite being in workspace
    // - user_file must be readable (permitted by contract allow_read)
    let script = format!(
        "masked=\"{}\"\n\
         user=\"{}\"\n\
         discard=\"$VETTO_VNG_ROOT/discard.txt\"\n\
         # Reading masked file must FAIL\n\
         if cat \"$masked\" > \"$discard\" 2>&1; then exit 10; fi\n\
         # Reading unmasked workspace file must SUCCEED\n\
         if ! cat \"$user\" > \"$discard\" 2>&1; then exit 11; fi\n\
         exit 0\n",
        masked_file.display(),
        user_file.display()
    );

    let (out, log) = run_linux_contract(&scen, &contract, &script, Vec::new(), false);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(
        out.exit_code,
        Some(0),
        "contract semantics: masked file denied, unmasked workspace file allowed (stdout: {}, stderr: {})",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_dir_all(&ws);
}

// ---------------------------------------------------------------------------
// 11. Full PASS verification with sealed contract: VFS-TRAV-001 & VFS-WRITE-001
// ---------------------------------------------------------------------------

#[test]
fn test_vfs_trav_001_pass_with_sealed_contract() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "VFS-TRAV-001")
        .expect("VFS-TRAV-001 must exist in registry");

    let ws = temp_dir("ws-trav-pass");
    let outside = temp_dir("outside-trav-pass");
    let outside_secret = outside.join("canary.txt");
    std::fs::write(&outside_secret, b"secret-pass-canary\n").expect("write outside canary");

    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-trav-pass-01");

    // Positive control: rotate challenge from downlink and write to uplink
    let script = concat!(
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "S=\"$C$VETTO_VNG_NONCE\"\n",
        "head=${S%????????}\n",
        "tail=${S#$head}\n",
        "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "exit 0\n"
    );

    // Provide 2 sentinels so quorum=2 is met
    let sentinels = vec![
        (
            "sentinel_inside.txt".to_string(),
            b"inside-canary\n".to_vec(),
        ),
        (
            "sentinel_second.txt".to_string(),
            b"second-canary\n".to_vec(),
        ),
    ];

    let (out, log) = run_linux_contract(scen, &contract, script, sentinels, true);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        let _ = std::fs::remove_dir_all(&outside);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(out.control_observed, "host control must be verified");
    assert!(out.evidence.has_host_fact());
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "VFS-TRAV-001 must PASS with sealed contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
    let _ = std::fs::remove_dir_all(&outside);
}

#[test]
fn test_vfs_write_001_pass_with_sealed_contract() {
    let scenarios = registry();
    let scen = scenarios
        .iter()
        .find(|s| s.id == "VFS-WRITE-001")
        .expect("VFS-WRITE-001 must exist in registry");

    let ws = temp_dir("ws-write-pass");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-write-pass-01");

    let script = concat!(
        "IFS= read -r C < \"$VETTO_VNG_CONTROL_DOWNLINK\"\n",
        "S=\"$C$VETTO_VNG_NONCE\"\n",
        "head=${S%????????}\n",
        "tail=${S#$head}\n",
        "printf %s \"$tail$head\" > \"$VETTO_VNG_CONTROL_UPLINK\"\n",
        "exit 0\n"
    );

    let sentinels = vec![
        (
            "sentinel_postmortem.txt".to_string(),
            b"postmortem-data\n".to_vec(),
        ),
        ("sentinel_canary.txt".to_string(), b"canary-data\n".to_vec()),
    ];

    let (out, log) = run_linux_contract(scen, &contract, script, sentinels, true);
    assert_eq!(log.len(), 1);
    if !assert_enforced_or_skip(&out, SecurityCapability::FilesystemIsolation) {
        let _ = std::fs::remove_dir_all(&ws);
        return;
    }

    assert_eq!(out.exit_code, Some(0));
    assert!(out.control_observed, "host control must be verified");
    assert_eq!(
        out.result.verdict,
        Verdict::Pass,
        "VFS-WRITE-001 must PASS with sealed contract"
    );

    let _ = std::fs::remove_dir_all(&ws);
}

#[test]
fn test_sentinel_mutation_yields_fail() {
    let scen = test_scenario("BND-FAIL-MUTATE-001", Category::FsWrite, 1);
    let ws = temp_dir("ws-mutate");
    let policy = Policy {
        allow_read: vec![ws.clone()],
        allow_write: vec![ws.clone()],
        ..Default::default()
    };
    let contract = seal_contract(&ws, &policy, &["sh"], "nonce-mutate-01");

    // Script mutates the staged sentinel
    let script = "printf 'tampered' > \"$VETTO_VNG_ROOT/tamper_target.txt\"\nexit 0\n";
    let sentinels = vec![("tamper_target.txt".to_string(), b"original\n".to_vec())];

    let (out, log) = run_linux_contract(&scen, &contract, script, sentinels, false);
    assert_eq!(log.len(), 1);
    assert_eq!(
        out.result.verdict,
        Verdict::Fail,
        "mutated sentinel must fail closed to Verdict::Fail"
    );
    assert!(out.violation_observed);

    let _ = std::fs::remove_dir_all(&ws);
}
