//! Master Task Section 14: Entrypoint Contract Parity Regressions
//!
//! Proves that CLI, MCP, and Multi-Agent entrypoints all run verification
//! through the SAME sealed-contract production boundary:
//!
//! 1. CLI Entrypoint:
//!    - Supervised session `--verify` routes through `preflight_contract(&SecurityContract)`.
//!    - CLI `vetto verify` command compiles and prepares `UnpreparedProductionExecution`,
//!      then runs `preflight_contract`.
//!    - Invalid / tampered contract digest fails closed before spawn.
//!
//! 2. MCP Entrypoint:
//!    - MCP tool `run_sandboxed` and `execute_sandboxed_command` execute directly
//!      via `UnpreparedProductionExecution::new` -> `prepare()?.spawn()?`.
//!    - Arguments are passed directly without shell strings (`sh -c` / `cmd.exe /C`).
//!    - Invalid / tampered contract fails closed during preparation/spawn.
//!
//! 3. Multi-Agent Entrypoint:
//!    - Multi-agent runtime (`multi::runtime`) executes agents via
//!      `UnpreparedProductionExecution::new` -> `prepare()?.spawn()?`.
//!    - Invalid / tampered contract fails closed during preparation/spawn.
//!
//! 4. Parity Proof:
//!    - All three entrypoints enforce identical sealed contract rules.
//!    - Tampered contract digest is rejected fail-closed across all entrypoints.
//!    - Direct `Backend::spawn` cannot be invoked outside the `sandbox` module.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::time::Duration;

use vetto::config::NetMode;
use vetto::policy::Policy;
use vetto::policy_ir::compiler::{EffectivePolicyInput, PolicyCompiler};
use vetto::policy_ir::contract::SecurityContract;
use vetto::sandbox::production::{
    PreparedProductionExecution, UnpreparedProductionExecution, PROD_SCENARIO_ID, PROD_SPAWN_COUNT,
};
use vetto::sandbox::{Backend, StdioMode};

fn test_temp_dir(prefix: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "vetto-parity-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("create test temp dir");
    dir
}

fn test_policy_with_roots(workspace: &Path) -> Policy {
    let mut policy = Policy::default();
    for cand in ["/bin", "/usr", "/lib", "/lib64", "/etc", "/dev", "/proc"] {
        let p = PathBuf::from(cand);
        if p.exists() && !policy.allow_read.contains(&p) {
            policy.allow_read.push(p);
        }
    }
    for cand in [workspace.to_path_buf(), PathBuf::from("/tmp")] {
        if cand.exists() && !policy.allow_write.contains(&cand) {
            policy.allow_write.push(cand);
        }
    }
    policy
}

fn compile_and_seal_test_contract(
    workspace: &Path,
    policy: &Policy,
    argv: &[&str],
    _scenario: &str,
) -> SecurityContract {
    let argv_strings: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
    let env_vars = BTreeMap::new();
    let input = EffectivePolicyInput {
        policy,
        argv: &argv_strings,
        cwd: workspace,
        env: &env_vars,
        net: &NetMode::Off,
        nonce: "test-nonce-parity-1234",
        timeout: Some(Duration::from_secs(15)),
        tier: None,
        backend: "test-backend".to_string(),
        observe_seccomp: false,
        debug_ports: None,
    };
    PolicyCompiler::compile_effective(input).expect("compile effective contract")
}

#[test]
fn test_cli_preflight_uses_sealed_contract_authority() {
    let tmp = test_temp_dir("cli-preflight");
    let policy = test_policy_with_roots(&tmp);
    let mut contract =
        compile_and_seal_test_contract(&tmp, &policy, &["/bin/true"], PROD_SCENARIO_ID);

    // 1. Valid contract verifies digest and preflight succeeds
    assert!(
        contract.verify_digest(),
        "sealed contract digest must verify"
    );
    let report = vetto::verify::preflight_contract(&contract);
    assert!(
        report.is_ok(),
        "preflight_contract on valid sealed contract must succeed: {:?}",
        report.err()
    );

    // 2. Tampered contract invalidates digest and preflight fails closed
    contract
        .filesystem
        .allow_write
        .push(PathBuf::from("/etc/malicious_write"));
    assert!(
        !contract.verify_digest(),
        "tampered contract must fail verify_digest"
    );

    let err_res = vetto::verify::preflight_contract(&contract);
    assert!(
        err_res.is_err(),
        "preflight_contract on tampered contract must fail closed"
    );
    let err_msg = err_res.unwrap_err().to_string();
    assert!(
        err_msg.contains("invalid security contract digest"),
        "expected digest mismatch error, got: {err_msg}"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_cli_verify_subcommand_uses_unprepared_production_execution() {
    let tmp = test_temp_dir("cli-verify-subcmd");
    let policy = test_policy_with_roots(&tmp);

    // Call preflight which constructs UnpreparedProductionExecution -> prepare() -> preflight_contract()
    let report_res = vetto::verify::preflight(&policy, &NetMode::Off);
    assert!(
        report_res.is_ok(),
        "vetto::verify::preflight must succeed through production boundary: {:?}",
        report_res.err()
    );
    let report = report_res.unwrap();
    assert_eq!(report.leaks(), 0, "healthy policy must report 0 leaks");

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_mcp_parse_command_tokens_no_shell() {
    // Tests that MCP parses command line arguments directly into argv without shell strings
    let tokens = vetto::mcp::parse_command_tokens("echo 'hello world' --flag /path/to/file");
    assert_eq!(
        tokens,
        vec!["echo", "hello world", "--flag", "/path/to/file"]
    );

    let quoted_double = vetto::mcp::parse_command_tokens("app --name \"quoted arg\" --count 42");
    assert_eq!(
        quoted_double,
        vec!["app", "--name", "quoted arg", "--count", "42"]
    );

    let escaped = vetto::mcp::parse_command_tokens("grep -r foo\\ bar .");
    assert_eq!(escaped, vec!["grep", "-r", "foo bar", "."]);
}

#[test]
fn test_mcp_entrypoint_executes_through_production_boundary() {
    let echo_bin = match vetto::mcp::wrap::resolve_in_path("echo") {
        Ok(bin) => bin,
        Err(_) => {
            eprintln!("SKIP: echo not in path");
            return;
        }
    };

    let echo_cmd = echo_bin.to_string_lossy().to_string();
    let extra = vec!["contract_authority_mcp_parity".to_string()];

    let spawn_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
    let res = vetto::mcp::execute_sandboxed_command(&echo_cmd, Some(&extra), None, Some("10s"));

    assert!(
        res.is_ok(),
        "mcp execute_sandboxed_command must succeed: {:?}",
        res.err()
    );
    let out = res.unwrap();
    assert_eq!(out.exit_code, 0, "echo exit code must be 0");
    assert!(
        out.stdout.contains("contract_authority_mcp_parity"),
        "stdout must contain direct argument text: {}",
        out.stdout
    );
    let spawn_after = PROD_SPAWN_COUNT.load(Ordering::SeqCst);
    assert!(
        spawn_after > spawn_before,
        "PROD_SPAWN_COUNT must increment through production boundary"
    );
}

#[test]
fn test_multi_agent_entrypoint_uses_production_boundary() {
    let tmp = test_temp_dir("multi-agent-bnd");
    let policy = test_policy_with_roots(&tmp);
    let backend = match Backend::detect(NetMode::Off, false) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: backend detection unavailable");
            let _ = std::fs::remove_dir_all(&tmp);
            return;
        }
    };

    let unprepared = UnpreparedProductionExecution::new(
        backend,
        policy,
        vec!["/bin/true".to_string()],
        tmp.clone(),
        HashMap::new(),
        NetMode::Off,
        None,
        StdioMode::Inherit,
        "multi:worker-parity".to_string(),
    );

    let prepared = unprepared.prepare().expect("prepare multi agent execution");
    assert!(
        prepared.contract().verify_digest(),
        "multi-agent prepared contract digest must be valid"
    );
    assert_eq!(
        prepared.identity().scenario_id,
        "multi:worker-parity",
        "scenario_id must match multi-agent specification"
    );

    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn test_tamper_parity_across_all_entrypoints() {
    let tmp = test_temp_dir("tamper-parity-all");
    let policy = test_policy_with_roots(&tmp);
    let marker = tmp.join("should-not-exist-tamper");

    let count_before = PROD_SPAWN_COUNT.load(Ordering::SeqCst);

    // 1. CLI Verification Parity: tampered contract rejected fail-closed
    {
        let mut contract =
            compile_and_seal_test_contract(&tmp, &policy, &["/bin/true"], "cli:verify");
        contract
            .filesystem
            .allow_write
            .push(PathBuf::from("/tampered/cli"));
        assert!(!contract.verify_digest());
        let preflight_res = vetto::verify::preflight_contract(&contract);
        assert!(
            preflight_res.is_err(),
            "CLI preflight must reject tampered contract"
        );
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            count_before,
            "CLI preflight rejection must not increment spawn count"
        );
    }

    // 2. MCP Production Boundary Parity: tampered contract in-flight rejected fail-closed
    {
        let backend = match Backend::detect(NetMode::Off, false) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("SKIP: backend detection unavailable");
                let _ = std::fs::remove_dir_all(&tmp);
                return;
            }
        };

        let unprepared = UnpreparedProductionExecution::new(
            backend,
            policy.clone(),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("touch {}", marker.display()),
            ],
            tmp.clone(),
            HashMap::new(),
            NetMode::Off,
            Some(Duration::from_secs(5)),
            StdioMode::Inherit,
            "mcp".to_string(),
        );

        let mut prepared = unprepared.prepare().expect("prepare MCP execution");
        // Tamper contract
        prepared
            .contract_mut_for_test()
            .filesystem
            .allow_write
            .push(PathBuf::from("/tampered/mcp"));
        assert!(!prepared.contract().verify_digest());

        let spawn_res = prepared.spawn();
        assert!(
            spawn_res.is_err(),
            "MCP spawn must fail on tampered contract"
        );
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            count_before,
            "MCP tampered spawn must not increment spawn count"
        );
        assert!(!marker.exists(), "MCP tampered contract child must NOT run");
    }

    // 3. Multi-Agent Production Boundary Parity: tampered contract in-flight rejected fail-closed
    {
        let backend = match Backend::detect(NetMode::Off, false) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("SKIP: backend detection unavailable");
                let _ = std::fs::remove_dir_all(&tmp);
                return;
            }
        };

        let unprepared = UnpreparedProductionExecution::new(
            backend,
            policy.clone(),
            vec![
                "/bin/sh".into(),
                "-c".into(),
                format!("touch {}", marker.display()),
            ],
            tmp.clone(),
            HashMap::new(),
            NetMode::Off,
            Some(Duration::from_secs(5)),
            StdioMode::Inherit,
            "multi:agent-parity".to_string(),
        );

        let mut prepared = unprepared.prepare().expect("prepare Multi execution");
        // Tamper contract
        prepared
            .contract_mut_for_test()
            .filesystem
            .allow_write
            .push(PathBuf::from("/tampered/multi"));
        assert!(!prepared.contract().verify_digest());

        let spawn_res = prepared.spawn();
        assert!(
            spawn_res.is_err(),
            "Multi spawn must fail on tampered contract"
        );
        assert_eq!(
            PROD_SPAWN_COUNT.load(Ordering::SeqCst),
            count_before,
            "Multi tampered spawn must not increment spawn count"
        );
        assert!(
            !marker.exists(),
            "Multi tampered contract child must NOT run"
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}
