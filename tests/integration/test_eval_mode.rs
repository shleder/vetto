//! Integration tests for `vetto eval` subcommand.

use std::path::PathBuf;
use vetto::cli::eval::{build_eval_argv, configure_eval_run, EvalArgs, EvalJsonResult};
use vetto::cli::Cli;

#[test]
fn test_eval_argv_python_inline() {
    let args = EvalArgs {
        runtime: "python3".to_string(),
        code: Some("print('vetto sandbox')".to_string()),
        file: None,
        timeout: 10,
        memory_mb: 256,
        json: false,
        args: vec![],
    };

    let argv = build_eval_argv(&args).expect("build argv");
    assert_eq!(argv, vec!["python3", "-c", "print('vetto sandbox')"]);
}

#[test]
fn test_eval_argv_script_file() {
    let args = EvalArgs {
        runtime: "python3".to_string(),
        code: None,
        file: Some(PathBuf::from("/workspace/eval.py")),
        timeout: 10,
        memory_mb: 512,
        json: true,
        args: vec!["--param", "value"],
    };

    let argv = build_eval_argv(&args).expect("build argv");
    assert_eq!(argv, vec!["python3", "/workspace/eval.py", "--param", "value"]);
}

#[test]
fn test_eval_argv_node_eval() {
    let args = EvalArgs {
        runtime: "node".to_string(),
        code: Some("console.log(123)".to_string()),
        file: None,
        timeout: 5,
        memory_mb: 128,
        json: false,
        args: vec![],
    };

    let argv = build_eval_argv(&args).expect("build argv");
    assert_eq!(argv, vec!["node", "-e", "console.log(123)"]);
}

#[test]
fn test_eval_configure_run_config() {
    let cli = Cli::parse_from(&["vetto", "eval", "-c", "1+1"]);
    let eval_args = EvalArgs {
        runtime: "python3".to_string(),
        code: Some("1+1".to_string()),
        file: None,
        timeout: 7,
        memory_mb: 512,
        json: true,
        args: vec![],
    };

    let cfg = configure_eval_run(&eval_args, &cli).expect("configure eval run");
    assert_eq!(cfg.agent, vec!["python3", "-c", "1+1"]);
    assert_eq!(cfg.agent_preset, Some("smolagents".to_string()));
    assert_eq!(cfg.session_timeout, Some(std::time::Duration::from_secs(7)));
    assert_eq!(cfg.limits_spec, Some("memory=512mb".to_string()));
    assert!(cfg.ephemeral);
    assert!(cfg.ci);
    assert!(cfg.quiet);
    assert!(cfg.mask_secrets);
}

#[test]
fn test_eval_json_result_serialization() {
    let res = EvalJsonResult {
        status: "success".to_string(),
        exit_code: 0,
        stdout: "result: 42\n".to_string(),
        stderr: "".to_string(),
        duration_ms: 15,
        timed_out: false,
        memory_limit_mb: 256,
    };

    let json = serde_json::to_string(&res).expect("serialize");
    assert!(json.contains("\"status\":\"success\""));
    assert!(json.contains("\"exit_code\":0"));
    assert!(json.contains("\"duration_ms\":15"));
}
