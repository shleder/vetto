//! `vetto eval`: Safely evaluate a code snippet or script in a disposable, kernel-isolated sandbox.
//!
//! Provides sub-millisecond, unprivileged execution for AI tool-calling agents (e.g. smolagents,
//! open-interpreter, langchain) with:
//! - Hard wall-clock timeout enforced via monotonic watchdog and SIGKILL
//! - Cgroups v2 memory ceiling (prevents memory explosion from taking down parent agent)
//! - Secret masking for ~/.ssh, ~/.aws, .env via ephemeral tmpfs
//! - Structured JSON output option for automated tool-calling pipelines

use std::io::{self, Read};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde::Serialize;

use crate::cli::Cli;
use crate::config::{NetMode, RunConfig, TuiMode};

/// Arguments for `vetto eval`.
#[derive(clap::Args, Debug, Clone)]
pub struct EvalArgs {
    /// Language runtime (e.g. python3, python, node, bash, sh, ruby). Default: python3
    #[arg(short = 'r', long = "runtime", default_value = "python3")]
    pub runtime: String,

    /// Code snippet string to evaluate
    #[arg(short = 'c', long = "code")]
    pub code: Option<String>,

    /// Path to script file to evaluate
    #[arg(value_name = "SCRIPT_FILE")]
    pub file: Option<PathBuf>,

    /// Hard wall-clock timeout in seconds (default: 10s)
    #[arg(short = 't', long = "timeout", default_value = "10")]
    pub timeout: u64,

    /// Memory limit ceiling in megabytes (cgroups v2 memory.max, default: 256MB)
    #[arg(short = 'm', long = "memory", default_value = "256")]
    pub memory_mb: u64,

    /// Output structured JSON with stdout, stderr, exit_code, and execution duration
    #[arg(long)]
    pub json: bool,

    /// Arguments passed directly to the runtime
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub args: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct EvalJsonResult {
    pub status: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u128,
    pub timed_out: bool,
    pub memory_limit_mb: u64,
}

pub fn build_eval_argv(args: &EvalArgs) -> Result<Vec<String>> {
    let mut argv = vec![args.runtime.clone()];

    if let Some(ref file) = args.file {
        argv.push(file.display().to_string());
        argv.extend(args.args.iter().cloned());
        return Ok(argv);
    }

    let code = if let Some(ref c) = args.code {
        c.clone()
    } else {
        // Read code snippet from stdin if piped
        let mut stdin_buf = String::new();
        io::stdin()
            .read_to_string(&mut stdin_buf)
            .context("failed to read code snippet from stdin")?;
        if stdin_buf.trim().is_empty() {
            bail!("no code snippet provided; pass `-c \"<code>\"`, a script file, or pipe via stdin");
        }
        stdin_buf
    };

    let rt = args.runtime.to_ascii_lowercase();
    if rt.contains("node") || rt.contains("ruby") || rt.contains("perl") {
        argv.push("-e".into());
    } else {
        argv.push("-c".into());
    }
    argv.push(code);
    argv.extend(args.args.iter().cloned());
    Ok(argv)
}

pub fn configure_eval_run(eval_args: &EvalArgs, cli: &Cli) -> Result<RunConfig> {
    let mut cfg = RunConfig::from_cli(cli)?;
    let argv = build_eval_argv(eval_args)?;

    cfg.agent = argv;
    cfg.agent_preset = Some("smolagents".into());
    cfg.session_timeout = Some(Duration::from_secs(eval_args.timeout));
    cfg.limits_spec = Some(format!("memory={}mb", eval_args.memory_mb));
    cfg.tui = TuiMode::None;
    cfg.ci = true;
    cfg.ephemeral = true;
    if cli.net.is_none() {
        cfg.net = NetMode::Off;
    }
    cfg.quiet = eval_args.json;
    cfg.mask_secrets = true;

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_eval_argv_python_code() {
        let args = EvalArgs {
            runtime: "python3".into(),
            code: Some("print(1 + 1)".into()),
            file: None,
            timeout: 5,
            memory_mb: 128,
            json: false,
            args: vec![],
        };
        let argv = build_eval_argv(&args).unwrap();
        assert_eq!(argv, vec!["python3", "-c", "print(1 + 1)"]);
    }

    #[test]
    fn test_build_eval_argv_node_code() {
        let args = EvalArgs {
            runtime: "node".into(),
            code: Some("console.log(42)".into()),
            file: None,
            timeout: 5,
            memory_mb: 128,
            json: false,
            args: vec!["--trace-warnings".into()],
        };
        let argv = build_eval_argv(&args).unwrap();
        assert_eq!(argv, vec!["node", "-e", "console.log(42)", "--trace-warnings"]);
    }

    #[test]
    fn test_build_eval_argv_file() {
        let args = EvalArgs {
            runtime: "python3".into(),
            code: None,
            file: Some(PathBuf::from("/tmp/script.py")),
            timeout: 5,
            memory_mb: 128,
            json: false,
            args: vec!["arg1".into()],
        };
        let argv = build_eval_argv(&args).unwrap();
        assert_eq!(argv, vec!["python3", "/tmp/script.py", "arg1"]);
    }
}
