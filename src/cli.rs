use clap::{Parser, Subcommand};

const EXAMPLES: &str = "\
Examples:
  vetto -- codex exec \"refactor auth module\"
  vetto -- claude -p \"fix the bug\"
  vetto --profile strict -- python agent.py
  vetto --net=allowlist:registry.npmjs.org -- npm install
  vetto --tui=full --observe-seccomp --report html,md -- make test
  vetto doctor
  vetto doctor --probe";

/// vetto - daemon-less sandbox + security layer for AI coding agents.
#[derive(Parser, Debug)]
#[command(name = "vetto", version, about, after_help = EXAMPLES)]
pub struct Cli {
    /// Built-in policy profile
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub profile: String,

    /// Custom policy TOML file (overrides --profile)
    #[arg(long, value_name = "PATH")]
    pub policy: Option<String>,

    /// Network mode: off | allowlist:<domain,domain,...>
    #[arg(long, value_name = "MODE", default_value = "off")]
    pub net: String,

    /// UI mode: statusline | full | none
    #[arg(long, value_name = "MODE", default_value = "statusline")]
    pub tui: String,

    /// Attach a best-effort blocked-attempt observation tap (Linux).
    /// Observation ONLY — Landlock remains the sole enforcer.
    #[arg(long)]
    pub observe_seccomp: bool,

    /// Append every session event as JSON lines to PATH
    #[arg(long, value_name = "PATH")]
    pub jsonl: Option<String>,

    /// Post-session report formats, comma separated: html,md,json
    #[arg(long, value_name = "FMTS")]
    pub report: Option<String>,

    /// Print resolved policy + tier plan and exit (nothing enforced)
    #[arg(long)]
    pub dry_run: bool,

    /// Non-interactive mode for CI: implies --tui=none and a JSON summary on stdout
    #[arg(long)]
    pub ci: bool,

    /// Verbose diagnostics on stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Agent command to supervise; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub agent: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Diagnose platform support: tiers, landlock ABI, userns, seccomp, audit feed
    Doctor {
        /// Additionally verify that every display_only_deny path is truly
        /// unreachable from inside a throwaway sandbox.
        #[arg(long)]
        probe: bool,
    },
    /// Write a starter vetto.toml policy into the current directory
    Init,
    /// List built-in policy profiles
    Profiles,
}
