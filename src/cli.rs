use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

const EXAMPLES: &str = "\
Examples:
  vetto -- codex exec \"refactor auth module\"
  vetto -- claude -p \"fix the bug\"
  vetto --profile strict -- python agent.py
  vetto --net=allowlist:registry.npmjs.org -- npm install
  vetto --net=strict:github.com:22 --git-ssh -- git fetch origin
  vetto --tui=full --observe-seccomp --report html,md,sarif -- make test
  vetto --agent codex -- codex exec \"refactor auth module\"
  vetto --multi --agent lint=/usr/bin/cargo --agent test=/usr/bin/cargo
  vetto multi --manifest vetto-agents.toml
  vetto multi --agent lint=/usr/bin/cargo --agent test=/usr/bin/cargo
  vetto doctor
  vetto doctor --probe
  vetto report compare session-a.json session-b.json
  vetto completions bash";

/// vetto - daemon-less sandbox + security layer for AI coding agents.
#[derive(Parser, Debug)]
#[command(name = "vetto", version, about, after_help = EXAMPLES)]
pub struct Cli {
    /// Built-in policy profile
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub profile: String,

    /// Explicit policy TOML layer applied after the profile and project policy
    #[arg(long, value_name = "PATH")]
    pub policy: Option<String>,

    /// Network mode: off | allowlist:<domain,domain,...> |
    /// strict:<domain:port,domain:port,...>
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

    /// Post-session report formats, comma separated: html,md,json,sarif
    #[arg(long, value_name = "FMTS")]
    pub report: Option<String>,

    /// Directory in which reports are stored (defaults to $PROJECT/.vetto/reports).
    #[arg(long, value_name = "PATH")]
    pub report_dir: Option<String>,

    /// Compatibility spelling for report retention cleanup.
    #[arg(long, alias = "report-cleanup")]
    pub report_auto_cleanup: bool,

    /// Keep reports without automatic retention cleanup.
    #[arg(
        long = "no-report-auto-cleanup",
        conflicts_with = "report_auto_cleanup"
    )]
    pub no_report_auto_cleanup: bool,

    /// Compatibility spelling for report cleanup (kept hidden from help).
    #[arg(long = "auto-cleanup", hide = true)]
    pub auto_cleanup: bool,

    /// Maximum number of reports to retain (default: 50).
    #[arg(long, value_name = "COUNT")]
    pub report_retention: Option<usize>,

    /// Remove reports older than this many seconds when cleanup is enabled.
    #[arg(long, value_name = "SECONDS")]
    pub report_max_age_secs: Option<u64>,

    /// Exit non-zero when at least THRESHOLD blocked attempts are observed.
    /// With no value, THRESHOLD defaults to 1.
    #[arg(
        long,
        value_name = "THRESHOLD",
        num_args = 0..=1,
        default_missing_value = "1"
    )]
    pub fail_on_block: Option<u64>,

    /// Route git/SSH connections through vetto's in-process relay helper.
    #[arg(long)]
    pub git_ssh: bool,

    /// Print resolved policy + tier plan and exit (nothing enforced)
    #[arg(long)]
    pub dry_run: bool,

    /// Non-interactive mode for CI: implies --tui=none and a JSON summary on stdout
    #[arg(long)]
    pub ci: bool,

    /// Verbose diagnostics on stderr
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Select an agent preset, or provide NAME=PROGRAM entries with --multi.
    #[arg(long = "agent", value_name = "NAME", action = clap::ArgAction::Append)]
    pub agents: Vec<String>,

    /// Run the compatibility multi-agent frontend without a `multi` subcommand.
    #[arg(long)]
    pub multi: bool,

    /// Multi-agent TOML manifest for the compatibility frontend.
    #[arg(long = "manifest", value_name = "PATH")]
    pub multi_manifest: Option<PathBuf>,

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
        /// Probe a known agent executable with a bounded --version command.
        #[arg(long = "check-agent", value_name = "NAME")]
        check_agent: Option<String>,
    },
    /// Write a starter vetto.toml policy into the current directory
    Init,
    /// List built-in policy profiles
    Profiles,
    /// Run named agents concurrently, each in an independent sandbox.
    Multi {
        /// TOML manifest containing one or more [[agents]] argv definitions.
        #[arg(long, value_name = "PATH", conflicts_with = "agents")]
        manifest: Option<PathBuf>,
        /// Explicit repeated executable form: NAME=PROGRAM. Arguments and
        /// per-agent policies belong in the manifest; no shell is involved.
        #[arg(long = "agent", value_name = "NAME=PROGRAM", action = clap::ArgAction::Append)]
        agents: Vec<String>,
        /// Compatibility form for exactly one argv command. A literal `--`
        /// inside this vector is rejected as ambiguous by the manifest parser.
        #[arg(last = true, value_name = "COMMAND [ARGS...]")]
        command: Vec<String>,
    },
    /// Compare two JSON session reports.
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Print shell completion script for the requested shell.
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Internal SSH ProxyCommand helper; not intended for direct use.
    #[command(name = "ssh-proxy", visible_alias = "__ssh-proxy", hide = true)]
    SshProxy {
        /// Host token supplied by OpenSSH (%h).
        host: String,
        /// Port token supplied by OpenSSH (%p).
        port: u16,
    },
}

#[derive(Subcommand, Debug)]
pub enum ReportCommand {
    /// Print a machine-readable delta for two session JSON reports.
    Compare {
        #[arg(value_name = "SESSION1")]
        session1: PathBuf,
        #[arg(value_name = "SESSION2")]
        session2: PathBuf,
    },
}

/// Render completions to stdout without starting a sandbox session.
pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    let mut command = Cli::command();
    clap_complete::generate(shell, &mut command, "vetto", &mut std::io::stdout());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_generators_cover_supported_shells() {
        for shell in [
            Shell::Bash,
            Shell::Zsh,
            Shell::Fish,
            Shell::PowerShell,
            Shell::Elvish,
        ] {
            let mut command = Cli::command();
            let mut output = Vec::new();
            clap_complete::generate(shell, &mut command, "vetto", &mut output);
            assert!(!output.is_empty(), "empty completion for {shell:?}");
        }
    }

    #[test]
    fn top_level_multi_keeps_named_agents_separate_from_literal_command() {
        let cli = Cli::try_parse_from([
            "vetto",
            "--multi",
            "--agent",
            "lint=/bin/true",
            "--",
            "/bin/true",
            "--version",
        ])
        .expect("top-level multi syntax");
        assert!(cli.multi);
        assert_eq!(cli.agents, vec!["lint=/bin/true"]);
        assert_eq!(cli.agent, vec!["/bin/true", "--version"]);
    }

    #[test]
    fn doctor_check_agent_is_an_explicit_subcommand_option() {
        let cli = Cli::try_parse_from(["vetto", "doctor", "--check-agent", "codex"])
            .expect("doctor agent check");
        assert!(matches!(
            cli.command,
            Some(Command::Doctor {
                check_agent: Some(ref agent),
                ..
            }) if agent == "codex"
        ));
    }
}
