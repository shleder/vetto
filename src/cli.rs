pub mod enable;
pub mod git_hook;
pub mod hook;
pub mod plugin;
pub mod shell_env;
pub mod status;
pub mod why_slow;

pub use enable::{DisableArgs, EnableArgs};
pub use hook::{HookCommand, HookScope, ShellType};

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

const HELP_ABOUT: &str = "\
1. vetto enable <agent>
2. Run your agent as usual — it runs in the sandbox under the hood.

Daemon-less sandbox + security layer for AI coding agents.";

const EXAMPLES: &str = "\
Examples:
  vetto enable claude
  vetto enable codex
  claude
  vetto doctor
  vetto tour
  vetto status
  vetto allow ./target
  vetto deny ~/.aws/credentials
  vetto -- python agent.py";

/// vetto - daemon-less sandbox + security layer for AI coding agents.
#[derive(Parser, Debug)]
#[command(
    name = "vetto",
    version,
    about = HELP_ABOUT,
    after_help = EXAMPLES
)]
pub struct Cli {
    /// Built-in policy profile
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub profile: String,

    /// Base security preset: paranoid | balanced | yolo
    #[arg(long, value_name = "PRESET")]
    pub preset: Option<String>,

    /// Explicit policy TOML layer applied after the profile and project policy
    #[arg(long, value_name = "PATH")]
    pub policy: Option<String>,

    /// Network mode: off | allowlist:<domain,domain,...> |
    /// strict:<domain:port,domain:port,...>
    #[arg(long, value_name = "MODE")]
    pub net: Option<String>,

    /// UI mode: statusline | full | none
    #[arg(long, value_name = "MODE", default_value = "statusline")]
    pub tui: String,

    /// Explicit sandbox backend: auto | process | win-sandbox
    #[arg(long, value_name = "BACKEND")]
    pub backend: Option<String>,

    /// Emit events to macOS unified log (os_log / logger)
    #[arg(long)]
    pub oslog: bool,

    /// Run Windows AppContainer in Less Privileged AppContainer (LPAC) mode
    #[arg(long)]
    pub lpac: bool,

    /// Attach a best-effort blocked-attempt observation tap (Linux).
    /// Observation ONLY — Landlock remains the sole enforcer.
    #[arg(long)]
    pub observe_seccomp: bool,

    /// Shadow mode: policy layer logs "would deny" instead of blocking in verification/preflight.
    /// Note: Kernel sandbox (Landlock/seccomp) cannot be shadowed; shadow mode applies to policy-layer verification.
    #[arg(long)]
    pub shadow: bool,

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

    /// Desktop notifications on security violations (blocked path access, network escape).
    #[arg(long)]
    pub notify: bool,

    /// OpenTelemetry OTLP endpoint for session span export.
    #[arg(long, value_name = "URL")]
    pub otel_endpoint: Option<String>,

    /// Kill the sandboxed session after DURATION without the agent finishing
    /// (e.g. 90s, 30m, 2h). Enforced with --tui=none (CI mode); other TUI
    /// modes warn and ignore it.
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,

    /// Resource ceilings for the agent process, comma separated:
    /// cpu=SECONDS, as=BYTES, procs=N, nofile=N, fsize=BYTES. Merged
    /// strictest-wins with any limits from the policy layers.
    #[arg(long, value_name = "SPEC")]
    pub limits: Option<String>,

    /// Run the boundary verification battery against the resolved policy
    /// before spawning the agent. Any leak aborts the session (fail-closed).
    #[arg(long)]
    pub verify: bool,

    /// Print resolved policy + tier plan and exit (nothing enforced)
    #[arg(long)]
    pub dry_run: bool,

    /// Non-interactive mode for CI: implies --tui=none and a JSON summary on stdout
    #[arg(long)]
    pub ci: bool,

    /// Suppress diagnostic and non-essential progress messages on stderr
    #[arg(short = 'q', long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Verbose diagnostics on stderr
    #[arg(short = 'v', long, global = true)]
    pub verbose: bool,

    /// Forward session events to system journal (journald, EventLog, syslog)
    #[arg(long)]
    pub system_log: bool,

    /// Select an agent preset, or provide NAME=PROGRAM entries with --multi.
    #[arg(long = "agent", value_name = "NAME", action = clap::ArgAction::Append)]
    pub agents: Vec<String>,

    /// Run the compatibility multi-agent frontend without a `multi` subcommand.
    #[arg(long)]
    pub multi: bool,

    /// Multi-agent TOML manifest for the compatibility frontend.
    #[arg(long = "manifest", value_name = "PATH")]
    pub multi_manifest: Option<PathBuf>,

    /// Additional glob patterns to resolve and deny (e.g. "**/*.pem").
    #[arg(long = "deny-glob", value_name = "PATTERN", action = clap::ArgAction::Append)]
    pub deny_glob: Vec<String>,

    /// Enforce Git branch protection (refuse write on main/master) and block destructive git pushes.
    #[arg(long = "git-guard")]
    pub git_guard: bool,

    /// Take a project snapshot before session starts and enable rollback.
    #[arg(long = "snapshot")]
    pub snapshot: bool,

    /// Automatically scan project for secrets at session start and deny them.
    #[arg(long = "auto-deny-secrets")]
    pub auto_deny_secrets: bool,

    /// Target remote daemon API endpoint URL (e.g. http://127.0.0.1:54321)
    #[arg(long, value_name = "URL")]
    pub remote: Option<String>,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Agent command to supervise; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub agent: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Enable transparent sandbox wrapper for an AI coding agent (e.g. `vetto enable claude`)
    Enable(EnableArgs),

    /// Disable transparent sandbox wrapper for an AI coding agent (e.g. `vetto disable claude`)
    Disable(DisableArgs),

    /// Grant the agent access to a path or network domain (writes policy)
    Allow {
        /// Filesystem path, or network domain with --net
        #[arg(value_name = "PATH|DOMAIN")]
        target: String,
        /// Filesystem only: read-only grant (default is read + write)
        #[arg(long)]
        read_only: bool,
        /// Treat TARGET as a network domain instead of a path
        #[arg(long)]
        net: bool,
        /// Edit ~/.vetto/config.toml instead of the project policy
        #[arg(long)]
        global: bool,
    },
    /// Explicitly deny reads of a path (secret masking) in the policy
    Deny {
        /// Filesystem path to mask, e.g. ~/.aws/credentials
        #[arg(value_name = "PATH")]
        target: String,
        /// Edit ~/.vetto/config.toml instead of the project policy
        #[arg(long)]
        global: bool,
    },
    /// Diagnose platform support: tiers, landlock ABI, userns, seccomp, audit feed
    Doctor {
        /// Additionally verify that every display_only_deny path is truly
        /// unreachable from inside a throwaway sandbox.
        #[arg(long)]
        probe: bool,
        /// Probe a known agent executable with a bounded --version command.
        #[arg(long = "check-agent", value_name = "NAME")]
        check_agent: Option<String>,
        /// Show concrete remediation commands and steps for missing sandbox primitives.
        #[arg(long)]
        fix: bool,
    },
    /// Interactive 5-step onboarding walkthrough
    Tour {
        /// Run all tour steps non-interactively without waiting for keypresses
        #[arg(long)]
        non_interactive: bool,
    },
    /// List active sandboxed sessions and cleanup stale metadata.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify the sandbox boundary WITHOUT running any agent: secret paths,
    /// network reachability, and write-outside checks execute inside a
    /// throwaway sandbox built from the resolved policy.
    Verify {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Run an agent command under the Vetto sandbox supervisor
    #[command(hide = true)]
    Run {
        /// Target agent binary or command
        #[arg(value_name = "COMMAND")]
        command: Option<String>,

        /// Arguments passed to the agent
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Analyze project ecosystem and generate a tailored policy.toml policy
    #[command(hide = true)]
    Init {
        /// Overwrite existing policy if present
        #[arg(long, short = 'f')]
        force: bool,
        /// Interactive first-run setup wizard
        #[arg(long)]
        wizard: bool,
    },
    /// List built-in policy profiles
    #[command(hide = true)]
    Profiles,
    /// Manage transparent developer shims, shell hooks, and Git hook wrappers
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Manage agent integration plugins (Claude Code, OpenCode)
    #[command(hide = true)]
    Plugin {
        #[command(subcommand)]
        command: plugin::PluginCommand,
    },
    /// Run as a Model Context Protocol (MCP) JSON-RPC stdio server
    #[command(hide = true)]
    Mcp,
    /// Manage background session multiplexer daemon and session registry
    #[command(hide = true)]
    Daemon {
        #[command(subcommand)]
        command: crate::daemon::DaemonCommand,
    },
    /// Run multiplexer daemon in foreground with SSH remote instructions
    #[command(hide = true)]
    Serve {
        /// Loopback HTTP port for REST API (default: 54321)
        #[arg(long, default_value_t = crate::daemon::DEFAULT_HTTP_PORT)]
        port: u16,
    },
    /// Fast native shim dispatcher for intercepted toolchain binaries
    #[command(hide = true)]
    Shim {
        /// Target binary name (if not inferred from argv[0])
        #[arg(value_name = "BINARY")]
        binary: Option<String>,

        /// Arguments passed to the target binary
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Run named agents concurrently, each in an independent sandbox.
    #[command(hide = true)]
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
    /// Inspect and copy persisted agent sessions without modifying originals.
    #[command(hide = true)]
    Rescue {
        /// Recovery adapter: codex, claude or cursor.
        #[arg(long, default_value = "codex", value_name = "ID")]
        adapter: String,
        /// Explicit agent state root. When omitted each adapter resolves its
        /// own default: CODEX_HOME or $HOME/.codex, CLAUDE_HOME or
        /// $HOME/.claude, and the platform Cursor user directory.
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
        /// Emit sanitized machine-readable JSON.
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        command: RescueCommand,
    },
    /// Compare two JSON session reports.
    #[command(hide = true)]
    Report {
        #[command(subcommand)]
        command: ReportCommand,
    },
    /// Run red-team sandbox containment and kernel isolation attack battery.
    #[command(hide = true)]
    Redteam {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain the effective policy or lint it for dangerous configurations.
    #[command(hide = true)]
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Print shell completion script for the requested shell.
    #[command(hide = true)]
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Generate man page to stdout.
    #[command(hide = true)]
    Man,
    /// Print environment variable export lines for shell integration and PS1.
    #[command(name = "shell-env", hide = true)]
    ShellEnv {
        /// Session ID to export.
        #[arg(long)]
        session_id: Option<String>,
        /// Sandbox tier to export.
        #[arg(long)]
        tier: Option<String>,
        /// Profile name to export.
        #[arg(long)]
        profile: Option<String>,
    },
    /// Manage persistent workspace profiles (cwd, agent, policy).
    #[command(hide = true)]
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Diagnostic latency breakdown and optimization hints for a session.
    #[command(name = "why-slow", hide = true)]
    WhySlow {
        /// Session identifier or report path.
        session: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Self-upgrade vetto via npm, cargo, homebrew, or direct binary
    #[command(hide = true)]
    Upgrade {
        /// Channel to upgrade from (stable or alpha)
        #[arg(long, value_name = "CHANNEL")]
        channel: Option<String>,
        /// Check for updates without applying
        #[arg(long)]
        check: bool,
        /// Simulate upgrade command without running
        #[arg(long)]
        dry_run: bool,
    },
    /// Scan project directory for exposed secrets and credentials
    #[command(hide = true)]
    ScanSecrets {
        /// Target directory or file to scan (defaults to current directory)
        #[arg(value_name = "PATH")]
        path: Option<PathBuf>,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
        /// Maximum file size to scan in bytes (default: 1MB)
        #[arg(long, value_name = "BYTES")]
        max_size: Option<u64>,
        /// Maximum number of files to scan (default: 5000)
        #[arg(long, value_name = "COUNT")]
        max_files: Option<usize>,
    },
    /// Live-tail session events from JSONL log with optional path filtering
    #[command(hide = true)]
    Watch {
        /// Session PID or path to JSONL log file
        #[arg(value_name = "SESSION_OR_LOG")]
        target: String,
        /// Optional path filter
        #[arg(long, value_name = "PATTERN")]
        path: Option<String>,
        /// Emit raw JSON lines instead of formatted output
        #[arg(long)]
        json: bool,
    },
    /// Restore project files from a previously created session snapshot
    #[command(hide = true)]
    Rollback {
        /// Session ID or path to snapshot archive
        #[arg(value_name = "SESSION")]
        session: String,
        /// Optional restore target directory override
        #[arg(long, value_name = "TARGET")]
        target: Option<PathBuf>,
    },
    /// Tail and filter JSONL session event logs.
    #[command(hide = true)]
    Events {
        /// Path to session JSONL log file or session identifier
        #[arg(value_name = "SESSION")]
        session: PathBuf,
        /// Filter events by category (deny, net, files, exec, notice) or substring
        #[arg(long, value_name = "FILTER")]
        filter: Option<String>,
        /// Continuously follow the log for new events (streaming tail)
        #[arg(short = 'f', long)]
        follow: bool,
        /// Emit machine-readable JSON lines
        #[arg(long)]
        json: bool,
        /// Format output as a column table
        #[arg(long)]
        table: bool,
    },
    /// Inspect recorded session events, filesystem denials, blocked egress, and filtered syscalls.
    #[command(hide = true)]
    Audit {
        /// Session ID, report/log path to inspect, or omit to list sessions
        #[arg(value_name = "SESSION_ID")]
        session_id: Option<String>,
        /// Inspect the most recent session
        #[arg(long)]
        latest: bool,
        /// Filter sessions since duration (e.g. 24h, 7d, 30m, YYYY-MM-DD)
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
        /// Filter by agent preset or name
        #[arg(long, value_name = "NAME")]
        agent: Option<String>,
        /// Limit the maximum number of history entries displayed
        #[arg(long, value_name = "COUNT")]
        limit: Option<usize>,
        /// Optional substring search in policy path, profile, agent, command, or session ID
        #[arg(long, value_name = "QUERY")]
        query: Option<String>,
        /// Emit machine-readable JSON output
        #[arg(long)]
        json: bool,
    },
    /// Generate an aggregated daily audit digest from session history.
    #[command(hide = true)]
    Digest {
        /// Window duration to aggregate (e.g. 24h, 7d, 30m; default 24h)
        #[arg(long, value_name = "DURATION", default_value = "24h")]
        since: String,
        /// Emit machine-readable JSON summary
        #[arg(long)]
        json: bool,
    },
    /// Compare two session JSON audit reports (metric deltas and violation diffs).
    #[command(name = "diff-sessions", hide = true)]
    DiffSessions {
        /// Base session JSON report or identifier
        #[arg(value_name = "SESSION1")]
        session1: PathBuf,
        /// Target session JSON report or identifier
        #[arg(value_name = "SESSION2")]
        session2: PathBuf,
        /// Emit machine-readable JSON diff
        #[arg(long)]
        json: bool,
    },
    /// Chronologically replay sandbox observation and security events from a session log.
    #[command(hide = true)]
    Replay {
        /// Path to session JSONL log file or session identifier
        #[arg(value_name = "SESSION")]
        session: PathBuf,
        /// Playback speed multiplier (e.g. 1.0 for real-time, 2.0 for 2x; default instant)
        #[arg(long, value_name = "FACTOR")]
        speed: Option<f64>,
        /// Emit machine-readable JSON lines
        #[arg(long)]
        json: bool,
    },
    /// Internal SSH ProxyCommand helper; not intended for direct use.
    #[command(name = "ssh-proxy", visible_alias = "__ssh-proxy", hide = true)]
    SshProxy {
        /// Host token supplied by OpenSSH (%h).
        host: String,
        /// Port token supplied by OpenSSH (%p).
        port: u16,
    },
    /// Stored workspace profile invocation by name.
    #[command(external_subcommand)]
    External(Vec<String>),
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommand {
    /// Print the effective policy after all layers merge: tier, network,
    /// roots, masked secrets, limits, environment.
    Explain {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Explain why a specific path is allowed, denied, or writable.
        #[arg(long = "why", value_name = "PATH")]
        why: Option<PathBuf>,
    },
    /// Show the resolved effective policy.
    Show {
        /// Print effective resolved policy.
        #[arg(long)]
        effective: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Check the resolved policy for dangerous configurations. Exits
    /// non-zero with --strict when any finding is reported.
    Lint {
        /// Exit non-zero when any finding is reported.
        #[arg(long)]
        strict: bool,
    },
    /// Import permissions from external agent configurations (e.g. claude, codex)
    Import {
        /// Source agent configuration format: claude | codex
        #[arg(long, value_name = "AGENT")]
        from: String,
        /// Path to source configuration file (defaults to ~/.claude/settings.json or ~/.codex/config.toml)
        #[arg(long, value_name = "PATH")]
        path: Option<PathBuf>,
        /// Output path for generated policy (default: ./policy.toml)
        #[arg(long, short = 'o', value_name = "PATH", default_value = "policy.toml")]
        output: PathBuf,
    },
    /// Cryptographically sign a policy file using Ed25519
    Sign {
        /// Policy file to sign
        file: PathBuf,
        /// Custom private signing key path (default: ~/.vetto/signing.key)
        #[arg(long)]
        key: Option<PathBuf>,
        /// Custom signature output path (default: <file>.sig)
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify the cryptographic Ed25519 signature of a policy file
    Verify {
        /// Policy file to verify
        file: PathBuf,
        /// Signature file path (default: <file>.sig)
        #[arg(long)]
        sig: Option<PathBuf>,
        /// Public key file path (default: ~/.vetto/signing.pub)
        #[arg(long)]
        key: Option<PathBuf>,
    },
    /// Adopt a community policy into the current project
    Use {
        /// Community policy name (e.g. python-dev, node-dev, rust-dev)
        name: String,
        /// Overwrite existing vetto.toml
        #[arg(short, long)]
        force: bool,
    },
    /// List available community policies
    List,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommand {
    /// Save current working directory and settings as a named workspace profile.
    Save {
        /// Name of the profile.
        name: String,
        /// Agent command or preset.
        #[arg(long)]
        agent: Option<String>,
        /// Explicit policy path.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Network mode.
        #[arg(long)]
        net: Option<String>,
        /// Built-in profile layer name.
        #[arg(long)]
        profile: Option<String>,
    },
    /// List all saved workspace profiles.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove a saved workspace profile.
    Rm {
        /// Name of the profile to remove.
        name: String,
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

#[derive(Subcommand, Debug)]
pub enum RescueCommand {
    /// Discover sessions. Codex defaults to verified index-first (limit 50);
    /// other adapters use their bounded filesystem discovery.
    Scan {
        /// For Codex, use a verified provider index and return at most COUNT
        /// sessions. This never falls back to a filesystem walk.
        #[arg(long, value_name = "COUNT", conflicts_with = "all")]
        limit: Option<usize>,
        /// Explicitly use the bounded recursive filesystem walk. For Codex,
        /// this opts out of the default index-first scan.
        #[arg(long, conflicts_with = "limit")]
        all: bool,
    },
    /// Diagnose one exact session key without changing agent state.
    Diagnose {
        #[arg(value_name = "SESSION")]
        session: String,
    },
    /// Create a verified, exclusive new copy outside the agent state root.
    Snapshot {
        #[arg(value_name = "SESSION")]
        session: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Create a recovery fork as a verified new copy outside agent state.
    Fork {
        #[arg(value_name = "SESSION")]
        session: String,
        #[arg(long, value_name = "PATH")]
        output: PathBuf,
    },
    /// Perform transactional state repair on a session with backup receipt.
    Repair {
        #[arg(value_name = "SESSION")]
        session: String,
        /// Directory in which pre-repair backups are stored (defaults to ~/.vetto/rescue_backups).
        #[arg(long, value_name = "PATH")]
        backup_dir: Option<PathBuf>,
    },
    /// Rollback a previous state repair using a repair receipt.
    Rollback {
        /// Path to the repair receipt JSON file.
        #[arg(long, value_name = "RECEIPT_PATH")]
        receipt: PathBuf,
        /// Explicit target path override (if target was moved or renamed).
        #[arg(long, value_name = "TARGET_PATH")]
        target: Option<PathBuf>,
    },
}

/// Render completions to stdout without starting a sandbox session.
pub fn print_completions(shell: Shell) -> anyhow::Result<()> {
    let mut command = Cli::command();
    clap_complete::generate(shell, &mut command, "vetto", &mut std::io::stdout());
    Ok(())
}

/// Render man page to stdout without starting a sandbox session.
pub fn print_man() -> anyhow::Result<()> {
    let command = Cli::command();
    let man = clap_mangen::Man::new(command);
    man.render(&mut std::io::stdout())?;
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
    fn hook_subcommand_parses_install_and_status() {
        let install_cli =
            Cli::try_parse_from(["vetto", "hook", "install", "--scope", "local", "--git"])
                .expect("hook install parsing");
        assert!(matches!(
            install_cli.command,
            Some(Command::Hook {
                command: HookCommand::Install {
                    scope: HookScope::Local,
                    git: true,
                    ..
                }
            })
        ));

        let status_cli = Cli::try_parse_from(["vetto", "hook", "status", "--json"])
            .expect("hook status parsing");
        assert!(matches!(
            status_cli.command,
            Some(Command::Hook {
                command: HookCommand::Status {
                    scope: HookScope::Global,
                    json: true,
                }
            })
        ));
    }

    #[test]
    fn shim_subcommand_parses_binary_and_args() {
        let cli =
            Cli::try_parse_from(["vetto", "shim", "node", "--", "index.js", "--port", "3000"])
                .expect("shim parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Shim {
                ref binary,
                ref args,
            }) if binary.as_deref() == Some("node") && args == &vec!["index.js", "--port", "3000"]
        ));
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

    #[test]
    fn rescue_parser_keeps_adapter_options_outside_the_session_selector() {
        let cli = Cli::try_parse_from([
            "vetto",
            "rescue",
            "--adapter",
            "codex",
            "--root",
            "/tmp/codex-home",
            "--json",
            "diagnose",
            "sessions/example.jsonl",
        ])
        .expect("rescue syntax");
        assert!(matches!(
            cli.command,
            Some(Command::Rescue {
                ref adapter,
                json: true,
                command: RescueCommand::Diagnose { ref session },
                ..
            }) if adapter == "codex" && session == "sessions/example.jsonl"
        ));
    }

    #[test]
    fn rescue_scan_exposes_explicit_index_limit_and_full_walk_modes() {
        let default =
            Cli::try_parse_from(["vetto", "rescue", "scan"]).expect("default rescue scan syntax");
        assert!(matches!(
            default.command,
            Some(Command::Rescue {
                command: RescueCommand::Scan {
                    limit: None,
                    all: false,
                },
                ..
            })
        ));

        let limited = Cli::try_parse_from(["vetto", "rescue", "scan", "--limit", "25"])
            .expect("limited rescue scan syntax");
        assert!(matches!(
            limited.command,
            Some(Command::Rescue {
                command: RescueCommand::Scan {
                    limit: Some(25),
                    all: false,
                },
                ..
            })
        ));

        let full = Cli::try_parse_from(["vetto", "rescue", "scan", "--all"])
            .expect("full rescue scan syntax");
        assert!(matches!(
            full.command,
            Some(Command::Rescue {
                command: RescueCommand::Scan {
                    limit: None,
                    all: true,
                },
                ..
            })
        ));
    }

    #[test]
    fn man_generator_renders_valid_troff_manpage() {
        let command = Cli::command();
        let man = clap_mangen::Man::new(command);
        let mut buffer = Vec::new();
        man.render(&mut buffer).expect("render man page");
        let rendered = String::from_utf8_lossy(&buffer);
        assert!(rendered.contains(".TH vetto"));
        assert!(rendered.contains("NAME"));
        assert!(rendered.contains("SYNOPSIS"));
    }

    #[test]
    fn parses_preset_and_shadow_flags() {
        let cli = Cli::try_parse_from(["vetto", "--preset", "paranoid", "--shadow", "--", "node"])
            .expect("preset and shadow flags");
        assert_eq!(cli.preset.as_deref(), Some("paranoid"));
        assert!(cli.shadow);
    }

    #[test]
    fn doctor_fix_subcommand_parses() {
        let cli = Cli::try_parse_from(["vetto", "doctor", "--fix"]).expect("doctor fix parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Doctor { fix: true, .. })
        ));
    }

    #[test]
    fn upgrade_subcommand_parses_channel_and_flags() {
        let cli = Cli::try_parse_from(["vetto", "upgrade", "--channel", "alpha", "--check"])
            .expect("upgrade parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Upgrade {
                channel: Some(ref ch),
                check: true,
                dry_run: false,
            }) if ch == "alpha"
        ));
    }

    #[test]
    fn init_wizard_subcommand_parses() {
        let cli = Cli::try_parse_from(["vetto", "init", "--wizard"]).expect("init wizard parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Init { wizard: true, .. })
        ));
    }

    #[test]
    fn policy_explain_why_parses() {
        let cli = Cli::try_parse_from(["vetto", "policy", "explain", "--why", "src/main.rs"])
            .expect("policy explain why parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Policy {
                command: PolicyCommand::Explain { why: Some(ref path), .. }
            }) if path == &PathBuf::from("src/main.rs")
        ));
    }

    #[test]
    fn policy_import_parses() {
        let cli = Cli::try_parse_from([
            "vetto",
            "policy",
            "import",
            "--from",
            "claude",
            "-o",
            "my-policy.toml",
        ])
        .expect("policy import parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Policy {
                command: PolicyCommand::Import { ref from, ref output, .. }
            }) if from == "claude" && output == &PathBuf::from("my-policy.toml")
        ));
    }

    #[test]
    fn tour_subcommand_parses_non_interactive_flag() {
        let cli =
            Cli::try_parse_from(["vetto", "tour", "--non-interactive"]).expect("tour parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Tour {
                non_interactive: true,
            })
        ));
    }

    #[test]
    fn parses_observability_subcommands() {
        let events_cli = Cli::try_parse_from([
            "vetto",
            "events",
            "session.jsonl",
            "--filter",
            "deny",
            "--follow",
        ])
        .expect("events parsing");
        assert!(matches!(
            events_cli.command,
            Some(Command::Events {
                ref session,
                ref filter,
                follow: true,
                ..
            }) if session == &PathBuf::from("session.jsonl") && filter.as_deref() == Some("deny")
        ));

        let audit_cli = Cli::try_parse_from([
            "vetto",
            "audit",
            "--since",
            "24h",
            "--agent",
            "codex",
            "--limit",
            "10",
            "--query",
            "search_term",
        ])
        .expect("audit parsing");
        assert!(matches!(
            audit_cli.command,
            Some(Command::Audit {
                ref since,
                ref agent,
                limit: Some(10),
                ref query,
                latest: false,
                ..
            }) if since.as_deref() == Some("24h") && agent.as_deref() == Some("codex") && query.as_deref() == Some("search_term")
        ));

        let audit_session = Cli::try_parse_from(["vetto", "audit", "session-12345", "--json"])
            .expect("audit session parsing");
        assert!(matches!(
            audit_session.command,
            Some(Command::Audit {
                ref session_id,
                json: true,
                ..
            }) if session_id.as_deref() == Some("session-12345")
        ));

        let audit_latest = Cli::try_parse_from(["vetto", "audit", "--latest", "--json"])
            .expect("audit latest parsing");
        assert!(matches!(
            audit_latest.command,
            Some(Command::Audit {
                latest: true,
                json: true,
                ..
            })
        ));

        let digest_cli = Cli::try_parse_from(["vetto", "digest", "--since", "7d", "--json"])
            .expect("digest parsing");
        assert!(matches!(
            digest_cli.command,
            Some(Command::Digest {
                ref since,
                json: true,
            }) if since == "7d"
        ));

        let diff_cli =
            Cli::try_parse_from(["vetto", "diff-sessions", "s1.json", "s2.json", "--json"])
                .expect("diff-sessions parsing");
        assert!(matches!(
            diff_cli.command,
            Some(Command::DiffSessions {
                ref session1,
                ref session2,
                json: true,
            }) if session1 == &PathBuf::from("s1.json") && session2 == &PathBuf::from("s2.json")
        ));

        let replay_cli =
            Cli::try_parse_from(["vetto", "replay", "session.jsonl", "--speed", "1.5"])
                .expect("replay parsing");
        assert!(matches!(
            replay_cli.command,
            Some(Command::Replay {
                ref session,
                speed: Some(1.5),
                ..
            }) if session == &PathBuf::from("session.jsonl")
        ));
    }

    #[test]
    fn tier7_subcommands_parse_correctly() {
        let mcp = Cli::try_parse_from(["vetto", "mcp"]).expect("mcp syntax");
        assert!(matches!(mcp.command, Some(Command::Mcp)));

        let plugin_install =
            Cli::try_parse_from(["vetto", "plugin", "install", "claude-code", "--force"])
                .expect("plugin install syntax");
        assert!(matches!(
            plugin_install.command,
            Some(Command::Plugin {
                command: plugin::PluginCommand::Install {
                    ref target,
                    force: true
                }
            }) if target == "claude-code"
        ));

        let daemon_start = Cli::try_parse_from([
            "vetto",
            "daemon",
            "start",
            "--port",
            "54321",
            "--foreground",
        ])
        .expect("daemon start syntax");
        assert!(matches!(
            daemon_start.command,
            Some(Command::Daemon {
                command: crate::daemon::DaemonCommand::Start {
                    port: 54321,
                    foreground: true,
                    ..
                }
            })
        ));

        let serve =
            Cli::try_parse_from(["vetto", "serve", "--port", "8080"]).expect("serve syntax");
        assert!(matches!(serve.command, Some(Command::Serve { port: 8080 })));

        let policy_sign = Cli::try_parse_from(["vetto", "policy", "sign", "vetto.toml"])
            .expect("policy sign syntax");
        assert!(matches!(
            policy_sign.command,
            Some(Command::Policy {
                command: PolicyCommand::Sign { ref file, .. }
            }) if file == &PathBuf::from("vetto.toml")
        ));

        let policy_use = Cli::try_parse_from(["vetto", "policy", "use", "python-dev"])
            .expect("policy use syntax");
        assert!(matches!(
            policy_use.command,
            Some(Command::Policy {
                command: PolicyCommand::Use { ref name, force: false }
            }) if name == "python-dev"
        ));
    }
}
