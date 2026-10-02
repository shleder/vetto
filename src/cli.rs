pub mod bench;
pub mod diff;
pub mod enable;
pub mod hook;
pub mod kill;
pub mod mask;
pub mod shell_env;
pub mod status;
pub mod undo;

#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub use crate::watchdog::WatchdogArgs;
pub use bench::BenchArgs;
pub use diff::DiffArgs;
pub use enable::{DisableArgs, EnableArgs};
pub use hook::{HookCommand, HookScope, ShellType};
pub use kill::KillArgs;
pub use mask::MaskArgs;
pub use undo::UndoArgs;

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

    /// UI mode: statusline | none
    #[arg(long, value_name = "MODE")]
    pub tui: Option<String>,

    /// Explicit sandbox backend: auto | process
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

    /// Mount host package caches (npm, pip, cargo, etc.) read-only to prevent tampering.
    #[arg(long)]
    pub read_only_caches: bool,

    /// Mount a 512MB tmpfs over /tmp (requires Linux)
    #[arg(long)]
    pub tmpfs_tmp: bool,

    /// Opt-in: send anonymous violation telemetry (hashed agent slug + category, no paths/secrets)
    #[arg(long)]
    pub anonymous_telemetry: bool,

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

    /// Enable OpenTelemetry spans for the session
    #[arg(long)]
    pub otel: bool,

    /// Kill the sandboxed session after DURATION without the agent finishing
    /// (e.g. 90s, 30m, 2h). Enforced with --tui=none (CI mode); other TUI
    /// modes warn and ignore it.
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,

    /// Calculate and use an adaptive timeout based on past successful sessions
    #[arg(long)]
    pub adaptive_timeout: bool,

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
    #[arg(long, alias = "headless", alias = "non-interactive")]
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

    /// Select an agent preset.
    #[arg(
        short = 'a',
        long = "agent",
        value_name = "NAME",
        action = clap::ArgAction::Append
    )]
    pub agents: Vec<String>,

    /// Additional glob patterns to resolve and deny (e.g. "**/*.pem").
    #[arg(long = "deny-glob", value_name = "PATTERN", action = clap::ArgAction::Append)]
    pub deny_glob: Vec<String>,

    /// Enforce Git branch protection (refuse write on main/master) and block destructive git pushes.
    #[arg(long = "git-guard")]
    pub git_guard: bool,

    /// Automatically create and switch to a temporary session branch if on main/master.
    #[arg(long = "auto-branch")]
    pub auto_branch: bool,

    /// Take a project snapshot before session starts and enable rollback.
    #[arg(long = "snapshot")]
    pub snapshot: bool,

    /// Disposable session: auto-rollback on failure, or prompt [Y/n] to keep changes on success
    #[arg(long = "ephemeral")]
    pub ephemeral: bool,

    /// Automatically scan project for secrets at session start and deny them.
    #[arg(long = "auto-deny-secrets")]
    pub auto_deny_secrets: bool,

    /// Redact secrets in real-time from stdout/stderr streams
    #[arg(long = "mask-secrets")]
    pub mask_secrets: bool,

    /// Disable real-time secret redaction
    #[arg(long = "no-mask-secrets")]
    pub no_mask_secrets: bool,

    /// Per-domain network traffic quota (e.g. --net-quota api.openai.com=100mb, --net-quota github.com=1gb)
    #[arg(long = "net-quota", value_name = "DOMAIN=SIZE", action = clap::ArgAction::Append)]
    pub net_quota: Vec<String>,

    /// Block DNS-over-HTTPS (DoH) and DNS-over-TLS (DoT) endpoints.
    #[arg(long = "block-doh")]
    pub block_doh: bool,

    /// Disable DoH and DoT blocking.
    #[arg(long = "no-block-doh")]
    pub no_block_doh: bool,

    /// Exits with 0 (and prints true) if running inside a container, 1 otherwise.
    #[arg(long)]
    pub is_container: bool,

    /// Fast-path benchmark mode (sub-4ms cold-start, pure JSON telemetry)
    #[arg(long)]
    pub benchmark: bool,

    #[command(subcommand)]
    pub command: Option<Command>,

    /// Agent command to supervise; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub agent: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Stream stdin to stdout with real-time secret and API key redaction
    Mask(mask::MaskArgs),

    /// Enable transparent sandbox wrapper for an AI coding agent (e.g. `vetto enable claude`)
    Enable(EnableArgs),

    /// Disable transparent sandbox wrapper for an AI coding agent (e.g. `vetto disable claude`)
    Disable(DisableArgs),

    /// Grant the agent access to a path or network domain (writes policy)
    Allow {
        /// Filesystem path, network domain, CIDR, or network preset name
        #[arg(
            value_name = "PATH|DOMAIN|CIDR|PRESET",
            required_unless_present = "preset"
        )]
        target: Option<String>,
        /// Filesystem only: read-only grant (default is read + write)
        #[arg(long)]
        read_only: bool,
        /// Treat TARGET as a network domain or CIDR/IP instead of a path
        #[arg(long)]
        net: bool,
        /// Explicitly treat TARGET as a network CIDR or IP range (e.g. 10.0.0.0/8, 192.168.1.0/24)
        #[arg(long)]
        cidr: bool,
        /// Add a network preset (e.g. npm, git, pip, cargo, huggingface, go, maven, nuget)
        #[arg(long, value_name = "PRESET")]
        preset: Option<String>,
        /// Set a network transfer quota for TARGET (e.g. --quota 100mb, --quota 1gb)
        #[arg(long, value_name = "SIZE")]
        quota: Option<String>,
        /// Edit ~/.vetto/config.toml instead of the project policy
        #[arg(long)]
        global: bool,
    },
    /// Explicitly deny reads of a path (secret masking) in the policy
    Deny {
        /// Filesystem path to mask, e.g. ~/.aws/credentials
        #[arg(value_name = "PATH")]
        target: Option<String>,
        /// Deny preset name (ssh, aws, gcp, kube, docker, antigravity, etc.)
        #[arg(long, value_name = "NAME")]
        preset: Option<String>,
        /// Treat target as a glob pattern (e.g. **/*.pem) and add to deny_glob
        #[arg(long = "glob")]
        glob: bool,
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
        /// Run comprehensive diagnostic preflight verification
        #[arg(long)]
        preflight: bool,
        /// Emit machine-readable diagnostic JSON
        #[arg(long)]
        json: bool,
    },
    /// List active sandboxed sessions and cleanup stale metadata.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Terminate a running session or process, or kill hung runaway sessions
    Kill(kill::KillArgs),
    /// Verify the sandbox boundary WITHOUT running any agent: secret paths,
    /// network reachability, and write-outside checks execute inside a
    /// throwaway sandbox built from the resolved policy.
    Verify {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Adversarial verification harness: runs the frozen scenario registry
    /// through host-fact-only oracle judging (measurement only, not part of
    /// the security boundary).
    #[command(name = "verify-ng")]
    VerifyNg {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
        /// Lint the frozen scenario registry without executing anything.
        #[arg(long)]
        lint: bool,
    },
    /// Run an agent command under the Vetto sandbox supervisor
    #[command(alias = "exec")]
    Run {
        /// Run in high-throughput SWE-bench benchmark mode (isolated CoW tmpfs, cgroups limits, no DB)
        #[arg(long)]
        benchmark: bool,

        /// Target agent binary or command
        #[arg(value_name = "COMMAND")]
        command: Option<String>,

        /// Arguments passed to the agent
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "ARGS"
        )]
        args: Vec<String>,
    },
    /// Restore project files from a previous session snapshot (instant rollback)
    Undo(undo::UndoArgs),
    /// Run an agent in a disposable ephemeral sandbox with instant rollback on cancel/failure
    Ephemeral(EphemeralArgs),
    /// High-throughput benchmark execution fast-path (SWE-bench adapter)
    Bench(bench::BenchArgs),
    /// Inspect agent changes against session snapshot (modified/added/deleted files & security)
    Diff(diff::DiffArgs),
    /// Inspect active autonomous loop counters, failing commands, and monitored workspaces
    Watchdog(WatchdogArgs),
    /// Analyze project ecosystem and generate a tailored policy.toml policy
    #[command(hide = true)]
    Init {
        /// Overwrite existing policy if present
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// List built-in policy profiles
    #[command(hide = true)]
    Profiles,
    /// Manage transparent developer shims and shell hooks
    #[command(hide = true)]
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Run or wrap Model Context Protocol (MCP) servers
    #[command(hide = true)]
    Mcp {
        #[command(subcommand)]
        command: Option<McpCommand>,
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
        /// Restore the last-good binary saved by the previous upgrade
        #[arg(long)]
        rollback: bool,
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
        /// Render the end-of-session security recap instead of the full detail
        #[arg(long)]
        recap: bool,
        #[arg(long)]
        digest: bool,
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
        #[arg(value_name = "SESSION_A")]
        session_a: String,
        /// Target session JSON report or identifier
        #[arg(value_name = "SESSION_B")]
        session_b: String,
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

#[derive(clap::Args, Debug, Clone)]
pub struct EphemeralArgs {
    /// Force discard changes without prompting, regardless of exit code
    #[arg(long = "discard")]
    pub discard: bool,

    /// Automatically accept and keep changes without prompting if session succeeds
    #[arg(short = 'y', long = "yes")]
    pub yes: bool,

    /// Command and arguments to execute; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub command: Vec<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum McpCommand {
    /// Run as native Vetto MCP JSON-RPC stdio server (default)
    Serve,

    /// Wrap and sandbox an external third-party MCP server binary
    Wrap(McpWrapArgs),
}

#[derive(clap::Args, Debug, Clone)]
pub struct McpWrapArgs {
    /// Allow read+write access to a path (can be repeated)
    #[arg(long = "allow", value_name = "PATH")]
    pub allow: Vec<String>,

    /// Allow read-only access to a path (can be repeated)
    #[arg(long = "allow-read", value_name = "PATH")]
    pub allow_read: Vec<String>,

    /// Network egress mode: off (default) | allowlist:<domains> | open
    #[arg(long, default_value = "off", value_name = "MODE")]
    pub net: String,

    /// Target MCP server command and arguments; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub command: Vec<String>,
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
        /// Resource ceilings for the agent process, comma separated:
        /// cpu=SECONDS, as=BYTES, procs=N, nofile=N, fsize=BYTES. Merged
        /// strictest-wins with policy layers.
        #[arg(long = "limits", value_name = "SPEC")]
        limits: Option<String>,
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
        /// Source agent configuration type (claude, codex)
        #[arg(long, value_name = "AGENT")]
        from: Option<String>,
        /// Source file path when using --from
        #[arg(long = "path", value_name = "PATH")]
        path: Option<PathBuf>,
        /// Import from Claude settings.json
        #[arg(long, value_name = "PATH")]
        claude: Option<PathBuf>,
        /// Import from Codex config.toml
        #[arg(long, value_name = "PATH")]
        codex: Option<PathBuf>,
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

impl Cli {
    pub fn to_run_config(&self) -> anyhow::Result<crate::config::RunConfig> {
        let global = crate::config::load_global_config().unwrap_or_default();
        self.to_run_config_with_global(&global)
    }

    pub fn to_run_config_with_global(
        &self,
        global: &crate::config::GlobalConfig,
    ) -> anyhow::Result<crate::config::RunConfig> {
        let cli = self;
        let agent_preset = match cli.agents.as_slice() {
            [] => crate::config::detect_agent_preset(&cli.agent),
            [agent] if !agent.contains('=') && !agent.trim().is_empty() => {
                Some(
                    crate::policy::defaults::canonical_agent_name(agent)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| agent.clone()),
                )
            }
            [_] => anyhow::bail!("--agent expects a preset name (e.g. claude, codex, aider)"),
            _ => anyhow::bail!("accepts at most one --agent preset"),
        };

        let explicit_net = cli.net.is_some();
        let net = match cli.net.as_deref().or(global.net.as_deref()) {
            Some(raw) => crate::config::parse_net_mode(raw)?,
            None => {
                if let Some(ref agent) = agent_preset {
                    let domains = crate::policy::presets::agent_network_allowlist(agent);
                    if !domains.is_empty() {
                        crate::config::NetMode::Allowlist(domains)
                    } else {
                        crate::config::NetMode::Off
                    }
                } else if crate::config::is_toolchain_command(&cli.agent) {
                    crate::config::NetMode::Allowlist(
                        crate::policy::presets::CANONICAL_PACKAGE_REGISTRY_DOMAINS
                            .iter()
                            .map(|s| s.to_string())
                            .collect(),
                    )
                } else {
                    crate::config::NetMode::Off
                }
            }
        };

        let git_ssh = cli.git_ssh || global.git_ssh.unwrap_or(false);
        if git_ssh && !net.uses_relay() {
            anyhow::bail!("--git-ssh requires --net=allowlist:... or --net=strict:...");
        }

        let fail_on_block = cli.fail_on_block.or(global.fail_on_block);
        if fail_on_block == Some(0) {
            return Err(anyhow::Error::new(crate::error::VettoError::Policy(
                "--fail-on-block threshold must be greater than zero".into(),
            )));
        }

        let report_auto_cleanup = !cli.no_report_auto_cleanup;
        let report_retention = cli
            .report_retention
            .or(global.report_retention)
            .or(Some(50));
        let report_max_age_secs = cli.report_max_age_secs.or(global.report_max_age_secs);

        let preset_str = cli.preset.as_deref().or(global.preset.as_deref());
        let preset = match preset_str {
            Some(p) => Some(crate::policy::presets::Preset::parse(p)?),
            None => None,
        };

        let profile = if cli.profile != "default" {
            cli.profile.clone()
        } else if let Some(ref gp) = global.profile {
            gp.clone()
        } else {
            "default".to_string()
        };

        let explicit_tui = cli.tui.is_some() || global.tui.is_some();
        let raw_tui = if let Some(ref ct) = cli.tui {
            ct.as_str()
        } else if let Some(ref gt) = global.tui {
            gt.as_str()
        } else {
            "statusline"
        };
        let mut tui = crate::config::parse_tui_mode(raw_tui)?;
        if cli.ci && tui == crate::config::TuiMode::Statusline {
            tui = crate::config::TuiMode::None;
        }

        if !explicit_tui
            && tui == crate::config::TuiMode::Statusline
            && crate::config::should_default_to_no_tui(None, &cli.agent)
        {
            tui = crate::config::TuiMode::None;
        }

        let timeout_str = cli.timeout.as_deref().or(global.timeout.as_deref());

        let limits_spec = match (cli.limits.as_deref(), global.limits.as_deref()) {
            (Some(cli_l), Some(glob_l)) => Some(format!("{glob_l},{cli_l}")),
            (Some(cli_l), None) => Some(cli_l.to_string()),
            (None, Some(glob_l)) => Some(glob_l.to_string()),
            (None, None) => None,
        };
        if let Some(spec) = &limits_spec {
            crate::config::validate_limits_spec(spec)?;
        }

        let report_spec = cli.report.as_deref().or(global.report.as_deref());
        let mut report_formats = Vec::new();
        if let Some(fmts) = report_spec {
            for f in fmts.split(',') {
                report_formats.push(match f.trim().to_ascii_lowercase().as_str() {
                    "md" | "markdown" => crate::config::ReportFormat::Markdown,
                    "json" => crate::config::ReportFormat::Json,
                    "sarif" => crate::config::ReportFormat::Sarif,
                    other => {
                        anyhow::bail!(
                            "unknown report format '{other}' (expected md, json, sarif)"
                        )
                    }
                });
            }
        }

        let observe_seccomp = cli.observe_seccomp || global.observe_seccomp.unwrap_or(false);
        let verify_preflight = cli.verify || global.verify.unwrap_or(false);
        let shadow = cli.shadow || global.shadow.unwrap_or(false);
        let report_dir = cli
            .report_dir
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| global.report_dir.as_ref().map(PathBuf::from));
        let jsonl_path = cli
            .jsonl
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| global.jsonl.as_ref().map(PathBuf::from));

        let mut auto_timeout_requested = false;
        let session_timeout = match timeout_str {
            Some("auto") => {
                auto_timeout_requested = true;
                let proj = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                let agent_name = agent_preset
                    .as_deref()
                    .unwrap_or_else(|| cli.agent.first().map(|s| s.as_str()).unwrap_or("default"));
                crate::history::compute_auto_timeout(&proj, agent_name)
            }
            Some(raw) => Some(crate::config::parse_session_timeout(raw)?),
            None => {
                if cli.adaptive_timeout {
                    let proj = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
                    let reports = report_dir.clone().unwrap_or_else(|| {
                        crate::audit::history::default_history_path()
                            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                            .unwrap_or_else(|| PathBuf::from("."))
                    });
                    crate::watchdog::timeout::recommend_timeout(&proj, &reports)
                } else {
                    None
                }
            }
        };

        let mask_secrets = if cli.no_mask_secrets {
            false
        } else if cli.mask_secrets {
            true
        } else {
            global.mask_secrets.unwrap_or(true)
        };

        let ephemeral = cli.ephemeral;
        let snapshot = cli.snapshot || ephemeral;

        let mut net_quota = std::collections::HashMap::new();
        for item in &cli.net_quota {
            let Some((domain, size_str)) = item.split_once('=') else {
                anyhow::bail!(
                    "invalid --net-quota format '{item}': expected DOMAIN=SIZE (e.g. api.openai.com=100mb)"
                );
            };
            let domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
            if domain.is_empty() {
                anyhow::bail!("invalid --net-quota '{item}': domain cannot be empty");
            }
            let bytes = crate::policy::loader::parse_quota_bytes(size_str.trim())?;
            net_quota.insert(domain, bytes);
        }

        let http_proxy = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let https_proxy = std::env::var("HTTPS_PROXY")
            .or_else(|_| std::env::var("https_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
            .ok();
        let no_proxy = std::env::var("NO_PROXY")
            .or_else(|_| std::env::var("no_proxy"))
            .ok();
        let block_doh = if cli.no_block_doh {
            false
        } else if cli.block_doh {
            true
        } else {
            matches!(
                net,
                crate::config::NetMode::Allowlist(_) | crate::config::NetMode::Strict(_)
            )
        };

        let benchmark = cli.benchmark;
        let tui = if benchmark {
            crate::config::TuiMode::None
        } else {
            tui
        };
        let ci = if benchmark { true } else { cli.ci };
        let ephemeral = if benchmark { true } else { ephemeral };
        let mask_secrets = if benchmark { true } else { mask_secrets };
        let auto_deny_secrets = if benchmark {
            true
        } else {
            cli.auto_deny_secrets
        };
        let snapshot = if benchmark { false } else { snapshot };
        let report_formats = if benchmark {
            Vec::new()
        } else {
            report_formats
        };
        let tmpfs_tmp = if benchmark { true } else { cli.tmpfs_tmp };

        Ok(crate::config::RunConfig {
            profile,
            preset,
            policy_path: cli.policy.as_ref().map(PathBuf::from),
            net,
            explicit_net,
            tui,
            backend: cli.backend.clone(),
            oslog: cli.oslog,
            lpac: cli.lpac,
            observe_seccomp,
            jsonl_path,
            report_formats,
            report_dir,
            report_auto_cleanup,
            report_retention,
            report_max_age_secs,
            fail_on_block,
            git_ssh,
            notify: cli.notify,
            otel_endpoint: cli.otel_endpoint.clone(),
            otel: cli.otel,
            session_timeout,
            auto_timeout_requested,
            system_log: cli.system_log,
            limits_spec,
            verify_preflight,
            shadow,
            dry_run: cli.dry_run,
            ci,
            agent_preset,
            deny_glob: cli.deny_glob.clone(),
            git_guard: cli.git_guard,
            auto_branch: cli.auto_branch,
            snapshot,
            ephemeral,
            ephemeral_auto_accept: false,
            ephemeral_force_discard: false,
            auto_deny_secrets,
            read_only_caches: cli.read_only_caches,
            anonymous_telemetry: cli.anonymous_telemetry
                || global.anonymous_telemetry.unwrap_or(false),
            tmpfs_tmp,
            mask_secrets,
            net_quota,
            block_doh,
            benchmark,
            agent: cli.agent.clone(),
            http_proxy,
            https_proxy,
            no_proxy,
        })
    }
}

impl crate::config::RunConfig {
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        cli.to_run_config()
    }

    pub fn from_cli_with_global(
        cli: &Cli,
        global: &crate::config::GlobalConfig,
    ) -> anyhow::Result<Self> {
        cli.to_run_config_with_global(global)
    }
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
            Cli::try_parse_from(["vetto", "hook", "install", "--scope", "local", "--force"])
                .expect("hook install parsing");
        assert!(matches!(
            install_cli.command,
            Some(Command::Hook {
                command: HookCommand::Install {
                    scope: HookScope::Local,
                    force: true,
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
    fn kill_subcommand_parses_hung_and_pid() {
        let hung_cli = Cli::try_parse_from(["vetto", "kill", "--hung"]).expect("kill hung parsing");
        assert!(matches!(
            hung_cli.command,
            Some(Command::Kill(KillArgs {
                hung: true,
                target: None,
                force: false,
                ..
            }))
        ));

        let pid_cli = Cli::try_parse_from(["vetto", "kill", "12345"]).expect("kill pid parsing");
        assert!(matches!(
            pid_cli.command,
            Some(Command::Kill(KillArgs {
                target: Some(ref t),
                hung: false,
                force: false,
                ..
            })) if t == "12345"
        ));

        let force_cli =
            Cli::try_parse_from(["vetto", "kill", "-9", "54321"]).expect("kill force parsing");
        assert!(matches!(
            force_cli.command,
            Some(Command::Kill(KillArgs {
                target: Some(ref t),
                force: true,
                ..
            })) if t == "54321"
        ));
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
    fn mask_subcommand_parses_style() {
        let cli_default = Cli::try_parse_from(["vetto", "mask"]).expect("mask default parsing");
        assert!(matches!(
            cli_default.command,
            Some(Command::Mask(MaskArgs {
                style: mask::MaskStyle::Marker,
            }))
        ));

        let cli_pad =
            Cli::try_parse_from(["vetto", "mask", "--style", "pad"]).expect("mask pad parsing");
        assert!(matches!(
            cli_pad.command,
            Some(Command::Mask(MaskArgs {
                style: mask::MaskStyle::Pad,
            }))
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
    fn doctor_preflight_and_json_flags_parse() {
        let cli_preflight = Cli::try_parse_from(["vetto", "doctor", "--preflight"])
            .expect("doctor preflight parsing");
        assert!(matches!(
            cli_preflight.command,
            Some(Command::Doctor {
                preflight: true,
                json: false,
                ..
            })
        ));

        let cli_json =
            Cli::try_parse_from(["vetto", "doctor", "--json"]).expect("doctor json parsing");
        assert!(matches!(
            cli_json.command,
            Some(Command::Doctor {
                preflight: false,
                json: true,
                ..
            })
        ));

        let cli_both = Cli::try_parse_from(["vetto", "doctor", "--preflight", "--json"])
            .expect("doctor preflight json parsing");
        assert!(matches!(
            cli_both.command,
            Some(Command::Doctor {
                preflight: true,
                json: true,
                ..
            })
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
                rollback: false,
            }) if ch == "alpha"
        ));
        let cli_rb =
            Cli::try_parse_from(["vetto", "upgrade", "--rollback"]).expect("upgrade rollback");
        assert!(matches!(
            cli_rb.command,
            Some(Command::Upgrade { rollback: true, .. })
        ));
    }

    #[test]
    fn init_subcommand_parses() {
        let cli = Cli::try_parse_from(["vetto", "init", "--force"]).expect("init parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Init { force: true })
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
    fn policy_explain_limits_parses() {
        let cli = Cli::try_parse_from(["vetto", "policy", "explain", "--limits", "cpu=10,procs=5"])
            .expect("policy explain limits parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Policy {
                command: PolicyCommand::Explain { limits: Some(ref limits), .. }
            }) if limits == "cpu=10,procs=5"
        ));
    }

    #[test]
    fn policy_import_parses() {
        let cli = Cli::try_parse_from([
            "vetto",
            "policy",
            "import",
            "--claude",
            "settings.json",
            "--output",
            "my-policy.toml",
        ])
        .expect("policy import parsing");
        assert!(matches!(
            cli.command,
            Some(Command::Policy {
                command: PolicyCommand::Import { ref claude, ref output, .. }
            }) if claude.as_deref() == Some(std::path::Path::new("settings.json"))
                && output == &PathBuf::from("my-policy.toml")
        ));
    }

    #[test]
    fn cli_parses_headless_and_non_interactive_flags_as_ci() {
        let cli_headless =
            Cli::try_parse_from(["vetto", "--headless", "run"]).expect("headless parsing");
        assert!(cli_headless.ci);

        let cli_non_interactive = Cli::try_parse_from(["vetto", "--non-interactive", "run"])
            .expect("non-interactive parsing");
        assert!(cli_non_interactive.ci);

        let cli_ci = Cli::try_parse_from(["vetto", "--ci", "run"]).expect("ci parsing");
        assert!(cli_ci.ci);
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
                recap: false,
                ..
            })
        ));

        let audit_recap = Cli::try_parse_from(["vetto", "audit", "--latest", "--recap"])
            .expect("audit recap parsing");
        assert!(matches!(
            audit_recap.command,
            Some(Command::Audit {
                latest: true,
                recap: true,
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
                ref session_a,
                ref session_b,
                json: true,
            }) if session_a == "s1.json" && session_b == "s2.json"
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
        assert!(matches!(mcp.command, Some(Command::Mcp { command: None })));

        let mcp_serve = Cli::try_parse_from(["vetto", "mcp", "serve"]).expect("mcp serve");
        assert!(matches!(
            mcp_serve.command,
            Some(Command::Mcp {
                command: Some(McpCommand::Serve)
            })
        ));

        let mcp_wrap = Cli::try_parse_from([
            "vetto",
            "mcp",
            "wrap",
            "--allow",
            "/tmp",
            "--",
            "node",
            "server.js",
        ])
        .expect("mcp wrap");
        assert!(matches!(
            mcp_wrap.command,
            Some(Command::Mcp {
                command: Some(McpCommand::Wrap(ref args))
            }) if args.allow == vec!["/tmp"] && args.command == vec!["node", "server.js"]
        ));

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

    #[test]
    fn test_ephemeral_cli_flag_and_subcommand() {
        let flag_cli = Cli::try_parse_from(["vetto", "--ephemeral", "--", "claude"])
            .expect("--ephemeral parsing");
        assert!(flag_cli.ephemeral);
        assert_eq!(flag_cli.agent, vec!["claude"]);

        let subcmd_cli = Cli::try_parse_from(["vetto", "ephemeral", "--", "claude"])
            .expect("ephemeral subcommand parsing");
        assert!(matches!(
            subcmd_cli.command,
            Some(Command::Ephemeral(ref args))
                if args.command == vec!["claude"] && !args.discard && !args.yes
        ));

        let subcmd_discard =
            Cli::try_parse_from(["vetto", "ephemeral", "--discard", "--", "codex"])
                .expect("ephemeral --discard");
        assert!(matches!(
            subcmd_discard.command,
            Some(Command::Ephemeral(ref args))
                if args.command == vec!["codex"] && args.discard && !args.yes
        ));

        let subcmd_yes = Cli::try_parse_from(["vetto", "ephemeral", "-y", "--", "cursor"])
            .expect("ephemeral -y");
        assert!(matches!(
            subcmd_yes.command,
            Some(Command::Ephemeral(ref args))
                if args.command == vec!["cursor"] && !args.discard && args.yes
        ));
    }
}

#[cfg(test)]
mod test_is_container {
    use super::*;
    use clap::Parser;

    #[test]
    fn parses_is_container_flag() {
        let cli = Cli::try_parse_from(["vetto", "--is-container"]).unwrap();
        assert!(cli.is_container);
        assert!(!cli.quiet);
    }
}
