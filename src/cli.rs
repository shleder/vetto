pub mod git_hook;
pub mod hook;
pub mod shell_env;

pub use hook::{HookCommand, HookScope, ShellType};

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
  vetto hook install --scope global --git
  vetto hook status
  vetto doctor
  vetto doctor --probe
  vetto rescue --json scan --limit 25
  vetto rescue --json scan --all
  vetto rescue diagnose sessions/2026/08/23/session.jsonl
  vetto rescue snapshot session.jsonl --output ./recovery/session.jsonl
  vetto report compare session-a.json session-b.json
  vetto mcp sandbox /usr/bin/mcp-server
  vetto net-l7 filter --method GET --host api.github.com --path /repos
  vetto watchdog loop-guard --tool bash --tokens 50
  vetto governance sbom --workspace .
  vetto wasm run module.wasm
  vetto ui --port 7070
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
    /// Analyze project ecosystem and generate a tailored vetto.toml policy
    Init {
        /// Overwrite existing vetto.toml if present
        #[arg(long, short = 'f')]
        force: bool,
    },
    /// List built-in policy profiles
    Profiles,
    /// Manage transparent developer shims, shell hooks, and Git hook wrappers
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },
    /// Fast native shim dispatcher for intercepted toolchain binaries
    Shim {
        /// Target binary name (if not inferred from argv[0])
        #[arg(value_name = "BINARY")]
        binary: Option<String>,

        /// Arguments passed to the target binary
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
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
    /// Inspect and copy persisted agent sessions without modifying originals.
    Rescue {
        /// Recovery adapter. The npm alpha ships Codex; main also has an
        /// experimental, explicit-root Claude read-only adapter.
        #[arg(long, default_value = "codex", value_name = "ID")]
        adapter: String,
        /// Explicit agent state root (required for non-Codex adapters; Codex
        /// defaults to CODEX_HOME or $HOME/.codex).
        #[arg(long, value_name = "PATH")]
        root: Option<PathBuf>,
        /// Emit sanitized machine-readable JSON.
        #[arg(long)]
        json: bool,
        #[command(subcommand)]
        command: RescueCommand,
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
    /// Model Context Protocol (MCP) process isolation and capabilities
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Deep Network L7 Inspection, Dev Server Armor, and Token Verifiers
    #[command(name = "net-l7", visible_alias = "l7")]
    NetL7 {
        #[command(subcommand)]
        command: NetL7Command,
    },
    /// State Watchdog, CoW Micro-Snapshots, Swarm Locks, and Loop Guards
    Watchdog {
        #[command(subcommand)]
        command: WatchdogCommand,
    },
    /// Developer Ecosystem, Enterprise Governance, SBOM, and Merkle Auditing
    #[command(name = "governance", visible_alias = "gov")]
    Governance {
        #[command(subcommand)]
        command: GovernanceCommand,
    },
    /// WebAssembly WASI Preview 2 Isolation Tier
    Wasm {
        #[command(subcommand)]
        command: WasmCommand,
    },
    /// Launch the local Web GUI Dashboard
    Ui {
        /// Port to bind the Web GUI server (default: 7070)
        #[arg(long, default_value_t = 7070)]
        port: u16,

        /// Host address to bind
        #[arg(long, default_value = "127.0.0.1")]
        host: String,

        /// Automatically open browser on launch
        #[arg(long)]
        open: bool,
    },
}

/// CLI subcommand definition for `vetto mcp`.
#[derive(Subcommand, Debug, Clone)]
pub enum McpCommand {
    /// Spawn and isolate an MCP server process in a capability sandbox
    Sandbox {
        /// Executable command/binary to launch
        #[arg(value_name = "COMMAND")]
        command: PathBuf,

        /// Server identifier name
        #[arg(long, default_value = "mcp-server")]
        name: String,

        /// Allowed filesystem read paths
        #[arg(long = "read", action = clap::ArgAction::Append)]
        read_paths: Vec<PathBuf>,

        /// Allowed filesystem write paths
        #[arg(long = "write", action = clap::ArgAction::Append)]
        write_paths: Vec<PathBuf>,

        /// Working directory
        #[arg(long, default_value = ".")]
        working_dir: PathBuf,

        /// Arguments passed to the server executable
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Evaluate an MCP tool call against granular authorization policy rules
    Gate {
        /// Target server name
        #[arg(long, default_value = "*")]
        server: String,

        /// Tool name to evaluate
        #[arg(long)]
        tool: String,

        /// JSON arguments payload
        #[arg(long, default_value = "{}")]
        args: String,
    },
    /// Replay or inspect a recorded JSON-RPC trace session
    Replay {
        /// Path to .vetto-trace or session trace file
        #[arg(value_name = "TRACE_FILE")]
        trace_file: PathBuf,

        /// Replay matching strategy: strict | hash | fuzzy
        #[arg(long, default_value = "strict")]
        strategy: String,
    },
    /// Analyze workspace AST and generate .cursorrules and vetto.toml policies
    Rules {
        /// Workspace root path to scan
        #[arg(long, default_value = ".")]
        workspace: PathBuf,

        /// Output path for generated .cursorrules
        #[arg(long)]
        out_rules: Option<PathBuf>,

        /// Output path for generated vetto.toml
        #[arg(long)]
        out_toml: Option<PathBuf>,
    },
    /// Generate adversarial fuzzing vectors for MCP tool JSON schemas
    Fuzz {
        /// Tool name
        #[arg(long, default_value = "generic_tool")]
        tool: String,

        /// Path to JSON schema definition file
        #[arg(long)]
        schema: Option<PathBuf>,
    },
    /// Mint or verify federated subagent capability tokens
    Federate {
        /// Session ID
        #[arg(long, default_value = "default-session")]
        session: String,

        /// Target role name
        #[arg(long, default_value = "subagent")]
        role: String,

        /// Target server name or pattern
        #[arg(long, default_value = "*")]
        server: String,

        /// Permitted tool methods (comma-separated or wildcard)
        #[arg(long, default_value = "*")]
        methods: String,

        /// Token validity TTL in seconds
        #[arg(long, default_value_t = 3600)]
        ttl: u64,
    },
}

/// CLI subcommand definition for `vetto net-l7` / `vetto l7`.
#[derive(Subcommand, Debug, Clone)]
pub enum NetL7Command {
    /// Evaluate HTTP request against L7 REST method and endpoint ACL rules
    Filter {
        /// HTTP method: GET, POST, PUT, DELETE, PATCH, etc.
        #[arg(long, default_value = "GET")]
        method: String,

        /// Target host / domain
        #[arg(long)]
        host: String,

        /// Request path and query
        #[arg(long, default_value = "/")]
        path: String,
    },
    /// Audit dev server access on ports 3000, 5173, 8000, 8080 against agent injection
    Ports {
        /// Dev server port to check
        #[arg(long, default_value_t = 3000)]
        port: u16,

        /// Request path
        #[arg(long, default_value = "/")]
        path: String,
    },
    /// Detect background tunneling tools (ngrok, cloudflared, localtunnel)
    TunnelDetect {
        /// Process executable path to audit
        #[arg(long)]
        exe: PathBuf,

        /// Process PID
        #[arg(long, default_value_t = 1000)]
        pid: u32,

        /// Process command line arguments
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Verify outbound API token permissions and scope rights
    TokenCheck {
        /// API token string
        #[arg(long)]
        token: String,

        /// Required OAuth scopes
        #[arg(long = "scope", action = clap::ArgAction::Append)]
        scopes: Vec<String>,
    },
    /// Generate ephemeral root CA certificate and mint leaf MITM certs
    MitmCa {
        /// Domain to mint leaf certificate for
        #[arg(long, default_value = "api.openai.com")]
        domain: String,
    },
    /// Verify incoming webhook HMAC signature and sanitize payload
    Webhook {
        /// Webhook provider: github | gitlab | stripe | slack
        #[arg(long, default_value = "github")]
        provider: String,

        /// Path to webhook payload body file
        #[arg(long)]
        body_file: PathBuf,

        /// HMAC signature header string
        #[arg(long)]
        signature: String,
    },
}

/// CLI subcommand definition for `vetto watchdog`.
#[derive(Subcommand, Debug, Clone)]
pub enum WatchdogCommand {
    /// Supervise tool calls for infinite loops, repeated commands, and token burns
    LoopGuard {
        /// Tool name
        #[arg(long, default_value = "bash")]
        tool: String,

        /// Estimated token cost
        #[arg(long, default_value_t = 100)]
        tokens: u64,

        /// Payload string or invocation command
        #[arg(long, default_value = "")]
        payload: String,
    },
    /// Create or list instant Copy-on-Write (CoW) micro-snapshots
    Snapshot {
        /// Action: create | list | rollback
        #[arg(long, default_value = "list")]
        action: String,

        /// Workspace directory
        #[arg(long, default_value = ".")]
        workspace: PathBuf,

        /// Triggering command description (for create)
        #[arg(long, default_value = "manual-snapshot")]
        trigger: String,

        /// Target snapshot ID (for rollback)
        #[arg(long)]
        snapshot_id: Option<String>,
    },
    /// Acquire, inspect, or resolve cross-agent swarm file locks
    Lock {
        /// Target file path
        #[arg(long)]
        path: PathBuf,

        /// Requesting Agent ID
        #[arg(long, default_value = "agent-1")]
        agent: String,

        /// Lock mode: shared | exclusive
        #[arg(long, default_value = "exclusive")]
        mode: String,
    },
    /// Synthesize sanitized .env.example template from session activity
    EnvSynth {
        /// Path to source .env or session file
        #[arg(long, default_value = ".env")]
        input: PathBuf,

        /// Output path for synthesized .env.example
        #[arg(long, default_value = ".env.example")]
        output: PathBuf,
    },
    /// Inspect or recover from crash-resilient session WAL journal
    Wal {
        /// Path to active_session.wal file
        #[arg(long, default_value = ".vetto/state/active_session.wal")]
        wal_file: PathBuf,

        /// Print all recorded events
        #[arg(long)]
        dump: bool,
    },
    /// Audit disk and inode quotas against threshold tripwires
    Tripwire {
        /// Workspace directory to check
        #[arg(long, default_value = ".")]
        workspace: PathBuf,

        /// Max allowed disk usage in MB
        #[arg(long, default_value_t = 10240)]
        max_mb: u64,
    },
    /// Dry-run script AST hazard analysis before execution
    ScriptDryRun {
        /// Path to shell/python script file or inline command
        #[arg(value_name = "SCRIPT")]
        script: String,
    },
}

/// CLI subcommand definition for `vetto governance` / `vetto gov`.
#[derive(Subcommand, Debug, Clone)]
pub enum GovernanceCommand {
    /// Generate and audit Software Bill of Materials (SBOM) and license compliance
    Sbom {
        /// Workspace path
        #[arg(long, default_value = ".")]
        workspace: PathBuf,

        /// Output format: json | spdx | cyclonedx
        #[arg(long, default_value = "json")]
        format: String,
    },
    /// Inspect or verify cryptographic Merkle-tree audit logs
    Merkle {
        /// Path to audit block log file
        #[arg(long, default_value = ".vetto/audit/merkle.log")]
        log_file: PathBuf,

        /// Verify complete blockchain-like seal integrity
        #[arg(long)]
        verify: bool,
    },
    /// Evaluate Policy-as-Code using Rego / OPA rules
    Opa {
        /// Policy definition file
        #[arg(long)]
        policy_file: Option<PathBuf>,

        /// Target command to evaluate
        #[arg(long)]
        command: String,

        /// Target path
        #[arg(long, default_value = ".")]
        path: String,
    },
    /// Run red-team containment security benchmark suite
    Benchmark {
        /// Benchmark suite ID
        #[arg(long, default_value = "vetto-redteam-core")]
        suite: String,
    },
    /// Compile and cryptographically sign an offline policy bundle
    BundleSign {
        /// Bundle ID
        #[arg(long, default_value = "corp-policy-bundle-v1")]
        bundle_id: String,

        /// Issuer name
        #[arg(long, default_value = "secops")]
        issuer: String,

        /// Path to policy TOML file to bundle
        #[arg(long, default_value = "vetto.toml")]
        policy_file: PathBuf,

        /// Secret key string for HMAC signature
        #[arg(long, default_value = "vetto-default-bundle-secret-key-32b!")]
        secret_key: String,

        /// Output path for signed bundle JSON
        #[arg(long, default_value = "vetto-bundle.signed.json")]
        output: PathBuf,
    },
    /// Start or run Language Server Protocol (LSP) diagnostics for policy files
    Lsp {
        /// Policy file to validate
        #[arg(long, default_value = "vetto.toml")]
        file: PathBuf,
    },
}

/// CLI subcommand definition for `vetto wasm`.
#[derive(Subcommand, Debug, Clone)]
pub enum WasmCommand {
    /// Execute a WASM module inside the isolated WASI Preview 2 sandbox tier
    Run {
        /// Path to compiled .wasm binary module
        #[arg(value_name = "WASM_MODULE")]
        wasm_file: PathBuf,

        /// Maximum fuel limit
        #[arg(long, default_value_t = 10_000_000)]
        max_fuel: u64,

        /// Memory limit in MB
        #[arg(long, default_value_t = 64)]
        max_memory_mb: u64,

        /// Arguments passed to the WASM entrypoint
        #[arg(last = true, value_name = "ARGS")]
        args: Vec<String>,
    },
    /// Inspect WASM module binary header, exported functions, and declared memory
    Inspect {
        /// Path to .wasm binary module
        #[arg(value_name = "WASM_MODULE")]
        wasm_file: PathBuf,
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
        let install_cli = Cli::try_parse_from(["vetto", "hook", "install", "--scope", "local", "--git"])
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
        let cli = Cli::try_parse_from(["vetto", "shim", "node", "--", "index.js", "--port", "3000"])
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
    fn mcp_subcommand_parses_all_variants() {
        let sandbox_cli = Cli::try_parse_from([
            "vetto", "mcp", "sandbox", "/usr/bin/git-mcp", "--name", "git-server", "--read", "/tmp", "--", "--stdio"
        ]).expect("mcp sandbox parsing");
        assert!(matches!(
            sandbox_cli.command,
            Some(Command::Mcp {
                command: McpCommand::Sandbox { ref name, ref args, .. }
            }) if name == "git-server" && args == &vec!["--stdio".to_string()]
        ));

        let gate_cli = Cli::try_parse_from([
            "vetto", "mcp", "gate", "--server", "db-mcp", "--tool", "query", "--args", "{\"sql\":\"SELECT 1\"}"
        ]).expect("mcp gate parsing");
        assert!(matches!(
            gate_cli.command,
            Some(Command::Mcp {
                command: McpCommand::Gate { ref server, ref tool, .. }
            }) if server == "db-mcp" && tool == "query"
        ));

        let rules_cli = Cli::try_parse_from([
            "vetto", "mcp", "rules", "--workspace", "/my/project", "--out-rules", "/my/project/.cursorrules"
        ]).expect("mcp rules parsing");
        assert!(matches!(
            rules_cli.command,
            Some(Command::Mcp {
                command: McpCommand::Rules { ref workspace, .. }
            }) if workspace == &PathBuf::from("/my/project")
        ));
    }

    #[test]
    fn net_l7_subcommand_parses_and_supports_alias() {
        let filter_cli = Cli::try_parse_from([
            "vetto", "net-l7", "filter", "--method", "POST", "--host", "api.github.com", "--path", "/graphql"
        ]).expect("net-l7 filter parsing");
        assert!(matches!(
            filter_cli.command,
            Some(Command::NetL7 {
                command: NetL7Command::Filter { ref method, ref host, ref path }
            }) if method == "POST" && host == "api.github.com" && path == "/graphql"
        ));

        let alias_cli = Cli::try_parse_from([
            "vetto", "l7", "ports", "--port", "5173", "--path", "/index.html"
        ]).expect("l7 alias ports parsing");
        assert!(matches!(
            alias_cli.command,
            Some(Command::NetL7 {
                command: NetL7Command::Ports { port: 5173, ref path }
            }) if path == "/index.html"
        ));
    }

    #[test]
    fn watchdog_subcommand_parses_variants() {
        let loop_cli = Cli::try_parse_from([
            "vetto", "watchdog", "loop-guard", "--tool", "bash", "--tokens", "250", "--payload", "rm -rf /tmp/build"
        ]).expect("watchdog loop-guard parsing");
        assert!(matches!(
            loop_cli.command,
            Some(Command::Watchdog {
                command: WatchdogCommand::LoopGuard { ref tool, tokens: 250, .. }
            }) if tool == "bash"
        ));

        let snap_cli = Cli::try_parse_from([
            "vetto", "watchdog", "snapshot", "--action", "create", "--workspace", ".", "--trigger", "pre-clean"
        ]).expect("watchdog snapshot parsing");
        assert!(matches!(
            snap_cli.command,
            Some(Command::Watchdog {
                command: WatchdogCommand::Snapshot { ref action, ref trigger, .. }
            }) if action == "create" && trigger == "pre-clean"
        ));
    }

    #[test]
    fn governance_and_wasm_and_ui_subcommands_parse() {
        let gov_cli = Cli::try_parse_from([
            "vetto", "gov", "sbom", "--workspace", ".", "--format", "cyclonedx"
        ]).expect("gov sbom parsing");
        assert!(matches!(
            gov_cli.command,
            Some(Command::Governance {
                command: GovernanceCommand::Sbom { ref format, .. }
            }) if format == "cyclonedx"
        ));

        let wasm_cli = Cli::try_parse_from([
            "vetto", "wasm", "run", "plugin.wasm", "--max-fuel", "5000000", "--", "arg1"
        ]).expect("wasm run parsing");
        assert!(matches!(
            wasm_cli.command,
            Some(Command::Wasm {
                command: WasmCommand::Run { ref wasm_file, max_fuel: 5000000, ref args, .. }
            }) if wasm_file == &PathBuf::from("plugin.wasm") && args == &vec!["arg1".to_string()]
        ));

        let ui_cli = Cli::try_parse_from([
            "vetto", "ui", "--port", "8080", "--host", "0.0.0.0", "--open"
        ]).expect("ui parsing");
        assert!(matches!(
            ui_cli.command,
            Some(Command::Ui { port: 8080, ref host, open: true }) if host == "0.0.0.0"
        ));
    }
}
