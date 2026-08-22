use anyhow::Result;
use clap::{Parser, Subcommand};

const EXAMPLES: &str = "\
Examples:
  leash -- npm run dev
  leash --profile strict -- python agent.py
  leash --dry-run -- cargo build
  leash init
  leash profiles
  leash doctor";

/// leash - a sandbox/security layer for AI coding agents.
#[derive(Parser, Debug)]
#[command(name = "leash", version, about, after_help = EXAMPLES)]
pub struct Cli {
    /// Security profile to enforce (see `leash profiles`)
    #[arg(long, default_value = "default", value_name = "NAME")]
    pub profile: String,

    /// Show what would be restricted without enforcing anything
    #[arg(long)]
    pub dry_run: bool,

    /// Non-interactive mode for CI pipelines (emits a JSON event summary)
    #[arg(long)]
    pub ci: bool,

    /// Enable verbose logging
    #[arg(long)]
    pub verbose: bool,

    /// Utility subcommand
    #[command(subcommand)]
    pub command: Option<Command>,

    /// Agent command to supervise; everything after `--`
    #[arg(last = true, value_name = "COMMAND [ARGS...]")]
    pub agent: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scaffold a leash.toml policy file in the current directory
    Init,
    /// List available security profiles
    Profiles,
    /// Check platform support and environment health
    Doctor,
}

impl Command {
    pub fn run(&self) -> Result<()> {
        match self {
            Command::Init => init_policy_file(),
            Command::Profiles => {
                println!("available profiles:");
                println!("  default  read ./, deny secret paths, allow LLM API hosts only");
                Ok(())
            }
            Command::Doctor => doctor(),
        }
    }
}

const POLICY_TEMPLATE: &str = r#"# leash security policy

[[fs_rules]]
action = "allow_read"
path = "./"

[[fs_rules]]
action = "deny_all"
path = "~/.ssh"

[[fs_rules]]
action = "deny_all"
path = "~/.aws"

[[fs_rules]]
action = "deny_all"
path = ".env*"

[[net_rules]]
action = "allow_outbound"
target = "api.openai.com:443"

[[net_rules]]
action = "allow_outbound"
target = "api.anthropic.com:443"

[[net_rules]]
action = "allow_outbound"
target = "localhost:*"

[[net_rules]]
action = "deny_all_outbound"

[[net_rules]]
action = "deny_all_inbound"
"#;

fn init_policy_file() -> Result<()> {
    let path = std::path::Path::new("leash.toml");
    if path.exists() {
        anyhow::bail!("leash.toml already exists in this directory");
    }
    std::fs::write(path, POLICY_TEMPLATE)?;
    println!("wrote {}", path.display());
    Ok(())
}

fn doctor() -> Result<()> {
    println!("platform : {}", std::env::consts::OS);
    println!("arch     : {}", std::env::consts::ARCH);

    let isolation = if cfg!(target_os = "linux") {
        "namespaces + ptrace (planned)"
    } else if cfg!(target_os = "macos") {
        "sandbox-exec (planned)"
    } else {
        "unsupported"
    };
    println!("isolation: {isolation}");

    let home = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"));
    match home {
        Some(home) => println!("home     : {}", home.to_string_lossy()),
        None => println!("home     : not detected"),
    }

    Ok(())
}
