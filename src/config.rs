//! Fully-parsed runtime configuration derived from the CLI.

use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::cli::Cli;

#[derive(Debug, Clone)]
pub enum NetMode {
    /// Default. Enforced on every tier (netns on FULL, seccomp-BPF on FS-ONLY).
    Off,
    /// CONNECT-level domain allowlist via the unix-fd bridge relay.
    Allowlist(Vec<String>),
}

impl NetMode {
    pub fn label(&self) -> String {
        match self {
            NetMode::Off => "off".into(),
            NetMode::Allowlist(domains) => format!("allowlist:{}", domains.join(",")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiMode {
    /// Agent keeps its own TUI; vetto renders one reserved bottom row.
    Statusline,
    /// vetto owns an alternate-screen dashboard; agent runs headless.
    Full,
    /// No terminal UI at all (CI / piping).
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    Html,
    Markdown,
    Json,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub profile: String,
    pub policy_path: Option<PathBuf>,
    pub net: NetMode,
    pub tui: TuiMode,
    pub observe_seccomp: bool,
    pub jsonl_path: Option<PathBuf>,
    pub report_formats: Vec<ReportFormat>,
    pub dry_run: bool,
    pub ci: bool,
    pub agent: Vec<String>,
}

impl RunConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let net = parse_net_mode(&cli.net)?;
        let mut tui = parse_tui_mode(&cli.tui)?;
        if cli.ci && tui == TuiMode::Statusline {
            tui = TuiMode::None;
        }

        let mut report_formats = Vec::new();
        if let Some(fmts) = &cli.report {
            for f in fmts.split(',') {
                report_formats.push(match f.trim().to_ascii_lowercase().as_str() {
                    "html" => ReportFormat::Html,
                    "md" | "markdown" => ReportFormat::Markdown,
                    "json" => ReportFormat::Json,
                    other => bail!("unknown report format '{other}' (expected html, md, json)"),
                });
            }
        }

        Ok(Self {
            profile: cli.profile.clone(),
            policy_path: cli.policy.as_ref().map(PathBuf::from),
            net,
            tui,
            observe_seccomp: cli.observe_seccomp,
            jsonl_path: cli.jsonl.as_ref().map(PathBuf::from),
            report_formats,
            dry_run: cli.dry_run,
            ci: cli.ci,
            agent: cli.agent.clone(),
        })
    }
}

fn parse_net_mode(s: &str) -> Result<NetMode> {
    if s == "off" {
        return Ok(NetMode::Off);
    }
    if let Some(rest) = s.strip_prefix("allowlist:") {
        let domains: Vec<String> = rest
            .split(',')
            .map(|d| d.trim().to_ascii_lowercase())
            .filter(|d| !d.is_empty())
            .collect();
        if domains.is_empty() {
            bail!("--net=allowlist requires at least one domain");
        }
        for d in &domains {
            if d.contains(|c: char| c.is_whitespace() || c == '/' || c == ':') {
                bail!("invalid domain in allowlist: '{d}'");
            }
        }
        return Ok(NetMode::Allowlist(domains));
    }
    bail!("invalid --net mode '{s}' (expected off or allowlist:d1,d2,...)");
}

fn parse_tui_mode(s: &str) -> Result<TuiMode> {
    match s {
        "statusline" => Ok(TuiMode::Statusline),
        "full" => Ok(TuiMode::Full),
        "none" => Ok(TuiMode::None),
        other => bail!("invalid --tui mode '{other}' (expected statusline, full or none)"),
    }
}
