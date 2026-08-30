//! Fully-parsed runtime configuration derived from the CLI and global config hierarchy.
//!
//! Configuration Precedence Hierarchy:
//! 1. Global defaults: `~/.vetto/config.toml` (or `~/.config/vetto/config.toml`)
//! 2. Project policy defaults: `./policy.toml`, `./.vetto/policy.toml`, or `vetto.toml`
//! 3. Explicit CLI flags and runtime overrides (strictest wins / explicit overrides default)

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::Deserialize;

use crate::cli::Cli;
use crate::policy::presets::Preset;

#[derive(Debug, Clone)]
pub enum NetMode {
    /// Default. Enforced on every tier (netns on FULL, seccomp-BPF on FS-ONLY).
    Off,
    /// CONNECT-level domain allowlist via the unix-fd bridge relay.
    Allowlist(Vec<String>),
    /// CONNECT-level domain and exact-port allowlist via the unix-fd bridge
    /// relay. DNS is resolved and validated by the broker before connect.
    Strict(Vec<NetRule>),
    /// Interactive domain confirmation mode with per-session caching.
    Ask,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetRule {
    pub domain: String,
    pub port: u16,
}

impl NetMode {
    pub fn label(&self) -> String {
        match self {
            NetMode::Off => "off".into(),
            NetMode::Allowlist(domains) => format!("allowlist:{}", domains.join(",")),
            NetMode::Strict(rules) => format!(
                "strict:{}",
                rules
                    .iter()
                    .map(|rule| format!("{}:{}", rule.domain, rule.port))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            NetMode::Ask => "ask".into(),
        }
    }

    pub fn uses_relay(&self) -> bool {
        matches!(self, Self::Allowlist(_) | Self::Strict(_) | Self::Ask)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuiMode {
    /// Agent keeps its own TUI; vetto draws ONE status row on the last line.
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
    Sarif,
}

/// Global defaults loaded from `~/.vetto/config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalConfig {
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub net: Option<String>,
    #[serde(default)]
    pub tui: Option<String>,
    #[serde(default)]
    pub observe_seccomp: Option<bool>,
    #[serde(default)]
    pub jsonl: Option<String>,
    #[serde(default)]
    pub report: Option<String>,
    #[serde(default)]
    pub report_dir: Option<String>,
    #[serde(default)]
    pub report_retention: Option<usize>,
    #[serde(default)]
    pub report_max_age_secs: Option<u64>,
    #[serde(default)]
    pub fail_on_block: Option<u64>,
    #[serde(default)]
    pub git_ssh: Option<bool>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub limits: Option<String>,
    #[serde(default)]
    pub verify: Option<bool>,
    #[serde(default)]
    pub shadow: Option<bool>,
}

pub fn load_global_config_from_home(home: &Path) -> Option<GlobalConfig> {
    let dot_vetto = home.join(".vetto/config.toml");
    let xdg_cfg = if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(xdg).join("vetto/config.toml")
    } else {
        home.join(".config/vetto/config.toml")
    };

    let path = if dot_vetto.is_file() {
        Some(dot_vetto)
    } else if xdg_cfg.is_file() {
        Some(xdg_cfg)
    } else {
        None
    };

    let path = path?;
    let text = std::fs::read_to_string(&path).ok()?;
    toml::from_str(&text).ok()
}

pub fn load_global_config() -> Option<GlobalConfig> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    load_global_config_from_home(&home)
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub profile: String,
    pub preset: Option<Preset>,
    pub policy_path: Option<PathBuf>,
    pub net: NetMode,
    pub tui: TuiMode,
    pub observe_seccomp: bool,
    pub jsonl_path: Option<PathBuf>,
    pub report_formats: Vec<ReportFormat>,
    pub report_dir: Option<PathBuf>,
    pub report_auto_cleanup: bool,
    pub report_retention: Option<usize>,
    pub report_max_age_secs: Option<u64>,
    pub fail_on_block: Option<u64>,
    pub git_ssh: bool,
    pub notify: bool,
    pub otel_endpoint: Option<String>,
    pub session_timeout: Option<std::time::Duration>,
    pub auto_timeout_requested: bool,
    pub system_log: bool,
    pub limits_spec: Option<String>,
    pub verify_preflight: bool,
    pub shadow: bool,
    pub dry_run: bool,
    pub ci: bool,
    pub agent_preset: Option<String>,
    pub deny_glob: Vec<String>,
    pub git_guard: bool,
    pub snapshot: bool,
    pub auto_deny_secrets: bool,
    pub agent: Vec<String>,
}

impl RunConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self> {
        let global = load_global_config().unwrap_or_default();
        Self::from_cli_with_global(cli, &global)
    }

    pub fn from_cli_with_global(cli: &Cli, global: &GlobalConfig) -> Result<Self> {
        let raw_net = cli
            .net
            .as_deref()
            .or(global.net.as_deref())
            .unwrap_or("off");
        let net = parse_net_mode(raw_net)?;

        let git_ssh = cli.git_ssh || global.git_ssh.unwrap_or(false);
        if git_ssh && !net.uses_relay() {
            bail!("--git-ssh requires --net=allowlist:... or --net=strict:...");
        }

        let fail_on_block = cli.fail_on_block.or(global.fail_on_block);
        if fail_on_block == Some(0) {
            bail!("--fail-on-block threshold must be greater than zero");
        }

        let report_auto_cleanup = !cli.no_report_auto_cleanup;
        let report_retention = cli
            .report_retention
            .or(global.report_retention)
            .or(Some(50));
        let report_max_age_secs = cli.report_max_age_secs.or(global.report_max_age_secs);

        let preset_str = cli.preset.as_deref().or(global.preset.as_deref());
        let preset = match preset_str {
            Some(p) => Some(Preset::parse(p)?),
            None => None,
        };

        let profile = if cli.profile != "default" {
            cli.profile.clone()
        } else if let Some(ref gp) = global.profile {
            gp.clone()
        } else {
            "default".to_string()
        };

        let raw_tui = if cli.tui != "statusline" {
            cli.tui.as_str()
        } else if let Some(ref gt) = global.tui {
            gt.as_str()
        } else {
            "statusline"
        };
        let mut tui = parse_tui_mode(raw_tui)?;
        if cli.ci && tui == TuiMode::Statusline {
            tui = TuiMode::None;
        }

        let timeout_str = cli.timeout.as_deref().or(global.timeout.as_deref());

        let limits_spec = match (cli.limits.as_deref(), global.limits.as_deref()) {
            (Some(cli_l), Some(glob_l)) => Some(format!("{glob_l},{cli_l}")),
            (Some(cli_l), None) => Some(cli_l.to_string()),
            (None, Some(glob_l)) => Some(glob_l.to_string()),
            (None, None) => None,
        };
        if let Some(spec) = &limits_spec {
            validate_limits_spec(spec)?;
        }

        let report_spec = cli.report.as_deref().or(global.report.as_deref());
        let mut report_formats = Vec::new();
        if let Some(fmts) = report_spec {
            for f in fmts.split(',') {
                report_formats.push(match f.trim().to_ascii_lowercase().as_str() {
                    "html" => ReportFormat::Html,
                    "md" | "markdown" => ReportFormat::Markdown,
                    "json" => ReportFormat::Json,
                    "sarif" => ReportFormat::Sarif,
                    other => {
                        bail!("unknown report format '{other}' (expected html, md, json, sarif)")
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

        let agent_preset = if cli.multi {
            None
        } else {
            match cli.agents.as_slice() {
                [] => detect_agent_preset(&cli.agent),
                [agent] if !agent.contains('=') && !agent.trim().is_empty() => {
                    Some(agent.clone())
                }
                [_] => bail!(
                    "single-agent --agent expects a preset name; NAME=PROGRAM is only valid with --multi"
                ),
                _ => bail!("single-agent mode accepts at most one --agent preset"),
            }
        };

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
            Some(raw) => Some(parse_session_timeout(raw)?),
            None => None,
        };

        Ok(Self {
            profile,
            preset,
            policy_path: cli.policy.as_ref().map(PathBuf::from),
            net,
            tui,
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
            session_timeout,
            auto_timeout_requested,
            system_log: cli.system_log,
            limits_spec,
            verify_preflight,
            shadow,
            dry_run: cli.dry_run,
            ci: cli.ci,
            agent_preset,
            deny_glob: cli.deny_glob.clone(),
            git_guard: cli.git_guard,
            snapshot: cli.snapshot,
            auto_deny_secrets: cli.auto_deny_secrets,
            agent: cli.agent.clone(),
        })
    }
}

/// Parse a network mode for both the single-agent and manifest frontends.
pub fn parse_net_mode(s: &str) -> Result<NetMode> {
    if s == "off" {
        return Ok(NetMode::Off);
    }
    if s == "ask" {
        return Ok(NetMode::Ask);
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
            validate_domain(d)
                .map_err(|e| anyhow::anyhow!("invalid domain in allowlist '{d}': {e}"))?;
        }
        return Ok(NetMode::Allowlist(domains));
    }
    if let Some(rest) = s.strip_prefix("strict:") {
        let mut rules = Vec::new();
        for item in rest.split(',') {
            let item = item.trim();
            let (domain, port_text) = item.rsplit_once(':').ok_or_else(|| {
                anyhow::anyhow!(
                    "strict rule '{item}' must use domain:port (for example github.com:443)"
                )
            })?;
            let domain = domain.trim().to_ascii_lowercase();
            validate_domain(&domain)
                .map_err(|e| anyhow::anyhow!("invalid domain in strict rule '{item}': {e}"))?;
            let port: u16 = port_text.trim().parse().map_err(|_| {
                anyhow::anyhow!("invalid port in strict rule '{item}': expected 1..65535")
            })?;
            if port == 0 {
                bail!("invalid port in strict rule '{item}': expected 1..65535");
            }
            let rule = NetRule { domain, port };
            if !rules.contains(&rule) {
                rules.push(rule);
            }
        }
        if rules.is_empty() {
            bail!("--net=strict requires at least one domain:port rule");
        }
        return Ok(NetMode::Strict(rules));
    }
    bail!(
        "invalid --net mode '{s}' (expected off, ask, allowlist:d1,d2,..., or strict:domain:port,... )"
    )
}

fn validate_domain(domain: &str) -> Result<()> {
    let domain = domain.trim_end_matches('.');
    if domain.is_empty() {
        bail!("domain is empty");
    }
    if domain.len() > 253 {
        bail!("domain is longer than 253 bytes");
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        bail!("IP literals are not accepted; use a DNS name");
    }
    let check_domain = if let Some(suffix) = domain.strip_prefix("*.") {
        if suffix.is_empty() {
            bail!("wildcard domain has no base domain");
        }
        suffix
    } else {
        domain
    };
    for label in check_domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("domain labels must be 1..63 bytes");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain labels cannot start or end with '-'");
        }
        if !label
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        {
            bail!("domain contains a character outside ASCII letters, digits, '-' and '.'");
        }
    }
    Ok(())
}

fn parse_tui_mode(s: &str) -> Result<TuiMode> {
    match s {
        "statusline" => Ok(TuiMode::Statusline),
        "full" => Ok(TuiMode::Full),
        "none" => Ok(TuiMode::None),
        other => bail!("invalid --tui mode '{other}' (expected statusline, full or none)"),
    }
}

/// Parse `--timeout` durations: bare seconds, `90s`, `30m`, `2h`.
pub fn parse_session_timeout(s: &str) -> Result<std::time::Duration> {
    let raw = s.trim();
    let (number, multiplier) = match raw.chars().last() {
        Some('s') => (&raw[..raw.len() - 1], 1u64),
        Some('m') => (&raw[..raw.len() - 1], 60),
        Some('h') => (&raw[..raw.len() - 1], 3600),
        _ => (raw, 1),
    };
    let seconds: u64 = number
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid --timeout '{s}' (expected e.g. 90s, 30m, 2h)"))?;
    if seconds == 0 {
        bail!("--timeout must be greater than zero");
    }
    Ok(std::time::Duration::from_secs(seconds * multiplier))
}

/// Coarse syntax check for `--limits`; full parsing happens where the spec
/// merges into the policy (see `policy::limits_spec`).
fn validate_limits_spec(spec: &str) -> Result<()> {
    if spec.trim().is_empty() {
        bail!("--limits requires at least one key=value pair");
    }
    for pair in spec.split(',') {
        let pair = pair.trim();
        if pair.split_once('=').map_or(true, |(key, value)| {
            key.trim().is_empty() || value.trim().is_empty()
        }) {
            bail!("invalid --limits entry '{pair}' (expected key=value, e.g. cpu=300,as=4g)");
        }
    }
    Ok(())
}

/// Auto-detect known agent preset from command invocation if not explicitly specified.
pub fn detect_agent_preset(command: &[String]) -> Option<String> {
    let first = command.first()?;
    let normalized = first.replace('\\', "/");
    let path = std::path::Path::new(&normalized);
    let stem = path.file_stem()?.to_str()?.to_ascii_lowercase();

    match stem.as_str() {
        "codex" | "codex-cli" => Some("codex".to_string()),
        "claude" | "claude-code" => Some("claude".to_string()),
        "cursor" | "cursor-server" => Some("cursor".to_string()),
        "aider" | "aider-chat" => Some("aider".to_string()),
        "cline" => Some("cline".to_string()),
        "copilot" | "github-copilot-cli" => Some("copilot".to_string()),
        "opencode" => Some("opencode".to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn config(args: &[&str]) -> Result<RunConfig> {
        let mut argv = vec!["vetto"];
        argv.extend_from_slice(args);
        RunConfig::from_cli(&Cli::try_parse_from(argv)?)
    }

    #[test]
    fn parses_strict_domain_port_rules() {
        let cfg = config(&["--net", "strict:GitHub.com:443,registry.npmjs.org:443"])
            .expect("strict config");
        assert_eq!(
            cfg.net.label(),
            "strict:github.com:443,registry.npmjs.org:443"
        );
    }

    #[test]
    fn strict_requires_exactly_one_valid_port() {
        assert!(config(&["--net", "strict:github.com"]).is_err());
        assert!(config(&["--net", "strict:github.com:0"]).is_err());
        assert!(config(&["--net", "strict:github.com:443:444"]).is_err());
        assert!(config(&["--net", "strict:127.0.0.1:443"]).is_err());
    }

    #[test]
    fn fail_on_block_without_value_defaults_to_one() {
        let cfg = config(&["--fail-on-block"]).expect("config");
        assert_eq!(cfg.fail_on_block, Some(1));
        assert!(config(&["--fail-on-block", "0"]).is_err());
    }

    #[test]
    fn cleanup_defaults_and_explicit_opt_out() {
        let cfg = config(&[]).expect("default config");
        assert!(cfg.report_auto_cleanup);
        assert_eq!(cfg.report_retention, Some(50));
        assert!(config(&["--report-retention", "3"]).is_ok());
        assert!(config(&["--report-max-age-secs", "60"]).is_ok());

        let cfg = config(&["--no-report-auto-cleanup", "--report-retention", "3"])
            .expect("cleanup opt-out");
        assert!(!cfg.report_auto_cleanup);
        assert_eq!(cfg.report_retention, Some(3));
    }

    #[test]
    fn git_ssh_requires_a_relay_network_mode() {
        assert!(config(&["--git-ssh"]).is_err());
        assert!(config(&["--git-ssh", "--net", "allowlist:github.com"]).is_ok());
    }

    #[test]
    fn timeout_parses_seconds_minutes_hours_and_rejects_zero() {
        let cfg = config(&["--timeout", "90s"]).expect("90s");
        assert_eq!(
            cfg.session_timeout,
            Some(std::time::Duration::from_secs(90))
        );
        let cfg = config(&["--timeout", "30m"]).expect("30m");
        assert_eq!(
            cfg.session_timeout,
            Some(std::time::Duration::from_secs(1800))
        );
        let cfg = config(&["--timeout", "2h"]).expect("2h");
        assert_eq!(
            cfg.session_timeout,
            Some(std::time::Duration::from_secs(7200))
        );
        let cfg = config(&["--timeout", "45"]).expect("bare seconds");
        assert_eq!(
            cfg.session_timeout,
            Some(std::time::Duration::from_secs(45))
        );
        assert!(config(&["--timeout", "0s"]).is_err());
        assert!(config(&["--timeout", "soon"]).is_err());
    }

    #[test]
    fn limits_spec_rejects_empty_or_malformed_pairs() {
        assert!(config(&["--limits", "cpu=300,as=4g"]).is_ok());
        assert!(config(&["--limits", ""]).is_err());
        assert!(config(&["--limits", "cpu"]).is_err());
        assert!(config(&["--limits", "cpu=,as=4g"]).is_err());
        assert!(config(&["--limits", "cpu=300,,nofile=1024"]).is_err());
    }

    #[test]
    fn verify_flag_reaches_run_config() {
        let cfg = config(&["--verify", "--", "/bin/true"]).expect("verify flag");
        assert!(cfg.verify_preflight);
        let cfg = config(&["--", "/bin/true"]).expect("default");
        assert!(!cfg.verify_preflight);
    }

    #[test]
    fn agent_flag_selects_a_preset_without_consuming_command_argv() {
        let cli = Cli::try_parse_from(["vetto", "--agent", "codex", "--", "codex"])
            .expect("agent preset and separator");
        let cfg = RunConfig::from_cli(&cli).expect("config");
        assert_eq!(cfg.agent_preset.as_deref(), Some("codex"));
        assert_eq!(cfg.agent, vec!["codex"]);
    }

    #[test]
    fn multi_agent_entries_are_not_single_agent_presets() {
        let cli = Cli::try_parse_from(["vetto", "--agent", "lint=/bin/true", "--", "/bin/true"])
            .expect("parse before mode validation");
        assert!(RunConfig::from_cli(&cli).is_err());
    }

    #[test]
    fn auto_detects_known_agents_from_command_without_agent_flag() {
        let cli =
            Cli::try_parse_from(["vetto", "--", "codex", "exec", "task"]).expect("parse command");
        let cfg = RunConfig::from_cli(&cli).expect("config");
        assert_eq!(cfg.agent_preset.as_deref(), Some("codex"));

        let cli = Cli::try_parse_from(["vetto", "--", "/usr/local/bin/claude-code", "-p", "hi"])
            .expect("parse command");
        let cfg = RunConfig::from_cli(&cli).expect("config");
        assert_eq!(cfg.agent_preset.as_deref(), Some("claude"));

        let cli = Cli::try_parse_from(["vetto", "--", "cursor-server", "--version"])
            .expect("parse command");
        let cfg = RunConfig::from_cli(&cli).expect("config");
        assert_eq!(cfg.agent_preset.as_deref(), Some("cursor"));

        let cli = Cli::try_parse_from(["vetto", "--", "python", "script.py"])
            .expect("parse non-agent command");
        let cfg = RunConfig::from_cli(&cli).expect("config");
        assert_eq!(cfg.agent_preset, None);
    }

    #[test]
    fn global_config_merges_under_cli_flags() {
        let global = GlobalConfig {
            profile: Some("audit".into()),
            preset: Some("paranoid".into()),
            net: Some("allowlist:api.anthropic.com".into()),
            fail_on_block: Some(5),
            shadow: Some(true),
            ..GlobalConfig::default()
        };

        // 1. Without CLI overrides, global config values are used
        let cli = Cli::try_parse_from(["vetto", "--", "/bin/true"]).unwrap();
        let cfg = RunConfig::from_cli_with_global(&cli, &global).unwrap();
        assert_eq!(cfg.profile, "audit");
        assert_eq!(cfg.preset, Some(Preset::Paranoid));
        assert_eq!(cfg.net.label(), "allowlist:api.anthropic.com");
        assert_eq!(cfg.fail_on_block, Some(5));
        assert!(cfg.shadow);

        // 2. CLI flags override global config values
        let cli_override = Cli::try_parse_from([
            "vetto",
            "--profile",
            "strict",
            "--preset",
            "yolo",
            "--net",
            "off",
            "--fail-on-block",
            "1",
            "--",
            "/bin/true",
        ])
        .unwrap();
        let cfg2 = RunConfig::from_cli_with_global(&cli_override, &global).unwrap();
        assert_eq!(cfg2.profile, "strict");
        assert_eq!(cfg2.preset, Some(Preset::Yolo));
        assert_eq!(cfg2.net.label(), "off");
        assert_eq!(cfg2.fail_on_block, Some(1));
    }
}
