//! CLI subcommands `vetto enable <agent>` and `vetto disable <agent>`.
//!
//! Enables transparent zero-friction sandboxing for AI coding agents:
//! creates priority PATH shims that intercept agent commands and execute them
//! inside the Vetto sandbox under default zero-config policies.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::cli::hook::{get_home_dir, get_shims_dir, HookScope};
use crate::cli::shell_env;
use crate::onboard::SUPPORTED_AGENTS;
use crate::policy::presets::agent_network_allowlist;
use crate::shim::registry::ShimRegistry;
use crate::shim::{find_real_binary, is_vetto_shim_content};

/// CLI arguments for `vetto enable`.
#[derive(clap::Args, Debug, Clone)]
pub struct EnableArgs {
    /// Name of the AI agent to wrap (e.g. claude, codex, gemini, aider, opencode, cursor)
    #[arg(value_name = "AGENT")]
    pub agent: Option<String>,

    /// Show status of wrapped agents
    #[arg(long)]
    pub status: bool,

    /// Overwrite existing non-Vetto binary or shim in the shims directory
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Installation scope (global: ~/.vetto/shims, local: .vetto/shims)
    #[arg(long, value_enum, default_value = "global")]
    pub scope: HookScope,
}

/// CLI arguments for `vetto disable`.
#[derive(clap::Args, Debug, Clone)]
pub struct DisableArgs {
    /// Name of the AI agent to unwrap (e.g. claude, codex, gemini, aider, opencode, cursor)
    #[arg(value_name = "AGENT")]
    pub agent: String,

    /// Scope to remove shim from (global or local)
    #[arg(long, value_enum, default_value = "global")]
    pub scope: HookScope,
}

/// Information about a wrapped agent.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WrappedAgentInfo {
    pub name: String,
    pub shim_path: PathBuf,
    pub real_binary: Option<PathBuf>,
    pub preset: &'static str,
    pub network_allowlist: Vec<String>,
}

/// Entrypoint for `vetto enable`.
pub fn run_enable(args: &EnableArgs) -> Result<()> {
    if args.status {
        return show_status(args.scope);
    }

    match &args.agent {
        None => list_agents(args.scope),
        Some(agent_raw) => {
            let agent_name = agent_raw.trim().to_lowercase();
            enable_agent(&agent_name, args.force, args.scope)
        }
    }
}

/// Entrypoint for `vetto disable`.
pub fn run_disable(args: &DisableArgs) -> Result<()> {
    let agent_name = args.agent.trim().to_lowercase();
    disable_agent(&agent_name, args.scope)
}

/// Enables transparent sandbox wrapping for a specific agent.
pub fn enable_agent(agent: &str, force: bool, scope: HookScope) -> Result<()> {
    // 1. Resolve the real host binary FIRST to verify it is installed and in PATH
    let real_bin = find_real_binary(agent).map_err(|_| {
        anyhow::anyhow!(
            "agent binary '{agent}' was not found in PATH outside Vetto shims.\n\
             Please install '{agent}' first or verify that it is present in your PATH.\n\
             Supported agents: {}",
            SUPPORTED_AGENTS.join(", ")
        )
    })?;

    // 2. Prepare target shims directory
    let shims_dir = get_shims_dir(scope)?;
    fs::create_dir_all(&shims_dir)
        .with_context(|| format!("failed to create shims dir: {}", shims_dir.display()))?;

    let target_shim_path = shims_dir.join(agent);

    // 3. Collision check: if a file already exists at target location
    if target_shim_path.exists() {
        let is_vetto = is_vetto_shim_content(&target_shim_path);
        if !is_vetto && !force {
            bail!(
                "target '{}' already exists and is not a Vetto shim.\n\
                 Refusing to overwrite without --force.",
                target_shim_path.display()
            );
        }
    }

    // 4. Create transparent shim
    let current_exe = std::env::current_exe().ok();
    let binaries = vec![agent.to_string()];
    ShimRegistry::create_shims(&shims_dir, &binaries, current_exe.as_deref())?;

    // 5. Ensure shell environment integration is installed
    let home_dir = get_home_dir()?;
    let shells = shell_env::detect_available_shells(&home_dir);
    for &shell in &shells {
        let status = shell_env::check_shell_hook_status(shell, &home_dir, &shims_dir);
        if !status.is_installed {
            let _ = shell_env::install_shell_hook(shell, &shims_dir, &home_dir, false);
        }
    }

    let net_allowlist = agent_network_allowlist(agent);
    let net_desc = if net_allowlist.is_empty() {
        "offline (no outbound access)".to_string()
    } else {
        net_allowlist.join(", ")
    };

    println!("vetto: successfully enabled sandbox wrapper for '{agent}'");
    println!("  real binary : {}", real_bin.display());
    println!("  shim path   : {}", target_shim_path.display());
    println!("  profile     : balanced (zero-config default)");
    println!("  network     : allowlisted ({net_desc})");
    println!();
    println!("You can now run `{agent}` normally — under the hood it runs in the Vetto sandbox.");

    // Check if shims_dir is in current PATH
    if let Some(path_val) = std::env::var_os("PATH") {
        let in_path = std::env::split_paths(&path_val).any(|p| p == shims_dir);
        if !in_path {
            println!();
            println!("To apply in your current terminal session immediately, run:");
            println!("  export PATH=\"{}:$PATH\"", shims_dir.display());
        }
    }

    Ok(())
}

/// Disables transparent sandbox wrapping for a specific agent.
pub fn disable_agent(agent: &str, scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let target_shim_path = shims_dir.join(agent);
    let target_cmd_path = shims_dir.join(format!("{agent}.cmd"));

    if !target_shim_path.exists() && !target_cmd_path.exists() {
        println!(
            "vetto: '{agent}' is not currently wrapped by Vetto (shim not found at {})",
            target_shim_path.display()
        );
        return Ok(());
    }

    if target_shim_path.exists() {
        if !is_vetto_shim_content(&target_shim_path) {
            bail!(
                "refusing to remove '{}': file exists but is not a Vetto shim",
                target_shim_path.display()
            );
        }
        fs::remove_file(&target_shim_path)
            .with_context(|| format!("failed to remove shim: {}", target_shim_path.display()))?;
    }

    if target_cmd_path.exists() {
        let _ = fs::remove_file(&target_cmd_path);
    }

    println!(
        "vetto: disabled sandbox wrapper for '{agent}' (removed {})",
        target_shim_path.display()
    );
    println!("'{agent}' will now run unconfined as a standard host binary.");

    Ok(())
}

/// Lists all supported AI agents and their current installation / wrapped status.
pub fn list_agents(scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;

    println!("AI Coding Agents (vetto enable):");
    println!("{}", "-".repeat(60));

    for &agent in &SUPPORTED_AGENTS {
        let shim_path = shims_dir.join(agent);
        let is_wrapped = shim_path.exists() && is_vetto_shim_content(&shim_path);
        let real_bin = find_real_binary(agent).ok();

        let (status_tag, detail) = if is_wrapped {
            let real_str = real_bin
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            ("[wrapped]  ", format!("-> {real_str} (preset: balanced)"))
        } else if let Some(p) = real_bin {
            ("[installed]", format!("-> {} (not wrapped)", p.display()))
        } else {
            ("[not found]", "not detected in PATH".to_string())
        };

        println!("  {:<10} {:<12} {}", agent, status_tag, detail);
    }

    println!("{}", "-".repeat(60));
    println!("To enable sandboxing for an agent:");
    println!("  vetto enable <agent>");
    println!();
    println!("To disable sandboxing for an agent:");
    println!("  vetto disable <agent>");

    Ok(())
}

/// Displays status of all currently wrapped agents.
pub fn show_status(scope: HookScope) -> Result<()> {
    let wrapped = get_wrapped_agents(scope)?;

    if wrapped.is_empty() {
        println!("No AI agents currently wrapped by Vetto ({scope:?} scope).");
        println!("Run `vetto enable` to see supported agents.");
        return Ok(());
    }

    println!("Wrapped AI Agents ({scope:?} scope):");
    println!(
        "{:<12} {:<30} {:<10} {:<20}",
        "AGENT", "REAL BINARY", "PRESET", "SHIM PATH"
    );
    println!("{}", "-".repeat(75));

    for w in &wrapped {
        let real_str = w
            .real_binary
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        println!(
            "{:<12} {:<30} {:<10} {:<20}",
            w.name,
            real_str,
            w.preset,
            w.shim_path.display()
        );
    }

    Ok(())
}

/// Discovers all currently wrapped agents in the specified scope.
pub fn get_wrapped_agents(scope: HookScope) -> Result<Vec<WrappedAgentInfo>> {
    let shims_dir = get_shims_dir(scope)?;
    if !shims_dir.exists() {
        return Ok(Vec::new());
    }

    let mut wrapped = Vec::new();

    for &agent in &SUPPORTED_AGENTS {
        let shim_path = shims_dir.join(agent);
        if shim_path.exists() && is_vetto_shim_content(&shim_path) {
            let real_bin = find_real_binary(agent).ok();
            wrapped.push(WrappedAgentInfo {
                name: agent.to_string(),
                shim_path,
                real_binary: real_bin,
                preset: "balanced",
                network_allowlist: agent_network_allowlist(agent),
            });
        }
    }

    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        command: TestSubcommand,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestSubcommand {
        Enable(EnableArgs),
        Disable(DisableArgs),
    }

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-enable-test-{name}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn parses_enable_and_disable_cli_args() {
        let cli = TestCli::try_parse_from(["vetto", "enable", "claude"]).expect("parse enable");
        match cli.command {
            TestSubcommand::Enable(args) => {
                assert_eq!(args.agent.as_deref(), Some("claude"));
                assert!(!args.status);
                assert!(!args.force);
                assert_eq!(args.scope, HookScope::Global);
            }
            _ => panic!("expected enable"),
        }

        let cli_status =
            TestCli::try_parse_from(["vetto", "enable", "--status"]).expect("parse enable status");
        match cli_status.command {
            TestSubcommand::Enable(args) => {
                assert!(args.status);
                assert_eq!(args.agent, None);
            }
            _ => panic!("expected enable status"),
        }

        let cli_disable =
            TestCli::try_parse_from(["vetto", "disable", "claude"]).expect("parse disable");
        match cli_disable.command {
            TestSubcommand::Disable(args) => {
                assert_eq!(args.agent, "claude");
                assert_eq!(args.scope, HookScope::Global);
            }
            _ => panic!("expected disable"),
        }
    }

    #[test]
    fn enable_creates_shim_and_disable_removes_it() {
        let dir = temp_test_dir("lifecycle");
        let shims_dir = dir.join("shims");

        // Write a mock binary for claude in a fake PATH
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let mock_claude = bin_dir.join("claude");
        fs::write(&mock_claude, "#!/bin/sh\necho mock_claude\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&mock_claude).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&mock_claude, perms).unwrap();
        }

        // Set PATH to contain bin_dir
        let original_path = std::env::var_os("PATH").unwrap();
        let mut new_path = std::env::split_paths(&original_path).collect::<Vec<_>>();
        new_path.insert(0, bin_dir.clone());
        std::env::set_var("PATH", std::env::join_paths(new_path).unwrap());

        // Create shim in shims_dir
        let created =
            ShimRegistry::create_shims(&shims_dir, &["claude".to_string()], None).unwrap();
        assert_eq!(created.len(), if cfg!(windows) { 2 } else { 1 });
        let shim_file = shims_dir.join("claude");
        assert!(shim_file.exists());
        assert!(is_vetto_shim_content(&shim_file));

        // Disable removes it
        let removed =
            ShimRegistry::remove_shims(&shims_dir, Some(&["claude".to_string()])).unwrap();
        assert!(!removed.is_empty());
        assert!(!shim_file.exists());

        // Restore PATH
        std::env::set_var("PATH", original_path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn collision_detection_rejects_non_vetto_file() {
        let dir = temp_test_dir("collision");
        let fake_file = dir.join("claude");
        fs::write(&fake_file, "custom non vetto binary content").unwrap();

        assert!(!is_vetto_shim_content(&fake_file));
        let _ = fs::remove_dir_all(&dir);
    }
}
