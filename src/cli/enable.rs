//! CLI subcommands `vetto enable <agent>` and `vetto disable <agent>`.
//!
//! Enables transparent zero-friction sandboxing for AI coding agents:
//! creates priority PATH shims that intercept agent commands and execute them
//! inside the Vetto sandbox under default zero-config policies.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::PathBuf;

use crate::cli::hook::{get_home_dir, get_shims_dir, HookScope};
use crate::cli::shell_env;
use crate::onboard::SUPPORTED_AGENTS;
use crate::policy::presets::agent_network_allowlist;
use crate::shim::registry::ShimRegistry;
use crate::shim::is_vetto_shim_content;

/// CLI arguments for `vetto enable`.
#[derive(clap::Args, Debug, Clone)]
pub struct EnableArgs {
    /// Name of the AI agent to wrap (e.g. claude, codex, opencode, windsurf, goose, cursor, aider)
    #[arg(value_name = "AGENT")]
    pub agent: Option<String>,

    /// Wrap all detected AI coding agents in PATH in a single command
    #[arg(long = "all", conflicts_with = "agent")]
    pub all: bool,

    /// Show status of wrapped agents
    #[arg(long)]
    pub status: bool,

    /// Overwrite existing non-Vetto binary or shim in the shims directory
    #[arg(long, short = 'f')]
    pub force: bool,

    /// Automatically repair shell configuration profiles with indestructible hooks
    #[arg(long)]
    pub fix: bool,

    /// Installation scope (global: ~/.vetto/shims, local: .vetto/shims)
    #[arg(long, value_enum, default_value = "global")]
    pub scope: HookScope,
}

/// CLI arguments for `vetto disable`.
#[derive(clap::Args, Debug, Clone)]
pub struct DisableArgs {
    /// Name of the AI agent to unwrap (e.g. claude, codex, opencode, windsurf, goose, cursor, aider)
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

    if args.all {
        return enable_all(args.force, args.fix, args.scope);
    }

    match &args.agent {
        None => list_agents(args.scope),
        Some(agent_raw) => {
            let agent_name = agent_raw.trim().to_lowercase();
            enable_agent_internal(&agent_name, args.force, args.fix, args.scope, false)
        }
    }
}

/// Enables transparent sandbox wrapping for all detected AI agents in PATH.
pub fn enable_all(force: bool, fix: bool, scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let mut installed_agents = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for &agent in &SUPPORTED_AGENTS {
        let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
        if !seen.insert(canon) {
            continue;
        }
        if let Ok((_real_name, real_bin)) = crate::onboard::find_real_agent_binary(canon) {
            installed_agents.push((canon, real_bin));
        }
    }

    if installed_agents.is_empty() {
        println!("vetto: no supported AI coding agents detected in PATH outside Vetto shims.");
        println!("Supported agents: {}", SUPPORTED_AGENTS.join(", "));
        return Ok(());
    }

    println!(
        "vetto: detected {} installed agent(s), enabling sandbox wrappers...",
        installed_agents.len()
    );
    println!();

    let mut newly_wrapped = Vec::new();
    let mut failed = Vec::new();

    for &(agent, ref real_bin) in &installed_agents {
        match enable_agent_internal(agent, force, fix, scope, true) {
            Ok(()) => {
                let net_allowlist = agent_network_allowlist(agent);
                let net_desc = if net_allowlist.is_empty() {
                    "offline (no outbound access)".to_string()
                } else {
                    net_allowlist.join(", ")
                };
                newly_wrapped.push((agent, real_bin.clone(), net_desc));
            }
            Err(err) => {
                failed.push((agent, err.to_string()));
            }
        }
    }

    if !newly_wrapped.is_empty() {
        let scope_str = match scope {
            HookScope::Global => "global",
            HookScope::Local => "local",
        };
        println!("Wrapped AI Agents ({} scope):", scope_str);
        println!(
            "  {:<12} {:<10} {:<30} NETWORK ALLOWLIST",
            "AGENT", "STATUS", "REAL BINARY"
        );
        println!("  {}", "-".repeat(75));
        for (agent, real_bin, net_desc) in &newly_wrapped {
            println!(
                "  {:<12} {:<10} {:<30} {}",
                agent,
                "wrapped",
                real_bin.display(),
                net_desc
            );
        }
        println!();
        println!("Successfully wrapped {} agent(s).", newly_wrapped.len());
    }

    if !failed.is_empty() {
        println!();
        println!("Failed to wrap {} agent(s):", failed.len());
        for (agent, err) in &failed {
            println!("  - {agent}: {err}");
        }
    }

    if let Some(path_val) = std::env::var_os("PATH") {
        let in_path = std::env::split_paths(&path_val).any(|p| p == shims_dir);
        if !in_path {
            println!();
            println!("To apply in your current terminal session immediately, prepend '~/.vetto/shims' to the FRONT of your PATH:");
            println!("  export PATH=\"{}:$PATH\"", shims_dir.display());
        }
    }

    Ok(())
}

/// Entrypoint for `vetto disable`.
pub fn run_disable(args: &DisableArgs) -> Result<()> {
    let agent_name = args.agent.trim().to_lowercase();
    disable_agent(&agent_name, args.scope)
}

/// Enables transparent sandbox wrapping for a specific agent without banner output.
pub fn enable_agent_silent(agent: &str, force: bool, scope: HookScope) -> Result<()> {
    enable_agent_internal(agent, force, false, scope, true)
}

/// Enables transparent sandbox wrapping for a specific agent.
pub fn enable_agent(agent: &str, force: bool, scope: HookScope) -> Result<()> {
    enable_agent_internal(agent, force, false, scope, false)
}

/// Enables transparent sandbox wrapping for a specific agent with explicit auto-repair control.
pub fn enable_agent_with_fix(agent: &str, force: bool, fix: bool, scope: HookScope) -> Result<()> {
    enable_agent_internal(agent, force, fix, scope, false)
}

fn enable_agent_internal(
    agent: &str,
    force: bool,
    fix: bool,
    scope: HookScope,
    silent: bool,
) -> Result<()> {
    // 1. Resolve the real host binary FIRST to verify it is installed and in PATH
    let (real_bin_name, real_bin) = crate::onboard::find_real_agent_binary(agent)?;

    let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);

    // 2. Prepare target shims directory
    let shims_dir = get_shims_dir(scope)?;
    fs::create_dir_all(&shims_dir)
        .with_context(|| format!("failed to create shims dir: {}", shims_dir.display()))?;

    let mut shim_names = vec![agent.to_string()];
    if canon != agent {
        shim_names.push(canon.to_string());
    }
    if !shim_names.contains(&real_bin_name) {
        shim_names.push(real_bin_name.clone());
    }

    // 3. Collision check: if a non-Vetto file already exists at any target location
    for name in &shim_names {
        let target_shim_path = shims_dir.join(name);
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
    }

    // 4. Create transparent shims
    let current_exe = std::env::current_exe().ok();
    ShimRegistry::create_shims(&shims_dir, &shim_names, current_exe.as_deref())?;

    // 5. Ensure shell environment integration is installed and up to date
    let home_dir = get_home_dir()?;
    if fix {
        let _ = shell_env::repair_shell_profiles(&shims_dir, &home_dir);
    } else {
        let shells = shell_env::detect_available_shells(&home_dir);
        for &shell in &shells {
            let status = shell_env::check_shell_hook_status(shell, &home_dir, &shims_dir);
            if !status.is_installed || force || !status.is_indestructible() {
                let _ = shell_env::install_shell_hook(shell, &shims_dir, &home_dir, force);
            }
        }
    }

    if !silent {
        let net_allowlist = agent_network_allowlist(canon);
        let net_desc = if net_allowlist.is_empty() {
            "offline (no outbound access)".to_string()
        } else {
            net_allowlist.join(", ")
        };

        let target_shim_path = shims_dir.join(agent);
        println!("vetto: successfully enabled sandbox wrapper for '{agent}'");
        println!("  real binary : {}", real_bin.display());
        println!("  shim path   : {}", target_shim_path.display());
        println!("  profile     : default + agent preset (zero-config)");
        println!("  network     : allowlisted ({net_desc})");
        println!();
        println!(
            "You can now run `{agent}` normally — under the hood it runs in the Vetto sandbox."
        );

        // Check if shims_dir is in current PATH or if an unshimmed binary shadows the shim
        if let Some(warning) =
            crate::doctor::agent_check::check_path_shadowing_with_fix(agent, Some(&shims_dir), fix)
        {
            println!();
            println!("{warning}");
        } else if let Some(path_val) = std::env::var_os("PATH") {
            let in_path = std::env::split_paths(&path_val).any(|p| p == shims_dir);
            if !in_path {
                println!();
                println!("To apply in your current terminal session immediately, prepend '~/.vetto/shims' to the FRONT of your PATH:");
                println!("  export PATH=\"{}:$PATH\"", shims_dir.display());
            }
        }
    }

    // Activation funnel milestone (issue #27): agent wrapped. Once-only.
    let _ = crate::telemetry::record_funnel_milestone("enable");

    Ok(())
}

/// Disables transparent sandbox wrapping for a specific agent.
pub fn disable_agent(agent: &str, scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);

    let mut to_remove = vec![agent.to_string()];
    if canon != agent {
        to_remove.push(canon.to_string());
    }
    for &cand in crate::onboard::agent_candidate_binaries(canon) {
        if !to_remove.iter().any(|c| c == cand) {
            to_remove.push(cand.to_string());
        }
    }

    let mut removed_count = 0;
    for name in &to_remove {
        let shim = shims_dir.join(name);
        let cmd = shims_dir.join(format!("{name}.cmd"));
        if shim.exists() {
            if !is_vetto_shim_content(&shim) {
                bail!(
                    "refusing to remove '{}': file exists but is not a Vetto shim",
                    shim.display()
                );
            }
            fs::remove_file(&shim)
                .with_context(|| format!("failed to remove shim: {}", shim.display()))?;
            removed_count += 1;
        }
        if cmd.exists() {
            let _ = fs::remove_file(&cmd);
        }
    }

    if removed_count == 0 {
        println!(
            "vetto: '{agent}' is not currently wrapped by Vetto (shim not found at {})",
            shims_dir.join(agent).display()
        );
        return Ok(());
    }

    println!("vetto: disabled sandbox wrapper for '{agent}' (removed {removed_count} shim(s))");
    println!("'{agent}' will now run unconfined as a standard host binary.");

    Ok(())
}

/// Lists all supported AI agents and their current installation / wrapped status.
pub fn list_agents(scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;

    println!("AI Coding Agents (vetto enable):");
    println!("{}", "-".repeat(60));

    let mut seen = std::collections::HashSet::new();
    for &agent in &SUPPORTED_AGENTS {
        let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
        if !seen.insert(canon) {
            continue;
        }
        let shim_path = shims_dir.join(canon);
        let is_wrapped = shim_path.exists() && is_vetto_shim_content(&shim_path);
        let real_bin = crate::onboard::find_real_agent_binary(canon)
            .ok()
            .map(|(_, p)| p);

        let (status_tag, detail) = if is_wrapped {
            let real_str = real_bin
                .clone()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "unknown".to_string());
            (
                "[wrapped]  ",
                format!("-> {real_str} (preset: default+agent)"),
            )
        } else if let Some(p) = real_bin {
            ("[installed]", format!("-> {} (not wrapped)", p.display()))
        } else {
            ("[not found]", "not detected in PATH".to_string())
        };

        println!("  {:<12} {:<12} {}", canon, status_tag, detail);
    }

    println!("{}", "-".repeat(60));
    println!("To enable sandboxing for an agent:");
    println!("  vetto enable <agent>");
    println!();
    println!("To enable sandboxing for all detected agents:");
    println!("  vetto enable --all");
    println!();
    println!("To disable sandboxing for an agent:");
    println!("  vetto disable <agent>");

    Ok(())
}

/// Displays status of all currently wrapped agents.
pub fn show_status(scope: HookScope) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
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
        if let Some(warning) = crate::doctor::check_path_shadowing(&w.name, Some(&shims_dir)) {
            println!("{warning}");
        }
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
    let mut seen = std::collections::HashSet::new();

    for &agent in &SUPPORTED_AGENTS {
        let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
        if !seen.insert(canon) {
            continue;
        }
        let shim_path = shims_dir.join(canon);
        let real_bin_opt = crate::onboard::find_real_agent_binary(canon)
            .ok()
            .map(|(_, p)| p);
        let is_canon_wrapped = shim_path.exists() && is_vetto_shim_content(&shim_path);

        let mut candidate_shim = None;
        for &cand in crate::onboard::agent_candidate_binaries(canon) {
            let p = shims_dir.join(cand);
            if p.exists() && is_vetto_shim_content(&p) {
                candidate_shim = Some(p);
                break;
            }
        }

        if is_canon_wrapped || candidate_shim.is_some() {
            let actual_shim = if is_canon_wrapped {
                shim_path
            } else {
                candidate_shim.unwrap()
            };
            wrapped.push(WrappedAgentInfo {
                name: canon.to_string(),
                shim_path: actual_shim,
                real_binary: real_bin_opt,
                preset: "default+agent",
                network_allowlist: agent_network_allowlist(canon),
            });
        }
    }

    Ok(wrapped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_LOCK: Mutex<()> = Mutex::new(());

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
            "vetto-enable-test-{name}-{}-{}",
            std::process::id(),
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
                assert!(!args.all);
                assert!(!args.status);
                assert!(!args.force);
                assert!(!args.fix);
                assert_eq!(args.scope, HookScope::Global);
            }
            _ => panic!("expected enable"),
        }

        let cli_all =
            TestCli::try_parse_from(["vetto", "enable", "--all"]).expect("parse enable --all");
        match cli_all.command {
            TestSubcommand::Enable(args) => {
                assert!(args.all);
                assert_eq!(args.agent, None);
                assert!(!args.status);
                assert!(!args.force);
                assert!(!args.fix);
                assert_eq!(args.scope, HookScope::Global);
            }
            _ => panic!("expected enable --all"),
        }

        // --all conflicts with positional agent
        assert!(TestCli::try_parse_from(["vetto", "enable", "--all", "claude"]).is_err());

        let cli_fix = TestCli::try_parse_from(["vetto", "enable", "--fix", "claude"])
            .expect("parse enable fix");
        match cli_fix.command {
            TestSubcommand::Enable(args) => {
                assert_eq!(args.agent.as_deref(), Some("claude"));
                assert!(args.fix);
            }
            _ => panic!("expected enable fix"),
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
        // Mutates process-global PATH: serialize under lock so parallel
        // tests resolving binaries never observe the fake bin_dir.
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    #[test]
    fn enable_agent_resolves_and_shims_aliases() {
        let _guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = temp_test_dir("alias-resolution");

        // Write a mock binary for claude-code (NOT claude) in a fake PATH
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).unwrap();
        let mock_claude_code = bin_dir.join("claude-code");
        fs::write(&mock_claude_code, "#!/bin/sh\necho mock_claude_code\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&mock_claude_code).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&mock_claude_code, perms).unwrap();
        }

        let orig_path = std::env::var_os("PATH").unwrap();
        let mut new_path = std::env::split_paths(&orig_path).collect::<Vec<_>>();
        new_path.insert(0, bin_dir.clone());
        std::env::set_var("PATH", std::env::join_paths(new_path).unwrap());

        // Call find_real_agent_binary for "claude"
        let (bin_name, path) = crate::onboard::find_real_agent_binary("claude").unwrap();
        assert_eq!(bin_name, "claude-code");
        assert_eq!(path, mock_claude_code);

        // Restore PATH
        std::env::set_var("PATH", orig_path);
        let _ = fs::remove_dir_all(&dir);
    }
}
