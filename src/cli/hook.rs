//! CLI subcommands `vetto hook install` / `uninstall` / `status` (Step 14).
//!
//! Manages developer tooling interception shims, multi-shell profile hooks,
//! and Git core.hooksPath configuration.

use anyhow::{Context, Result};
use clap::Subcommand;
use std::path::{Path, PathBuf};

use crate::cli::git_hook::{self, GitHookStatus};
use crate::cli::shell_env::{self, ShellHookStatus, ShellKind};
use crate::shim::registry::{ShimInfo, ShimRegistry};

/// Scope of hook and shim installation.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HookScope {
    /// User-global scope (~/.vetto/shims)
    Global,
    /// Repository-local scope (.vetto/shims)
    Local,
}

/// Shell type selector for CLI arguments.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShellType {
    Bash,
    Zsh,
    Fish,
    #[value(name = "powershell", alias = "pwsh")]
    PowerShell,
    Cmd,
    All,
}

impl ShellType {
    pub fn to_shell_kinds(self, home_dir: &Path) -> Vec<ShellKind> {
        match self {
            ShellType::Bash => vec![ShellKind::Bash],
            ShellType::Zsh => vec![ShellKind::Zsh],
            ShellType::Fish => vec![ShellKind::Fish],
            ShellType::PowerShell => vec![ShellKind::PowerShell],
            ShellType::Cmd => vec![ShellKind::Cmd],
            ShellType::All => shell_env::detect_available_shells(home_dir),
        }
    }
}

/// CLI subcommand definition for `vetto hook`.
#[derive(Subcommand, Debug, Clone)]
pub enum HookCommand {
    /// Install Vetto transparent shims and shell environment hooks
    Install {
        /// Installation scope (global: ~/.vetto/shims, local: .vetto/shims)
        #[arg(long, value_enum, default_value = "global")]
        scope: HookScope,

        /// Target shells to configure (bash, zsh, fish, powershell, cmd, all)
        #[arg(long = "shell", value_enum, action = clap::ArgAction::Append)]
        shells: Vec<ShellType>,

        /// Custom toolchain binaries to generate shims for (defaults to ecosystem registry)
        #[arg(long = "shim", value_name = "BINARY", action = clap::ArgAction::Append)]
        shims: Vec<String>,

        /// Overwrite existing shims and force shell profile update
        #[arg(long, short = 'f')]
        force: bool,

        /// Configure Git transparent hooks (core.hooksPath)
        #[arg(long)]
        git: bool,
    },
    /// Uninstall Vetto transparent shims and restore shell environments
    Uninstall {
        /// Scope to uninstall from (global or local)
        #[arg(long, value_enum, default_value = "global")]
        scope: HookScope,

        /// Target shells to remove configuration from
        #[arg(long = "shell", value_enum, action = clap::ArgAction::Append)]
        shells: Vec<ShellType>,

        /// Remove Git transparent hooks
        #[arg(long)]
        git: bool,
    },
    /// Display status of Vetto shims, shell integrations, and Git hooks
    Status {
        /// Scope to check (global or local)
        #[arg(long, value_enum, default_value = "global")]
        scope: HookScope,

        /// Output status as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Overall hook and shim system status report.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HookStatusReport {
    pub scope: HookScope,
    pub shims_dir: PathBuf,
    pub shims_count: usize,
    pub active_shims: Vec<ShimInfo>,
    pub shell_hooks: Vec<ShellHookStatus>,
    pub git_hooks: GitHookStatus,
}

/// Resolves the shims directory based on the selected scope.
pub fn get_shims_dir(scope: HookScope) -> Result<PathBuf> {
    match scope {
        HookScope::Global => {
            let home = std::env::var_os("HOME")
                .or_else(|| std::env::var_os("USERPROFILE"))
                .map(PathBuf::from)
                .context("neither HOME nor USERPROFILE is set")?;
            Ok(home.join(".vetto").join("shims"))
        }
        HookScope::Local => {
            let cwd = std::env::current_dir().context("getcwd")?;
            Ok(cwd.join(".vetto").join("shims"))
        }
    }
}

/// Resolves the home directory.
pub fn get_home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("neither HOME nor USERPROFILE is set")
}

/// Executes the `vetto hook` CLI subcommands.
pub fn run_cli(command: &HookCommand) -> Result<()> {
    match command {
        HookCommand::Install {
            scope,
            shells,
            shims,
            force,
            git,
        } => handle_install(*scope, shells, shims, *force, *git),
        HookCommand::Uninstall {
            scope,
            shells,
            git,
        } => handle_uninstall(*scope, shells, *git),
        HookCommand::Status { scope, json } => handle_status(*scope, *json),
    }
}

fn handle_install(
    scope: HookScope,
    shells: &[ShellType],
    custom_shims: &[String],
    force: bool,
    install_git: bool,
) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let home_dir = get_home_dir()?;

    // Determine target binaries
    let binaries: Vec<String> = if !custom_shims.is_empty() {
        custom_shims.to_vec()
    } else if scope == HookScope::Local {
        let cwd = std::env::current_dir().context("getcwd")?;
        ShimRegistry::detect_for_project(&cwd)
    } else {
        ShimRegistry::default_binaries()
            .into_iter()
            .map(String::from)
            .collect()
    };

    let current_exe = std::env::current_exe().ok();
    let created_shims = ShimRegistry::create_shims(&shims_dir, &binaries, current_exe.as_deref())?;

    // Determine shells
    let target_shells: Vec<ShellKind> = if shells.is_empty() {
        shell_env::detect_available_shells(&home_dir)
    } else {
        let mut kinds = Vec::new();
        for st in shells {
            kinds.extend(st.to_shell_kinds(&home_dir));
        }
        kinds.sort_by_key(|k| k.name());
        kinds.dedup();
        kinds
    };

    let mut configured_profiles = Vec::new();
    for &shell in &target_shells {
        let profile = shell_env::install_shell_hook(shell, &shims_dir, &home_dir, force)?;
        configured_profiles.push((shell, profile));
    }

    let git_status = if install_git {
        let is_global = scope == HookScope::Global;
        let cwd = std::env::current_dir().ok();
        let base_dir = if is_global { None } else { cwd.as_deref() };
        let gdir = git_hook::install_git_hooks(is_global, base_dir, force)?;
        Some(gdir)
    } else {
        None
    };

    println!("vetto hook install: successfully configured environment");
    println!("  scope     : {:?}", scope);
    println!("  shims dir : {}", shims_dir.display());
    println!("  shims ({}) : {}", created_shims.len(), binaries.join(", "));
    println!("  configured shells:");
    for (shell, profile) in &configured_profiles {
        println!("    - {:<10} -> {}", shell.name(), profile.display());
    }
    if let Some(gdir) = git_status {
        println!("  git hooks : configured in {}", gdir.display());
    }
    println!();
    println!("To apply in your current shell session, run:");
    println!("  export PATH=\"{}:$PATH\"", shims_dir.display());

    Ok(())
}

fn handle_uninstall(
    scope: HookScope,
    shells: &[ShellType],
    uninstall_git: bool,
) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let home_dir = get_home_dir()?;

    let removed_shims = ShimRegistry::remove_shims(&shims_dir, None)?;

    let target_shells: Vec<ShellKind> = if shells.is_empty() {
        shell_env::detect_available_shells(&home_dir)
    } else {
        let mut kinds = Vec::new();
        for st in shells {
            kinds.extend(st.to_shell_kinds(&home_dir));
        }
        kinds.sort_by_key(|k| k.name());
        kinds.dedup();
        kinds
    };

    let mut cleaned_profiles = Vec::new();
    for &shell in &target_shells {
        if let Some(profile) = shell_env::uninstall_shell_hook(shell, &home_dir)? {
            cleaned_profiles.push((shell, profile));
        }
    }

    let git_unset = if uninstall_git {
        let is_global = scope == HookScope::Global;
        let cwd = std::env::current_dir().ok();
        let base_dir = if is_global { None } else { cwd.as_deref() };
        git_hook::uninstall_git_hooks(is_global, base_dir)?
    } else {
        false
    };

    println!("vetto hook uninstall: successfully cleaned environment");
    println!("  scope         : {:?}", scope);
    println!("  removed shims : {}", removed_shims.len());
    println!("  cleaned shells:");
    if cleaned_profiles.is_empty() {
        println!("    (no shell profiles contained active vetto blocks)");
    } else {
        for (shell, profile) in &cleaned_profiles {
            println!("    - {:<10} -> {}", shell.name(), profile.display());
        }
    }
    if uninstall_git {
        println!("  git hooks     : unset core.hooksPath ({})", if git_unset { "cleaned" } else { "was not set" });
    }

    Ok(())
}

fn handle_status(scope: HookScope, json: bool) -> Result<()> {
    let shims_dir = get_shims_dir(scope)?;
    let home_dir = get_home_dir()?;
    let is_global = scope == HookScope::Global;
    let cwd = std::env::current_dir().ok();
    let base_dir = if is_global { None } else { cwd.as_deref() };

    let active_shims = ShimRegistry::list_active_shims(&shims_dir)?;
    let mut shell_hooks = Vec::new();
    for &shell in ShellKind::all() {
        let st = shell_env::check_shell_hook_status(shell, &home_dir, &shims_dir);
        shell_hooks.push(st);
    }
    let git_hooks = git_hook::git_hooks_status(is_global, base_dir)?;

    let report = HookStatusReport {
        scope,
        shims_dir: shims_dir.clone(),
        shims_count: active_shims.len(),
        active_shims: active_shims.clone(),
        shell_hooks: shell_hooks.clone(),
        git_hooks: git_hooks.clone(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("vetto hook status ({:?} scope)", scope);
    println!("  shims directory : {}", shims_dir.display());
    println!("  active shims    : {} installed", active_shims.len());
    if !active_shims.is_empty() {
        let names: Vec<String> = active_shims.iter().map(|s| s.name.clone()).collect();
        println!("    binaries: {}", names.join(", "));
    }

    println!();
    println!("  shell integrations:");
    for hook in &shell_hooks {
        let status_str = if hook.is_installed {
            "✓ active"
        } else if hook.profile_exists {
            "✗ not configured"
        } else {
            "- profile missing"
        };
        println!("    {:<12} : {:<18} ({})", hook.shell.name(), status_str, hook.profile_path.display());
    }

    println!();
    println!("  git auto-wrapping:");
    println!("    configured    : {}", if git_hooks.is_configured { "✓ active" } else { "✗ inactive" });
    if let Some(ref path) = git_hooks.configured_hooks_path {
        println!("    core.hooksPath: {}", path);
    }
    println!("    hooks dir     : {}", git_hooks.hooks_dir.display());
    if !git_hooks.active_hooks.is_empty() {
        println!("    hooks present : {}", git_hooks.active_hooks.join(", "));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct TestCli {
        #[command(subcommand)]
        hook: HookCommand,
    }

    #[test]
    fn parses_hook_install_subcommand() {
        let cli = TestCli::try_parse_from(["vetto", "install", "--scope", "local", "--git", "--force"])
            .expect("parse hook install");
        match cli.hook {
            HookCommand::Install {
                scope,
                force,
                git,
                ..
            } => {
                assert_eq!(scope, HookScope::Local);
                assert!(force);
                assert!(git);
            }
            _ => panic!("expected install variant"),
        }
    }

    #[test]
    fn parses_hook_status_json_subcommand() {
        let cli = TestCli::try_parse_from(["vetto", "status", "--json"])
            .expect("parse hook status");
        match cli.hook {
            HookCommand::Status { scope, json } => {
                assert_eq!(scope, HookScope::Global);
                assert!(json);
            }
            _ => panic!("expected status variant"),
        }
    }
}
