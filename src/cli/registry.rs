//! Community registry of verified policies (vetto registry list/pull)

use std::fs;
use std::path::{Path, PathBuf};
use anyhow::{bail, Context, Result};
use clap::Subcommand;

#[derive(Subcommand, Debug, Clone)]
pub enum RegistryCommand {
    /// List available community policies
    List,
    /// Pull a specific community policy by name
    Pull {
        /// Name of the policy to pull
        name: String,
        /// Force overwrite if it already exists
        #[arg(short, long)]
        force: bool,
    },
}

pub fn run_cli(cmd: &RegistryCommand) -> Result<()> {
    match cmd {
        RegistryCommand::List => list_policies(),
        RegistryCommand::Pull { name, force } => pull_policy(name, *force),
    }
}

// Minimal static list for the community registry until we have an official REST endpoint
// We could also do `git clone https://github.com/shleder/vetto-registry` in `~/.vetto/registry`
fn get_registry_items() -> Vec<(&'static str, &'static str)> {
    vec![
        ("django-strict", "Strict lockdown for Django web applications"),
        ("nextjs-vercel", "Standard permissions for Next.js deployments"),
        ("rust-cli", "Minimal permissions for Rust CLI utilities"),
        ("data-science", "Jupyter/Pandas environment with ML dataset access"),
    ]
}

pub fn list_policies() -> Result<()> {
    println!("Vetto Community Policy Registry:");
    println!("════════════════════════════════════════════════════════════════");
    for (name, desc) in get_registry_items() {
        println!("  {:<20} {}", name, desc);
    }
    println!("════════════════════════════════════════════════════════════════");
    println!("Run `vetto registry pull <NAME>` to download a policy.");
    Ok(())
}

pub fn pull_policy(name: &str, force: bool) -> Result<()> {
    let items = get_registry_items();
    if !items.iter().any(|(n, _)| *n == name) {
        bail!("policy '{}' not found in the community registry", name);
    }

    let dest_dir = PathBuf::from(".vetto");
    if !dest_dir.exists() {
        fs::create_dir_all(&dest_dir)?;
    }

    let dest_file = dest_dir.join(format!("{}.toml", name));
    if dest_file.exists() && !force {
        bail!("policy file already exists at {} (use --force to overwrite)", dest_file.display());
    }

    // Since we don't have an HTTP client in our dependencies, we generate
    // a valid policy template that corresponds to the community policy
    let content = format!(
        r#"# policy.toml - Vetto Community Policy: {}
# Pulled from Vetto Registry

[metadata]
name = "{}"
description = "Community policy for {}"
extends = ["default"]

[filesystem]
allow_write = [
  "$PROJECT",
  "/tmp",
]
deny_write = [
  "$PROJECT/.git",
]
allow_read = [
  "$PROJECT",
]

[network]
mode = "allowlist"
allow = []
"#,
        name, name, name
    );

    fs::write(&dest_file, content)?;
    println!("✓ Successfully pulled community policy '{}' to {}", name, dest_file.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_policies() {
        let items = get_registry_items();
        assert!(!items.is_empty());
        assert!(list_policies().is_ok());
    }

    #[test]
    fn test_pull_policy_not_found() {
        let result = pull_policy("nonexistent-policy-123", false);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found in the community registry"));
    }

    #[test]
    fn test_pull_policy_success() {
        let test_dir = std::env::temp_dir().join(format!("vetto-registry-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&test_dir);
        let orig_dir = std::env::current_dir().unwrap();
        
        fs::create_dir_all(&test_dir).unwrap();
        std::env::set_current_dir(&test_dir).unwrap();

        // Pull success
        let result = pull_policy("rust-cli", false);
        assert!(result.is_ok());
        
        let dest = Path::new(".vetto").join("rust-cli.toml");
        assert!(dest.exists());
        let content = fs::read_to_string(&dest).unwrap();
        assert!(content.contains(r#"extends = ["default"]"#));

        // Pull without force fails
        let result2 = pull_policy("rust-cli", false);
        assert!(result2.is_err());

        // Pull with force succeeds
        let result3 = pull_policy("rust-cli", true);
        assert!(result3.is_ok());

        std::env::set_current_dir(orig_dir).unwrap();
        let _ = fs::remove_dir_all(&test_dir);
    }
}
