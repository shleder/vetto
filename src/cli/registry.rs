//! Community registry of verified policies (vetto registry list/pull)

use std::fs;
use std::path::Path;
use anyhow::{bail, Result};
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

// Minimal static list for the community registry until an official REST endpoint exists.
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
        println!("  {name:<20} {desc}");
    }
    println!("════════════════════════════════════════════════════════════════");
    println!("Run `vetto registry pull <NAME>` to download a policy.");
    Ok(())
}

pub fn pull_policy(name: &str, force: bool) -> Result<()> {
    pull_policy_to(name, force, Path::new("."))
}

pub fn pull_policy_to(name: &str, force: bool, root: &Path) -> Result<()> {
    let items = get_registry_items();
    if !items.iter().any(|(n, _)| *n == name) {
        bail!("policy '{name}' not found in the community registry");
    }

    let dest_dir = root.join(".vetto");
    if !dest_dir.exists() {
        fs::create_dir_all(&dest_dir)?;
    }

    let dest_file = dest_dir.join(format!("{name}.toml"));
    if dest_file.exists() && !force {
        bail!(
            "policy file already exists at {} (use --force to overwrite)",
            dest_file.display()
        );
    }

    let content = format!(
        r#"# policy.toml - Vetto Community Policy: {name}
# Pulled from Vetto Registry

[metadata]
name = "{name}"
description = "Community policy for {name}"
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
"#
    );

    fs::write(&dest_file, content)?;
    println!(
        "✓ Successfully pulled community policy '{name}' to {}",
        dest_file.display()
    );
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
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("not found in the community registry")
        );
    }

    #[test]
    fn test_pull_policy_success() {
        let test_dir = std::env::temp_dir().join(format!(
            "vetto-registry-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&test_dir);
        fs::create_dir_all(&test_dir).unwrap();

        // Pull success
        let result = pull_policy_to("rust-cli", false, &test_dir);
        assert!(result.is_ok());

        let dest = test_dir.join(".vetto").join("rust-cli.toml");
        assert!(dest.exists());
        let content = fs::read_to_string(&dest).unwrap();
        assert!(content.contains(r#"extends = ["default"]"#));

        // Pull without force fails
        let result2 = pull_policy_to("rust-cli", false, &test_dir);
        assert!(result2.is_err());

        // Pull with force succeeds
        let result3 = pull_policy_to("rust-cli", true, &test_dir);
        assert!(result3.is_ok());

        let _ = fs::remove_dir_all(&test_dir);
    }
}
