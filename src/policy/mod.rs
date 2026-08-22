//! Policy loading and representation.

pub mod defaults;

use std::path::Path;

use anyhow::{Context, Result};

use defaults::{FsRule, NetRule, PolicyFile};

#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub fs_rules: Vec<FsRule>,
    pub net_rules: Vec<NetRule>,
}

impl Policy {
    /// One-line human-readable summary of the active policy.
    pub fn summary(&self) -> String {
        format!(
            "profile '{}': {} filesystem rule(s), {} network rule(s)",
            self.name,
            self.fs_rules.len(),
            self.net_rules.len()
        )
    }
}

/// Load a named policy. Reads ./leash.toml when present, otherwise falls back
/// to the built-in defaults.
pub fn load(name: &str) -> Result<Policy> {
    let file = load_file()?;
    Ok(Policy {
        name: name.to_string(),
        fs_rules: file.fs_rules,
        net_rules: file.net_rules,
    })
}

fn load_file() -> Result<PolicyFile> {
    let path = Path::new("leash.toml");
    if !path.exists() {
        return Ok(defaults::default_policy());
    }
    let raw =
        std::fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    toml::from_str(&raw).with_context(|| format!("failed to parse {}", path.display()))
}
