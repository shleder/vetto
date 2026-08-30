//! Workspace profiles storage and dispatch.
//!
//! Stores named project presets (cwd, agent command, policy, net mode) under `~/.vetto/profiles/`.
//! Allows invoking saved profiles directly via `vetto <profile_name>`.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkspaceProfile {
    pub name: String,
    pub cwd: PathBuf,
    pub agent: Vec<String>,
    pub policy_path: Option<PathBuf>,
    pub net: String,
    pub profile: String,
    #[serde(default)]
    pub created_at: u64,
}

pub struct ProfileStorage {
    dir: PathBuf,
}

impl ProfileStorage {
    pub fn default_dir() -> Result<PathBuf> {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("failed to resolve HOME for profile storage")?;
        Ok(home.join(".vetto").join("profiles"))
    }

    pub fn new() -> Result<Self> {
        let dir = Self::default_dir()?;
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    pub fn with_dir(dir: PathBuf) -> Self {
        let _ = fs::create_dir_all(&dir);
        Self { dir }
    }

    pub fn profile_path(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.json"))
    }

    pub fn save(&self, profile: &WorkspaceProfile) -> Result<()> {
        let path = self.profile_path(&profile.name);
        let content = serde_json::to_string_pretty(profile)?;
        fs::write(path, content)?;
        Ok(())
    }

    pub fn load(&self, name: &str) -> Result<WorkspaceProfile> {
        let path = self.profile_path(name);
        if !path.exists() {
            bail!("workspace profile '{name}' not found");
        }
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed to read profile {}", path.display()))?;
        let profile = serde_json::from_str(&content)
            .with_context(|| format!("failed to parse profile {}", path.display()))?;
        Ok(profile)
    }

    pub fn list(&self) -> Result<Vec<WorkspaceProfile>> {
        let mut profiles = Vec::new();
        if !self.dir.exists() {
            return Ok(profiles);
        }
        for entry in fs::read_dir(&self.dir)?.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(profile) = serde_json::from_str::<WorkspaceProfile>(&content) {
                        profiles.push(profile);
                    }
                }
            }
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    pub fn delete(&self, name: &str) -> Result<()> {
        let path = self.profile_path(name);
        if !path.exists() {
            bail!("workspace profile '{name}' does not exist");
        }
        fs::remove_file(path)?;
        Ok(())
    }
}

/// Save current directory and CLI options as a workspace profile.
pub fn save_profile(
    name: &str,
    agent: Vec<String>,
    policy_path: Option<PathBuf>,
    net: Option<String>,
    profile_layer: Option<String>,
) -> Result<()> {
    let storage = ProfileStorage::new()?;
    let cwd = std::env::current_dir()?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let prof = WorkspaceProfile {
        name: name.to_string(),
        cwd,
        agent,
        policy_path,
        net: net.unwrap_or_else(|| "off".to_string()),
        profile: profile_layer.unwrap_or_else(|| "default".to_string()),
        created_at: now,
    };

    storage.save(&prof)?;
    println!("Saved workspace profile '{name}'.");
    Ok(())
}

/// List all saved workspace profiles.
pub fn list_profiles(json: bool) -> Result<()> {
    let storage = ProfileStorage::new()?;
    let profiles = storage.list()?;

    if json {
        println!("{}", serde_json::to_string_pretty(&profiles)?);
        return Ok(());
    }

    if profiles.is_empty() {
        println!("No saved workspace profiles found.");
        return Ok(());
    }

    println!("{:<15} {:<30} {:<10} {:<20}", "NAME", "CWD", "NET", "AGENT");
    println!("{}", "-".repeat(80));
    for p in &profiles {
        let agent_str = p.agent.join(" ");
        let cwd_str = p.cwd.display().to_string();
        let short_cwd = if cwd_str.len() > 28 {
            format!("...{}", &cwd_str[cwd_str.len() - 25..])
        } else {
            cwd_str
        };
        println!(
            "{:<15} {:<30} {:<10} {:<20}",
            p.name, short_cwd, p.net, agent_str
        );
    }

    Ok(())
}

/// Remove a workspace profile.
pub fn remove_profile(name: &str) -> Result<()> {
    let storage = ProfileStorage::new()?;
    storage.delete(name)?;
    println!("Removed workspace profile '{name}'.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_crud_lifecycle() {
        let temp = std::env::temp_dir().join(format!("vetto-prof-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        let storage = ProfileStorage::with_dir(temp.clone());

        let prof = WorkspaceProfile {
            name: "my-project".into(),
            cwd: PathBuf::from("/workspace/code"),
            agent: vec!["cargo".into(), "test".into()],
            policy_path: Some(PathBuf::from("policy.toml")),
            net: "allowlist:crates.io".into(),
            profile: "strict".into(),
            created_at: 1000,
        };

        storage.save(&prof).unwrap();
        let loaded = storage.load("my-project").unwrap();
        assert_eq!(loaded, prof);

        let list = storage.list().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "my-project");

        storage.delete("my-project").unwrap();
        assert!(storage.load("my-project").is_err());
        assert!(storage.list().unwrap().is_empty());

        let _ = fs::remove_dir_all(&temp);
    }
}
