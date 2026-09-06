//! One-liner plugin installers for AI agent environments (Claude Code, OpenCode, etc.).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use clap::Subcommand;
use serde_json::{json, Value};

#[derive(Subcommand, Debug, Clone)]
pub enum PluginCommand {
    /// Install agent plugin configuration with automatic non-destructive backup
    Install {
        /// Agent or tool to integrate with (e.g. 'claude-code', 'opencode')
        target: String,
        /// Force install / reconfigure
        #[arg(short, long)]
        force: bool,
    },
    /// List supported agent integrations and plugin hooks
    List,
}

pub fn run_cli(cmd: &PluginCommand) -> Result<()> {
    match cmd {
        PluginCommand::Install { target, force: _ } => install_plugin(target),
        PluginCommand::List => list_plugins(),
    }
}

pub fn list_plugins() -> Result<()> {
    println!("Supported Vetto agent plugins and integrations:");
    println!("  claude-code   Claude Code PreToolUse hook shim in ~/.claude/settings.json");
    println!("  opencode      OpenCode sandbox execution runner in ~/.config/opencode/config.json");
    println!("  vscode        VS Code workspace sandboxing tasks and extension");
    println!("  jetbrains     JetBrains IDE sandbox plugin");
    Ok(())
}

pub fn install_plugin(target: &str) -> Result<()> {
    match target.to_ascii_lowercase().as_str() {
        "claude-code" | "claude" => install_claude_code()?,
        "opencode" => install_opencode()?,
        other => {
            bail!("unknown plugin target '{other}'. Available: claude-code, opencode");
        }
    }
    Ok(())
}

fn get_home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context("Could not resolve home directory")
}

/// Recursively merges `source` into `target` preserving all non-conflicting fields.
pub fn deep_merge_json(target: &mut Value, source: &Value) {
    match (target, source) {
        (Value::Object(target_map), Value::Object(source_map)) => {
            for (key, val) in source_map {
                deep_merge_json(target_map.entry(key.clone()).or_insert(Value::Null), val);
            }
        }
        (target_val, source_val) => {
            *target_val = source_val.clone();
        }
    }
}

/// Creates a timestamped backup of the target file if it exists.
pub fn backup_file(path: &Path) -> Result<Option<PathBuf>> {
    if !path.exists() {
        return Ok(None);
    }
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_path = PathBuf::from(format!("{}.bak.{}", path.display(), timestamp));
    fs::copy(path, &backup_path)
        .with_context(|| format!("failed to create backup at {}", backup_path.display()))?;
    Ok(Some(backup_path))
}

pub fn install_claude_code() -> Result<()> {
    let home = get_home_dir()?;
    let claude_dir = home.join(".claude");
    fs::create_dir_all(&claude_dir)
        .with_context(|| format!("failed to create directory {}", claude_dir.display()))?;

    let settings_path = claude_dir.join("settings.json");
    let mut config: Value = if settings_path.exists() {
        let raw = fs::read_to_string(&settings_path)
            .with_context(|| format!("failed to read {}", settings_path.display()))?;
        serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if let Some(bak) = backup_file(&settings_path)? {
        println!("Backed up existing configuration to {}", bak.display());
    }

    let vetto_patch = json!({
        "hooks": {
            "PreToolUse": {
                "command": "vetto shim"
            }
        },
        "vetto": {
            "enabled": true,
            "version": "0.2.5",
            "managed": true
        }
    });

    deep_merge_json(&mut config, &vetto_patch);

    let updated_json = serde_json::to_string_pretty(&config)?;
    fs::write(&settings_path, updated_json.as_bytes())
        .with_context(|| format!("failed to write {}", settings_path.display()))?;

    println!(
        "Successfully installed Claude Code integration in {}",
        settings_path.display()
    );
    Ok(())
}

pub fn install_opencode() -> Result<()> {
    let home = get_home_dir()?;
    let config_dir = home.join(".config").join("opencode");
    fs::create_dir_all(&config_dir)
        .with_context(|| format!("failed to create directory {}", config_dir.display()))?;

    let config_path = config_dir.join("config.json");
    let mut config: Value = if config_path.exists() {
        let raw = fs::read_to_string(&config_path)
            .with_context(|| format!("failed to read {}", config_path.display()))?;
        serde_json::from_str(&raw).unwrap_or_else(|_| json!({}))
    } else {
        json!({})
    };

    if let Some(bak) = backup_file(&config_path)? {
        println!("Backed up existing configuration to {}", bak.display());
    }

    let vetto_patch = json!({
        "sandbox": {
            "command": "vetto",
            "args": ["--ci", "--"]
        },
        "vetto": {
            "enabled": true,
            "version": env!("CARGO_PKG_VERSION")
        }
    });

    deep_merge_json(&mut config, &vetto_patch);

    let updated_json = serde_json::to_string_pretty(&config)?;
    fs::write(&config_path, updated_json.as_bytes())
        .with_context(|| format!("failed to write {}", config_path.display()))?;

    println!(
        "Successfully installed OpenCode integration in {}",
        config_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_merge_json_preserves_existing_keys() {
        let mut target = json!({
            "existing_key": "safe_value",
            "user_preferences": {
                "theme": "dark",
                "custom_prompt": "hello"
            }
        });

        let patch = json!({
            "hooks": {
                "PreToolUse": {
                    "command": "vetto shim"
                }
            },
            "user_preferences": {
                "theme": "dark"
            }
        });

        deep_merge_json(&mut target, &patch);

        assert_eq!(target["existing_key"], "safe_value");
        assert_eq!(target["user_preferences"]["custom_prompt"], "hello");
        assert_eq!(target["user_preferences"]["theme"], "dark");
        assert_eq!(target["hooks"]["PreToolUse"]["command"], "vetto shim");
    }
}
