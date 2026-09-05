//! Global user configuration loader (~/.vetto/config.toml).

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};

fn default_channel() -> String {
    "stable".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserConfig {
    #[serde(default = "default_channel")]
    pub channel: String,
    #[serde(default)]
    pub telemetry: bool,
    #[serde(default)]
    pub telemetry_endpoint: String,
    /// Opt-in background self-update (default off: a security tool must not
    /// mutate itself silently). Env `VETTO_AUTO_UPDATE=1` enables,
    /// `VETTO_NO_SELF_UPDATE=1` (or CI) always disables.
    /// v1 scope: direct-binary installs (npm/cargo/brew stay with their
    /// package managers and keep showing the banner instead).
    #[serde(default)]
    pub auto_update: bool,
}

impl Default for UserConfig {
    fn default() -> Self {
        Self {
            channel: default_channel(),
            telemetry: false,
            telemetry_endpoint: String::new(),
            auto_update: false,
        }
    }
}

pub fn resolve_config_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    Some(home.join(".vetto").join("config.toml"))
}

pub fn load_user_config() -> Result<UserConfig> {
    let mut config = if let Some(path) = resolve_config_path() {
        if path.exists() {
            load_config_from_file(&path)?
        } else {
            UserConfig::default()
        }
    } else {
        UserConfig::default()
    };

    // Environment variables override config file values if set
    if let Ok(ch) = std::env::var("VETTO_CHANNEL") {
        if !ch.trim().is_empty() {
            config.channel = ch.trim().to_string();
        }
    }

    if let Ok(tel) = std::env::var("VETTO_TELEMETRY") {
        match tel.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => config.telemetry = true,
            "0" | "false" | "no" | "off" => config.telemetry = false,
            _ => {}
        }
    }

    if let Ok(endpoint) = std::env::var("VETTO_TELEMETRY_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            config.telemetry_endpoint = endpoint.trim().to_string();
        }
    }

    if let Ok(au) = std::env::var("VETTO_AUTO_UPDATE") {
        match au.trim().to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => config.auto_update = true,
            "0" | "false" | "no" | "off" => config.auto_update = false,
            _ => {}
        }
    }

    // Kill-switch wins over everything, including the config file. CI
    // environments must never self-mutate: builds have to stay reproducible.
    if std::env::var("VETTO_NO_SELF_UPDATE").is_ok() || std::env::var("CI").is_ok() {
        config.auto_update = false;
    }

    Ok(config)
}

/// Effective auto-update decision for the current process.
pub fn auto_update_enabled(config: &UserConfig) -> bool {
    if std::env::var("VETTO_NO_SELF_UPDATE").is_ok() || std::env::var("CI").is_ok() {
        return false;
    }
    config.auto_update
}

pub fn load_config_from_file(path: &Path) -> Result<UserConfig> {
    let content = fs::read_to_string(path)?;
    let parsed: UserConfig = toml::from_str(&content)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_config_defaults() {
        let cfg = UserConfig::default();
        assert_eq!(cfg.channel, "stable");
        assert!(!cfg.telemetry);
        assert!(cfg.telemetry_endpoint.is_empty());
        // Security default: a sandbox never self-mutates unless asked.
        assert!(!cfg.auto_update);
    }

    #[test]
    fn test_user_config_toml_parsing() {
        let toml_str = r#"
channel = "alpha"
telemetry = true
telemetry_endpoint = "https://telemetry.example.com/api/v1/report"
auto_update = true
"#;
        let parsed: UserConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(parsed.channel, "alpha");
        assert!(parsed.telemetry);
        assert_eq!(
            parsed.telemetry_endpoint,
            "https://telemetry.example.com/api/v1/report"
        );
        assert!(parsed.auto_update);
    }
}
