//! Async & cached npm registry version checking with 24-hour cache TTL and 2s timeout.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::parser::{parse_registry_version, SemVer};
use super::upgrade::{detect_install_method, InstallMethod};

pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60; // 24 hours
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(2);
pub const NPM_REGISTRY_LATEST_URL: &str = "https://registry.npmjs.org/@shledery/vetto/latest";
pub const NPM_REGISTRY_PKG_URL: &str = "https://registry.npmjs.org/@shledery/vetto";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionCache {
    pub latest_version: String,
    pub channel: String,
    pub checked_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateNotice {
    pub current_version: String,
    pub latest_version: String,
    pub channel: String,
    pub install_method: InstallMethod,
}

impl UpdateNotice {
    pub fn banner_message(&self) -> String {
        let upgrade_cmd = match self.install_method {
            InstallMethod::Npm => {
                if self.channel == "alpha" {
                    "npm i -g @shledery/vetto@alpha"
                } else {
                    "npm i -g @shledery/vetto"
                }
            }
            InstallMethod::Cargo => {
                if self.channel == "alpha" {
                    "cargo install vetto --version"
                } else {
                    "cargo install vetto"
                }
            }
            InstallMethod::Binary => "vetto upgrade",
        };

        format!(
            "vetto {} → {} available: {}",
            self.current_version, self.latest_version, upgrade_cmd
        )
    }
}

/// Resolves the version cache path (~/.vetto/cache/version.json).
pub fn resolve_cache_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    Some(home.join(".vetto").join("cache").join("version.json"))
}

/// Loads cached version information if valid and unexpired.
pub fn load_cache(cache_path: &Path, ttl_secs: u64) -> Option<VersionCache> {
    let content = fs::read_to_string(cache_path).ok()?;
    let cache: VersionCache = serde_json::from_str(&content).ok()?;

    let now_unix = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();

    if now_unix.saturating_sub(cache.checked_at_unix) < ttl_secs {
        Some(cache)
    } else {
        None
    }
}

/// Saves version information to cache path.
pub fn save_cache(cache_path: &Path, cache: &VersionCache) -> std::io::Result<()> {
    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(cache)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    fs::write(cache_path, data)
}

/// Performs a bounded curl fetch against the npm registry. Fails silently on any error.
pub fn fetch_registry_version(channel: &str, timeout: Duration) -> Option<String> {
    let url = if channel == "alpha" {
        NPM_REGISTRY_PKG_URL
    } else {
        NPM_REGISTRY_LATEST_URL
    };

    let mut cmd = Command::new("curl");
    cmd.arg("-s")
        .arg("--max-time")
        .arg(timeout.as_secs().max(1).to_string())
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }

    let body = String::from_utf8(output.stdout).ok()?;
    parse_registry_version(&body, channel)
}

/// Checks if a newer version is available, using cache when fresh.
pub fn check_version(
    current_version: &str,
    channel: &str,
    force_refresh: bool,
) -> Option<UpdateNotice> {
    let current_semver = SemVer::parse(current_version)?;
    let cache_path = resolve_cache_path();

    let mut latest_version_str = None;

    if !force_refresh {
        if let Some(ref path) = cache_path {
            if let Some(cache) = load_cache(path, CACHE_TTL_SECS) {
                if cache.channel == channel {
                    latest_version_str = Some(cache.latest_version);
                }
            }
        }
    }

    if latest_version_str.is_none() {
        if let Some(remote_ver) = fetch_registry_version(channel, CHECK_TIMEOUT) {
            if let Some(ref path) = cache_path {
                let now_unix = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);

                let cache = VersionCache {
                    latest_version: remote_ver.clone(),
                    channel: channel.to_string(),
                    checked_at_unix: now_unix,
                };
                let _ = save_cache(path, &cache);
            }
            latest_version_str = Some(remote_ver);
        }
    }

    let latest_str = latest_version_str?;
    let latest_semver = SemVer::parse(&latest_str)?;

    if latest_semver.is_newer_than(&current_semver) {
        let exe_path = std::env::current_exe().ok();
        let install_method = exe_path
            .as_deref()
            .map(detect_install_method)
            .unwrap_or(InstallMethod::Npm);

        Some(UpdateNotice {
            current_version: current_version.to_string(),
            latest_version: latest_str,
            channel: channel.to_string(),
            install_method,
        })
    } else {
        None
    }
}

/// Print version banner to stderr if update is available. Does NOT block startup.
pub fn print_banner_if_update_available(current_version: &str, channel: &str) {
    if let Some(notice) = check_version(current_version, channel, false) {
        eprintln!("{}", notice.banner_message());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_notice_banner_formatting() {
        let notice_npm = UpdateNotice {
            current_version: "0.2.5".to_string(),
            latest_version: "0.2.6".to_string(),
            channel: "stable".to_string(),
            install_method: InstallMethod::Npm,
        };
        assert_eq!(
            notice_npm.banner_message(),
            "vetto 0.2.5 → 0.2.6 available: npm i -g @shledery/vetto"
        );

        let notice_alpha = UpdateNotice {
            current_version: "0.2.5".to_string(),
            latest_version: "0.2.6-alpha.1".to_string(),
            channel: "alpha".to_string(),
            install_method: InstallMethod::Npm,
        };
        assert_eq!(
            notice_alpha.banner_message(),
            "vetto 0.2.5 → 0.2.6-alpha.1 available: npm i -g @shledery/vetto@alpha"
        );

        let notice_cargo = UpdateNotice {
            current_version: "0.2.5".to_string(),
            latest_version: "0.2.6".to_string(),
            channel: "stable".to_string(),
            install_method: InstallMethod::Cargo,
        };
        assert_eq!(
            notice_cargo.banner_message(),
            "vetto 0.2.5 → 0.2.6 available: cargo install vetto"
        );
    }

    #[test]
    fn test_cache_serialization_and_expiry() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_test_cache_{}", std::process::id()));
        let cache_file = temp_dir.join("version.json");

        let cache = VersionCache {
            latest_version: "0.2.6".to_string(),
            channel: "stable".to_string(),
            checked_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        save_cache(&cache_file, &cache).expect("save cache");
        let loaded = load_cache(&cache_file, 3600).expect("load valid cache");
        assert_eq!(loaded, cache);

        // Immediate expiry with ttl 0
        let expired = load_cache(&cache_file, 0);
        assert_eq!(expired, None);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
