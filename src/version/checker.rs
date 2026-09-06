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
pub const GITHUB_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/shleder/vetto/releases/latest";
pub const GITHUB_RELEASES_ALL_URL: &str = "https://api.github.com/repos/shleder/vetto/releases";

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
        format!(
            "Update available: {} -> {} (run 'vetto upgrade')",
            self.current_version, self.latest_version
        )
    }
}

/// Resolves the version cache path (~/.vetto/cache/update-check.json).
pub fn resolve_cache_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)?;
    Some(home.join(".vetto").join("cache").join("update-check.json"))
}

/// Resolves fallback legacy version cache path (~/.vetto/cache/version.json).
fn resolve_legacy_cache_path() -> Option<PathBuf> {
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

    if now_unix.abs_diff(cache.checked_at_unix) < ttl_secs {
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
    let data = serde_json::to_string_pretty(cache).map_err(std::io::Error::other)?;
    fs::write(cache_path, data)
}

/// Performs a bounded curl fetch against the npm registry or GitHub releases. Fails silently on any error.
pub fn fetch_registry_version(channel: &str, timeout: Duration) -> Option<String> {
    let npm_url = if channel != "stable" {
        NPM_REGISTRY_PKG_URL
    } else {
        NPM_REGISTRY_LATEST_URL
    };

    let mut cmd = Command::new("curl");
    cmd.arg("-s")
        .arg("-A")
        .arg("vetto-updater")
        .arg("--max-time")
        .arg(timeout.as_secs().max(1).to_string())
        .arg(npm_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    if let Ok(output) = cmd.output() {
        if output.status.success() {
            if let Ok(body) = String::from_utf8(output.stdout) {
                if let Some(ver) = parse_registry_version(&body, channel) {
                    return Some(ver);
                }
            }
        }
    }

    // Fallback: GitHub Releases API
    let gh_url = if channel != "stable" {
        GITHUB_RELEASES_ALL_URL
    } else {
        GITHUB_RELEASES_LATEST_URL
    };

    let mut gh_cmd = Command::new("curl");
    gh_cmd
        .arg("-s")
        .arg("-A")
        .arg("vetto-updater")
        .arg("--max-time")
        .arg(timeout.as_secs().max(1).to_string())
        .arg(gh_url)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());

    let gh_output = gh_cmd.output().ok()?;
    if !gh_output.status.success() {
        return None;
    }

    let gh_body = String::from_utf8(gh_output.stdout).ok()?;
    parse_registry_version(&gh_body, channel)
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
            } else if let Some(legacy_path) = resolve_legacy_cache_path() {
                if let Some(cache) = load_cache(&legacy_path, CACHE_TTL_SECS) {
                    if cache.channel == channel {
                        latest_version_str = Some(cache.latest_version);
                    }
                }
            }
        }
    }

    if latest_version_str.is_none() {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if let Some(remote_ver) = fetch_registry_version(channel, CHECK_TIMEOUT) {
            if let Some(ref path) = cache_path {
                let cache = VersionCache {
                    latest_version: remote_ver.clone(),
                    channel: channel.to_string(),
                    checked_at_unix: now_unix,
                };
                let _ = save_cache(path, &cache);
            }
            latest_version_str = Some(remote_ver);
        } else if !force_refresh {
            if let Some(ref path) = cache_path {
                if let Some(stale) = load_cache(path, u64::MAX) {
                    if stale.channel == channel {
                        latest_version_str = Some(stale.latest_version.clone());
                    }
                }
                let offline_cached_ver = latest_version_str
                    .clone()
                    .unwrap_or_else(|| current_version.to_string());
                let cache = VersionCache {
                    latest_version: offline_cached_ver,
                    channel: channel.to_string(),
                    checked_at_unix: now_unix.saturating_sub(CACHE_TTL_SECS.saturating_sub(3600)),
                };
                let _ = save_cache(path, &cache);
            }
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
        let notice = UpdateNotice {
            current_version: "0.2.10".to_string(),
            latest_version: "0.2.11".to_string(),
            channel: "stable".to_string(),
            install_method: InstallMethod::Npm,
        };
        assert_eq!(
            notice.banner_message(),
            "Update available: 0.2.10 -> 0.2.11 (run 'vetto upgrade')"
        );

        let notice_cargo = UpdateNotice {
            current_version: "0.2.10".to_string(),
            latest_version: "0.2.11".to_string(),
            channel: "stable".to_string(),
            install_method: InstallMethod::Cargo,
        };
        assert_eq!(
            notice_cargo.banner_message(),
            "Update available: 0.2.10 -> 0.2.11 (run 'vetto upgrade')"
        );
    }

    #[test]
    fn test_cache_serialization_and_expiry() {
        let temp_dir =
            std::env::temp_dir().join(format!("vetto_test_cache_{}", std::process::id()));
        let cache_file = temp_dir.join("update-check.json");

        let cache = VersionCache {
            latest_version: "0.2.11".to_string(),
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
