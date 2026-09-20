//! Host environment detection for `vetto doctor` (WSL, devcontainer, Docker, Podman).

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentInfo {
    pub is_container: bool,
    pub is_wsl: bool,
    pub container_type: Option<String>,
    pub wsl_version: Option<String>,
    pub summary: String,
}

pub fn detect_environment() -> EnvironmentInfo {
    let mut is_container = false;
    let mut container_type = None;
    let mut is_wsl = false;
    let mut wsl_version = None;

    // 1. Container detection
    if Path::new("/.dockerenv").exists() {
        is_container = true;
        container_type = Some("Docker".to_string());
    } else if Path::new("/run/.containerenv").exists() {
        is_container = true;
        container_type = Some("Podman / OCI container".to_string());
    } else if std::env::var("REMOTE_CONTAINERS").is_ok() || std::env::var("DEVCONTAINER").is_ok() {
        is_container = true;
        container_type = Some("Devcontainer (VSCode / Codespaces)".to_string());
    } else if let Ok(cgroup_content) = std::fs::read_to_string("/proc/1/cgroup") {
        if cgroup_content.contains("docker") {
            is_container = true;
            container_type = Some("Docker".to_string());
        } else if cgroup_content.contains("containerd") {
            is_container = true;
            container_type = Some("Containerd".to_string());
        } else if cgroup_content.contains("podman") {
            is_container = true;
            container_type = Some("Podman".to_string());
        } else if cgroup_content.contains("kubepods") {
            is_container = true;
            container_type = Some("Kubernetes".to_string());
        }
    }

    // 2. WSL detection
    if std::env::var("WSL_DISTRO_NAME").is_ok() || std::env::var("WSL_INTEROP").is_ok() {
        is_wsl = true;
        wsl_version = Some("WSL2 / WSL".to_string());
    } else if let Ok(version_content) = std::fs::read_to_string("/proc/version") {
        let version_lower = version_content.to_lowercase();
        if version_lower.contains("microsoft-standard-wsl2") || version_lower.contains("wsl2") {
            is_wsl = true;
            wsl_version = Some("WSL2".to_string());
        } else if version_lower.contains("microsoft") || version_lower.contains("wsl") {
            is_wsl = true;
            wsl_version = Some("WSL".to_string());
        }
    }

    let summary = match (is_container, is_wsl) {
        (true, true) => format!(
            "Container ({}) running inside WSL ({})",
            container_type.as_deref().unwrap_or("generic"),
            wsl_version.as_deref().unwrap_or("WSL")
        ),
        (true, false) => format!(
            "Container ({})",
            container_type.as_deref().unwrap_or("generic")
        ),
        (false, true) => format!("WSL ({})", wsl_version.as_deref().unwrap_or("WSL")),
        (false, false) => "Native host".to_string(),
    };

    EnvironmentInfo {
        is_container,
        is_wsl,
        container_type,
        wsl_version,
        summary,
    }
}

/// Honest isolation-tier notice printed by `vetto doctor` on native Windows.
pub const WINDOWS_TIER3_ISOLATION_NOTICE: &str = "Windows operates under Tier 3 isolation (AppContainer LPAC + Job Objects). For Tier 1 full kernel Landlock/cgroups containment, run vetto inside WSL2.";

/// Honest cgroup-limit support status for the native Windows backend.
/// There is no cgroup surface on Windows, so the answer is always
/// `Unsupported` — reported with exit code 0 in `vetto doctor`, never a
/// panic or an `unwrap` on a missing controller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsCgroupLimitsStatus {
    Unsupported,
}

impl WindowsCgroupLimitsStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unsupported => "unsupported (Windows Tier 3 enforces limits via Job Objects; run inside WSL2 for Tier 1 cgroups v2)",
        }
    }
}

/// Returns the cgroup-limit support status for the native Windows backend.
/// Total function: no I/O, no `unwrap`, no panic paths.
pub fn windows_cgroup_limits_status() -> WindowsCgroupLimitsStatus {
    WindowsCgroupLimitsStatus::Unsupported
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_detect_runs_without_panic() {
        let env_info = detect_environment();
        assert!(!env_info.summary.is_empty());
    }

    #[test]
    fn windows_cgroup_limits_status_is_honest_unsupported() {
        assert_eq!(
            windows_cgroup_limits_status(),
            WindowsCgroupLimitsStatus::Unsupported
        );
        assert!(windows_cgroup_limits_status()
            .as_str()
            .contains("unsupported"));
        assert!(WINDOWS_TIER3_ISOLATION_NOTICE.contains("Tier 3"));
        assert!(WINDOWS_TIER3_ISOLATION_NOTICE.contains("WSL2"));
    }
}
