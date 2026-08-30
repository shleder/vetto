//! Self-upgrade command (`vetto upgrade`) with automatic installation method detection.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::checker::check_version;
use super::config::load_user_config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallMethod {
    Npm,
    Cargo,
    Binary,
}

impl InstallMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Binary => "binary",
        }
    }
}

/// Detects how vetto was installed by inspecting its binary executable path.
pub fn detect_install_method(exe_path: &Path) -> InstallMethod {
    let path_str = exe_path.to_string_lossy().to_lowercase();

    if path_str.contains("node_modules")
        || path_str.contains(".nvm")
        || path_str.contains("npm")
        || path_str.ends_with(".js")
    {
        InstallMethod::Npm
    } else if path_str.contains(".cargo")
        || path_str.contains("/target/")
        || path_str.contains("\\target\\")
    {
        InstallMethod::Cargo
    } else {
        InstallMethod::Binary
    }
}

/// Executes the upgrade workflow.
pub fn run_upgrade(channel_opt: Option<&str>, check_only: bool, dry_run: bool) -> Result<()> {
    let user_config = load_user_config().unwrap_or_default();
    let channel = channel_opt.unwrap_or(user_config.channel.as_str()).trim();

    let current_version = env!("CARGO_PKG_VERSION");
    let exe_path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("vetto"));
    let method = detect_install_method(&exe_path);

    println!("vetto upgrade: checking updates on channel '{channel}'...");
    println!(
        "current version: v{current_version} (installed via {})",
        method.label()
    );

    let notice = check_version(current_version, channel, true);

    match notice {
        Some(update) => {
            println!(
                "Update available: v{} → v{} (channel: {})",
                update.current_version, update.latest_version, update.channel
            );

            if check_only {
                println!("Run 'vetto upgrade' to perform the upgrade.");
                return Ok(());
            }

            match update.install_method {
                InstallMethod::Npm => {
                    let pkg_target = if channel == "alpha" {
                        "@shledery/vetto@alpha"
                    } else {
                        "@shledery/vetto@latest"
                    };

                    let cmd_str = format!("npm install -g {pkg_target}");
                    if dry_run {
                        println!("[dry-run] Would execute: {cmd_str}");
                        return Ok(());
                    }

                    println!("Executing: {cmd_str}");
                    let status = Command::new("npm")
                        .args(["install", "-g", pkg_target])
                        .status()
                        .context("failed to invoke npm; ensure npm is available in PATH")?;

                    if status.success() {
                        println!(
                            "Successfully upgraded vetto to v{} via npm.",
                            update.latest_version
                        );
                        Ok(())
                    } else {
                        bail!("npm upgrade command failed with status {status}");
                    }
                }
                InstallMethod::Cargo => {
                    let cmd_str = if channel == "alpha" {
                        format!("cargo install vetto --version {}", update.latest_version)
                    } else {
                        "cargo install vetto --locked".to_string()
                    };

                    if dry_run {
                        println!("[dry-run] Would execute: {cmd_str}");
                        return Ok(());
                    }

                    println!("Executing: {cmd_str}");
                    let mut cmd = Command::new("cargo");
                    cmd.arg("install").arg("vetto");
                    if channel == "alpha" {
                        cmd.arg("--version").arg(&update.latest_version);
                    } else {
                        cmd.arg("--locked");
                    }

                    let status = cmd
                        .status()
                        .context("failed to invoke cargo; ensure cargo is in PATH")?;
                    if status.success() {
                        println!(
                            "Successfully upgraded vetto to v{} via cargo.",
                            update.latest_version
                        );
                        Ok(())
                    } else {
                        bail!("cargo install failed with status {status}");
                    }
                }
                InstallMethod::Binary => {
                    println!(
                        "vetto was installed as a direct binary ({})\n\
                         Please download release v{} from:\n\
                         https://github.com/shleder/vetto/releases/tag/v{}",
                        exe_path.display(),
                        update.latest_version,
                        update.latest_version
                    );
                    Ok(())
                }
            }
        }
        None => {
            println!("vetto is already up to date (v{current_version}).");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_install_method() {
        assert_eq!(
            detect_install_method(Path::new("/home/user/.cargo/bin/vetto")),
            InstallMethod::Cargo
        );
        assert_eq!(
            detect_install_method(Path::new(r"C:\Users\user\.cargo\bin\vetto.exe")),
            InstallMethod::Cargo
        );
        assert_eq!(
            detect_install_method(Path::new(
                "/usr/local/lib/node_modules/@shledery/vetto/native/linux-x64/vetto"
            )),
            InstallMethod::Npm
        );
        assert_eq!(
            detect_install_method(Path::new("/home/user/.nvm/versions/node/v20.0.0/bin/vetto")),
            InstallMethod::Npm
        );
        assert_eq!(
            detect_install_method(Path::new(
                r"C:\Users\user\AppData\Roaming\npm\node_modules\@shledery\vetto\native\win32-x64\vetto.exe"
            )),
            InstallMethod::Npm
        );
        assert_eq!(
            detect_install_method(Path::new("/opt/vetto/bin/vetto")),
            InstallMethod::Binary
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/bin/vetto")),
            InstallMethod::Binary
        );
    }
}
