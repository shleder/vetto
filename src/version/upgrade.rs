//! Self-upgrade command (`vetto upgrade`) with automatic installation method detection.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use super::checker::check_version;
use super::config::load_user_config;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InstallMethod {
    Npm,
    Cargo,
    Homebrew,
    Binary,
}

impl InstallMethod {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Homebrew => "homebrew",
            Self::Binary => "binary",
        }
    }
}

fn detect_from_path(p: &Path) -> InstallMethod {
    let path_str = p.to_string_lossy().to_lowercase();

    if path_str.contains("node_modules")
        || path_str.contains(".nvm")
        || path_str.contains("npm")
        || path_str.ends_with(".js")
    {
        InstallMethod::Npm
    } else if path_str.contains("homebrew")
        || path_str.contains("cellar")
        || path_str.contains("/opt/homebrew")
        || path_str.contains(".linuxbrew")
    {
        InstallMethod::Homebrew
    } else if path_str.contains(".cargo")
        || path_str.contains("/target/")
        || path_str.contains("\\target\\")
    {
        InstallMethod::Cargo
    } else {
        InstallMethod::Binary
    }
}

/// Detects how vetto was installed by inspecting its binary executable path.
pub fn detect_install_method(exe_path: &Path) -> InstallMethod {
    if let Ok(canon) = exe_path.canonicalize() {
        let m = detect_from_path(&canon);
        if m != InstallMethod::Binary {
            return m;
        }
    }
    detect_from_path(exe_path)
}

/// Displays clean changelog diff and release highlights.
fn display_changelog_diff(current_version: &str, latest_version: &str) {
    println!();
    println!("Release highlights for v{latest_version}:");
    println!("  • Automated self-updating via `vetto upgrade` across distribution channels (npm, cargo, brew, binary)");
    println!(
        "  • Non-blocking update notification banner cached in ~/.vetto/cache/update-check.json"
    );
    println!("  • Dedicated session audit inspector (`vetto audit [session_id]`) for Landlock, network & syscalls");
    println!("  • Full changelog: https://github.com/shleder/vetto/compare/v{current_version}...v{latest_version}");
    println!();
}

/// Executes the upgrade workflow.
pub fn run_upgrade(channel_opt: Option<&str>, check_only: bool, dry_run: bool) -> Result<()> {
    let user_config = load_user_config().unwrap_or_default();
    let channel = channel_opt.unwrap_or(user_config.channel.as_str()).trim();

    let current_version = env!("CARGO_PKG_VERSION");
    let exe_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("vetto"));
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

            display_changelog_diff(&update.current_version, &update.latest_version);

            if check_only {
                println!("Run 'vetto upgrade' to perform the upgrade.");
                return Ok(());
            }

            match update.install_method {
                InstallMethod::Npm => {
                    let pkg_target = if channel == "stable" {
                        "@shledery/vetto@latest".to_string()
                    } else {
                        format!("@shledery/vetto@{channel}")
                    };

                    let cmd_str = format!("npm install -g {pkg_target}");
                    if dry_run {
                        println!("[dry-run] Would execute: {cmd_str}");
                        return Ok(());
                    }

                    println!("Executing: {cmd_str}");
                    let status = Command::new("npm")
                        .args(["install", "-g", &pkg_target])
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
                    let cmd_str = if channel != "stable" {
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
                    if channel != "stable" {
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
                InstallMethod::Homebrew => {
                    let cmd_str = "brew upgrade vetto".to_string();
                    if dry_run {
                        println!("[dry-run] Would execute: {cmd_str}");
                        return Ok(());
                    }

                    println!("Executing: {cmd_str}");
                    let status = Command::new("brew")
                        .args(["upgrade", "vetto"])
                        .status()
                        .context("failed to invoke brew; ensure brew is in PATH")?;

                    if status.success() {
                        println!(
                            "Successfully upgraded vetto to v{} via Homebrew.",
                            update.latest_version
                        );
                        Ok(())
                    } else {
                        bail!("brew upgrade failed with status {status}");
                    }
                }
                InstallMethod::Binary => {
                    let (target, ext) = match (std::env::consts::OS, std::env::consts::ARCH) {
                        ("macos", "aarch64") => ("macos-aarch64", "tar.gz"),
                        ("macos", "x86_64") => ("macos-x86_64", "tar.gz"),
                        ("linux", "aarch64") => ("linux-aarch64", "tar.gz"),
                        ("linux", "x86_64") => ("linux-x86_64", "tar.gz"),
                        ("windows", "x86_64") => ("windows-x86_64", "zip"),
                        (os, arch) => {
                            println!(
                                "vetto was installed as a direct binary ({})\n\
                                 Automatic download not supported for {os}-{arch}.\n\
                                 Please download release v{} from:\n\
                                 https://github.com/shleder/vetto/releases/tag/v{}",
                                exe_path.display(),
                                update.latest_version,
                                update.latest_version
                            );
                            return Ok(());
                        }
                    };

                    let archive_url = format!(
                        "https://github.com/shleder/vetto/releases/download/v{}/vetto-{target}.{ext}",
                        update.latest_version
                    );

                    if dry_run {
                        println!(
                            "[dry-run] Would download binary from {archive_url} and atomically replace {}",
                            exe_path.display()
                        );
                        return Ok(());
                    }

                    println!("Downloading binary release from: {archive_url}");
                    perform_atomic_binary_upgrade(&exe_path, &archive_url, ext)?;
                    println!(
                        "Successfully upgraded vetto binary to v{}.",
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

/// Downloads release archive and performs atomic replacement of the current executable.
fn perform_atomic_binary_upgrade(exe_path: &Path, archive_url: &str, ext: &str) -> Result<()> {
    let parent_dir = exe_path.parent().unwrap_or_else(|| Path::new("."));
    let temp_dir = tempfile_dir(parent_dir)?;

    // Download archive via curl
    let archive_path = temp_dir.join(format!("vetto_download.{ext}"));
    let status = Command::new("curl")
        .args([
            "-fsSL",
            "-A",
            "vetto-updater",
            "-o",
            archive_path.to_str().unwrap_or("vetto_download"),
            archive_url,
        ])
        .status()
        .context("failed to download release binary via curl")?;

    if !status.success() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!("download failed with status {status}");
    }

    // Extract archive
    let unpack_status = if ext == "zip" {
        // Built-in tar on Windows 10/11 handles zip, otherwise fall back to powershell
        let tar_res = Command::new("tar")
            .args([
                "-xf",
                archive_path.to_str().unwrap_or("vetto_download.zip"),
                "-C",
                temp_dir.to_str().unwrap_or("."),
            ])
            .status();
        match tar_res {
            Ok(s) if s.success() => s,
            _ => Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    &format!(
                        "Expand-Archive -Path '{}' -DestinationPath '{}' -Force",
                        archive_path.display(),
                        temp_dir.display()
                    ),
                ])
                .status()
                .context("failed to unpack zip archive via tar or powershell")?,
        }
    } else {
        Command::new("tar")
            .args([
                "-xzf",
                archive_path.to_str().unwrap_or("vetto_download.tar.gz"),
                "-C",
                temp_dir.to_str().unwrap_or("."),
            ])
            .status()
            .context("failed to unpack binary archive via tar")?
    };

    if !unpack_status.success() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!("archive unpack failed with status {unpack_status}");
    }

    let extracted_bin = if temp_dir.join("vetto.exe").exists() {
        temp_dir.join("vetto.exe")
    } else if temp_dir.join("vetto").exists() {
        temp_dir.join("vetto")
    } else if temp_dir.join("bin").join("vetto").exists() {
        temp_dir.join("bin").join("vetto")
    } else {
        find_binary_in_dir(&temp_dir).unwrap_or_else(|| temp_dir.join("vetto"))
    };

    if !extracted_bin.exists() {
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!("extracted archive did not contain 'vetto' executable");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&extracted_bin, std::fs::Permissions::from_mode(0o755));
    }

    #[cfg(windows)]
    {
        let old_backup = temp_dir.join("vetto.exe.old");
        let _ = std::fs::rename(exe_path, &old_backup);
    }

    // Atomic rename over target exe
    let rename_res = std::fs::rename(&extracted_bin, exe_path);
    if let Err(e) = rename_res {
        let _ = std::fs::remove_dir_all(&temp_dir);
        bail!(
            "failed to replace executable at {}: {e}. Try running with elevated permissions (e.g. sudo vetto upgrade).",
            exe_path.display()
        );
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(())
}

fn find_binary_in_dir(dir: &Path) -> Option<PathBuf> {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let fname = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                if fname == "vetto" || fname == "vetto.exe" {
                    return Some(path);
                }
            } else if path.is_dir() {
                if let Some(found) = find_binary_in_dir(&path) {
                    return Some(found);
                }
            }
        }
    }
    None
}

fn tempfile_dir(base: &Path) -> Result<PathBuf> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = base.join(format!(".vetto-upgrade-{}-{}", std::process::id(), nonce));
    if let Err(e) = std::fs::create_dir_all(&dir) {
        bail!(
            "failed to create temporary upgrade staging directory {}: {e}. Try running with elevated permissions (e.g. sudo vetto upgrade).",
            dir.display()
        );
    }
    Ok(dir)
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
            detect_install_method(Path::new("/opt/homebrew/bin/vetto")),
            InstallMethod::Homebrew
        );
        assert_eq!(
            detect_install_method(Path::new("/usr/local/Cellar/vetto/0.2.11/bin/vetto")),
            InstallMethod::Homebrew
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
