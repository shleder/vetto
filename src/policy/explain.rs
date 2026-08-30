//! `vetto policy explain`: print the effective policy after all layers merge.
//!
//! Read-only tooling command: it detects the enforcement tier, loads the
//! policy exactly like a supervised session does (same tier semantics, same
//! layer order), and prints text or JSON. It NEVER spawns a sandbox.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::NetMode;
use crate::sandbox::Backend;

use super::loader::{load_with_options, PolicyLoadOptions};
use super::types::{Policy, Tier};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathExplanation {
    pub path: String,
    pub access: String,
    pub writable: bool,
    pub readable: bool,
    pub denied: bool,
    pub rule_type: String,
    pub matching_rule: String,
    pub how_to_change: String,
}

/// Detect the tier, load the effective policy and print it as text or JSON.
pub fn run_cli(
    json: bool,
    why: Option<&Path>,
    profile: &str,
    policy_path: Option<&Path>,
    net: &NetMode,
) -> Result<()> {
    let backend = Backend::detect(net.clone(), false).ok();
    let tier = backend.as_ref().and_then(|b| b.tier());

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .context(
            "neither $HOME nor %USERPROFILE% is set; vetto needs it to resolve policy variables",
        )?;

    let options = PolicyLoadOptions {
        agent: None,
        include_project_policy: true,
        ..PolicyLoadOptions::default()
    };
    let policy = load_with_options(
        profile,
        policy_path,
        &project,
        &home,
        tier.unwrap_or(Tier::Full), // macOS: no FS-ONLY enumeration semantics
        &options,
    )?;

    if let Some(target_path) = why {
        let explanation = explain_why(&policy, target_path, &project);
        if json {
            println!("{}", serde_json::to_string_pretty(&explanation)?);
        } else {
            print_why_text(&explanation);
        }
    } else if json {
        print_json(&policy, tier, net)?;
    } else {
        print_text(&policy, tier, net)?;
    }

    Ok(())
}

/// Explain access rules and remediation for a specific target path.
pub fn explain_why(policy: &Policy, target_path: &Path, project: &Path) -> PathExplanation {
    let resolved = if target_path.is_relative() {
        project.join(target_path)
    } else {
        target_path.to_path_buf()
    };

    // 1. Check if path is in deny list (display_only_deny or deny_read)
    let is_denied_secret = policy.deny_resolved.iter().any(|d| {
        if d.is_dir {
            resolved.starts_with(&d.path)
        } else {
            resolved == d.path
        }
    });

    let is_denied_read = policy.deny_read.iter().any(|d| resolved.starts_with(d));
    let is_denied_write = policy.deny_write.iter().any(|d| resolved.starts_with(d));

    // 2. Check if writable
    let matching_write_root = policy
        .allow_write
        .iter()
        .find(|root| resolved.starts_with(root))
        .map(|r| r.display().to_string());

    let is_writable = matching_write_root.is_some() && !is_denied_write && !is_denied_secret;

    // 3. Check if readable
    let matching_read_root = policy
        .allow_read
        .iter()
        .find(|root| resolved.starts_with(root))
        .map(|r| r.display().to_string())
        .or_else(|| matching_write_root.clone());

    let is_readable = matching_read_root.is_some() && !is_denied_read && !is_denied_secret;

    let (access, rule_type, matching_rule, how_to_change) = if is_denied_secret {
        (
            "DENIED".to_string(),
            "display_only_deny".to_string(),
            "masked credential / secret path".to_string(),
            "To allow access: remove matching pattern from [display_only_deny.paths] in policy.toml, or move file out of masked secrets pattern.".to_string(),
        )
    } else if is_denied_read {
        (
            "DENIED".to_string(),
            "deny_read".to_string(),
            "filesystem.deny_read rule".to_string(),
            "To allow access: remove path from [filesystem.deny_read] in policy.toml.".to_string(),
        )
    } else if is_writable {
        (
            "WRITABLE".to_string(),
            "allow_write".to_string(),
            format!("allow_write root: {}", matching_write_root.unwrap_or_default()),
            "Path is writable and readable. To restrict to read-only, remove from [filesystem.allow_write] and keep in [filesystem.allow_read].".to_string(),
        )
    } else if is_readable {
        (
            "READ_ONLY".to_string(),
            "allow_read".to_string(),
            format!("allow_read root: {}", matching_read_root.unwrap_or_default()),
            format!(
                "Path is read-only. To allow writing: add \"{}\" or parent directory to [filesystem.allow_write] in policy.toml.",
                target_path.display()
            ),
        )
    } else {
        (
            "BLOCKED".to_string(),
            "unmapped".to_string(),
            "not in any allowed read or write root".to_string(),
            format!(
                "Path is outside sandbox scope. To allow reading: add `allow_read = [\"{}\"]` to policy.toml. To allow writing: add to `allow_write`.",
                target_path.display()
            ),
        )
    };

    PathExplanation {
        path: resolved.display().to_string(),
        access,
        writable: is_writable,
        readable: is_readable,
        denied: is_denied_secret || is_denied_read,
        rule_type,
        matching_rule,
        how_to_change,
    }
}

fn print_why_text(e: &PathExplanation) {
    println!("vetto policy explain --why");
    println!("  path:          {}", e.path);
    println!("  access:        {}", e.access);
    println!("  writable:      {}", if e.writable { "yes" } else { "no" });
    println!("  readable:      {}", if e.readable { "yes" } else { "no" });
    println!("  rule type:     {}", e.rule_type);
    println!("  matching rule: {}", e.matching_rule);
    println!("  how to change: {}", e.how_to_change);
}

fn tier_label(tier: Option<Tier>) -> &'static str {
    match tier {
        Some(Tier::Full) => Tier::Full.label(),
        Some(Tier::FsOnly) => Tier::FsOnly.label(),
        #[cfg(target_os = "windows")]
        _ => "windows-sandbox",
        #[cfg(not(target_os = "windows"))]
        None => "macos-seatbelt",
    }
}

/// How `deny_resolved` secrets are actually kept from the agent on this tier.
fn masking_strategy(tier: Option<Tier>) -> &'static str {
    match tier {
        Some(Tier::Full) => "mount-masked",
        Some(Tier::FsOnly) => "allowlist-carved",
        #[cfg(target_os = "windows")]
        _ => "token-restricted",
        #[cfg(not(target_os = "windows"))]
        None => "seatbelt-denied",
    }
}

/// Human-readable byte count, 1024-based, one decimal (e.g. "8.0 GiB").
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_limit(name: &str, value: u64, is_bytes: bool) -> String {
    if is_bytes {
        format!("{name}: {}", human_bytes(value))
    } else {
        format!("{name}: {value}")
    }
}

const MAX_LISTED_READ_ROOTS: usize = 25;

fn print_text(policy: &Policy, tier: Option<Tier>, net: &NetMode) -> Result<()> {
    println!("vetto policy explain");
    println!("  tier:    {}", tier_label(tier));
    println!("  net:     {}", net.label());
    println!("  profile: {}", policy.name);
    println!("  immutable: {}", policy.is_immutable);

    println!("  write roots:");
    if policy.allow_write.is_empty() {
        println!("    (none)");
    }
    for root in &policy.allow_write {
        println!("    {}", root.display());
    }

    println!("  read roots ({}):", policy.allow_read.len());
    for root in policy.allow_read.iter().take(MAX_LISTED_READ_ROOTS) {
        println!("    {}", root.display());
    }
    if policy.allow_read.len() > MAX_LISTED_READ_ROOTS {
        println!(
            "    ... {} more",
            policy.allow_read.len() - MAX_LISTED_READ_ROOTS
        );
    }

    let strategy = masking_strategy(tier);
    println!(
        "  masked secrets ({}): {}",
        policy.deny_resolved.len(),
        strategy
    );
    for entry in &policy.deny_resolved {
        println!(
            "    {}{}",
            entry.path.display(),
            if entry.is_dir { "/" } else { "" }
        );
    }

    println!("  limits:");
    let limits = &policy.limits;
    let mut printed = 0usize;
    if let Some(value) = limits.cpu_seconds {
        println!("    {}", format_limit("cpu_seconds", value, false));
        printed += 1;
    }
    if let Some(value) = limits.address_space_bytes {
        println!("    {}", format_limit("address_space_bytes", value, true));
        printed += 1;
    }
    if let Some(value) = limits.processes {
        println!("    {}", format_limit("processes", value, false));
        printed += 1;
    }
    if let Some(value) = limits.open_files {
        println!("    {}", format_limit("open_files", value, false));
        printed += 1;
    }
    if let Some(value) = limits.file_size_bytes {
        println!("    {}", format_limit("file_size_bytes", value, true));
        printed += 1;
    }
    if printed == 0 {
        println!("    (none)");
    }

    println!(
        "  environment: {} pass-through pattern(s), {} deny pattern(s)",
        policy.environment.pass_through.len(),
        policy.environment.deny.len()
    );
    if policy.environment.pass_through.is_empty() {
        println!("    pass-through: (none)");
    } else {
        println!(
            "    pass-through: {}",
            policy.environment.pass_through.join(", ")
        );
    }
    if policy.environment.deny.is_empty() {
        println!("    deny: (none)");
    } else {
        println!("    deny: {}", policy.environment.deny.join(", "));
    }

    println!("  deny_network: {}", policy.deny_network);

    if policy.warnings.is_empty() {
        println!("  warnings: (none)");
    } else {
        println!("  warnings ({}):", policy.warnings.len());
        for warning in &policy.warnings {
            println!("    - {warning}");
        }
    }
    Ok(())
}

fn print_json(policy: &Policy, tier: Option<Tier>, net: &NetMode) -> Result<()> {
    let strategy = masking_strategy(tier);
    let limits = &policy.limits;
    let object = serde_json::json!({
        "tier": tier_label(tier),
        "net": net.label(),
        "profile": policy.name.clone(),
        "immutable": policy.is_immutable,
        "write_roots": paths_as_strings(&policy.allow_write),
        "read_root_count": policy.allow_read.len(),
        "read_roots": paths_as_strings(
            &policy.allow_read.iter().take(MAX_LISTED_READ_ROOTS).cloned().collect::<Vec<_>>(),
        ),
        "masked_secrets": policy
            .deny_resolved
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "path": entry.path.display().to_string(),
                    "is_dir": entry.is_dir,
                    "strategy": strategy,
                })
            })
            .collect::<Vec<_>>(),
        "limits": {
            "cpu_seconds": limits.cpu_seconds,
            "address_space_bytes": limits.address_space_bytes,
            "processes": limits.processes,
            "open_files": limits.open_files,
            "file_size_bytes": limits.file_size_bytes,
        },
        "environment": {
            "pass_through": policy.environment.pass_through.clone(),
            "deny": policy.environment.deny.clone(),
        },
        "deny_network": policy.deny_network,
        "warnings": policy.warnings.clone(),
    });
    println!("{}", serde_json::to_string_pretty(&object)?);
    Ok(())
}

fn paths_as_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| path.display().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::DenyEntry;

    #[test]
    fn human_bytes_uses_binary_units_with_one_decimal() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(8589934592), "8.0 GiB");
        assert_eq!(human_bytes(5 * 1024 * 1024), "5.0 MiB");
        assert_eq!(human_bytes(2 * 1024u64.pow(4)), "2.0 TiB");
    }

    #[test]
    fn tier_and_masking_labels_cover_all_tiers() {
        assert_eq!(tier_label(Some(Tier::Full)), "full");
        assert_eq!(tier_label(Some(Tier::FsOnly)), "fs-only");
        assert_eq!(tier_label(None), "macos-seatbelt");
        assert_eq!(masking_strategy(Some(Tier::Full)), "mount-masked");
        assert_eq!(masking_strategy(Some(Tier::FsOnly)), "allowlist-carved");
    }

    #[test]
    fn explain_why_identifies_writable_readable_and_denied_paths() {
        let mut policy = Policy::default();
        let project = PathBuf::from("/home/user/project");
        policy.allow_write = vec![project.clone(), PathBuf::from("/tmp")];
        policy.allow_read = vec![PathBuf::from("/usr")];
        policy.deny_resolved = vec![DenyEntry {
            path: project.join(".env"),
            is_dir: false,
        }];

        // 1. Writable path
        let src_file = project.join("src/main.rs");
        let exp_src = explain_why(&policy, &src_file, &project);
        assert_eq!(exp_src.access, "WRITABLE");
        assert!(exp_src.writable);
        assert!(exp_src.readable);

        // 2. Denied secret path
        let env_file = project.join(".env");
        let exp_env = explain_why(&policy, &env_file, &project);
        assert_eq!(exp_env.access, "DENIED");
        assert!(!exp_env.writable);
        assert!(!exp_env.readable);
        assert!(exp_env.denied);
        assert!(exp_env.how_to_change.contains("display_only_deny"));

        // 3. Read-only path
        let usr_lib = PathBuf::from("/usr/lib");
        let exp_usr = explain_why(&policy, &usr_lib, &project);
        assert_eq!(exp_usr.access, "READ_ONLY");
        assert!(!exp_usr.writable);
        assert!(exp_usr.readable);

        // 4. Outside path
        let etc_pass = PathBuf::from("/etc/shadow");
        let exp_etc = explain_why(&policy, &etc_pass, &project);
        assert_eq!(exp_etc.access, "BLOCKED");
        assert!(!exp_etc.writable);
        assert!(!exp_etc.readable);
    }
}
