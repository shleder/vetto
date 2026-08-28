//! `vetto policy explain`: print the effective policy after all layers merge.
//!
//! Read-only tooling command: it detects the enforcement tier, loads the
//! policy exactly like a supervised session does (same tier semantics, same
//! layer order), and prints text or JSON. It NEVER spawns a sandbox.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::NetMode;
use crate::sandbox::Backend;

use super::loader::{load_with_options, PolicyLoadOptions};
use super::types::{Policy, Tier};

/// Detect the tier, load the effective policy and print it as text or JSON.
pub fn run_cli(json: bool, profile: &str, policy_path: Option<&Path>, net: &NetMode) -> Result<()> {
    // Same detect semantics as a real session: fail-closed when no tier exists.
    let backend = Backend::detect(net.clone(), false)?;
    let tier = backend.tier();

    let project = std::env::current_dir().context("getcwd")?;
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set; vetto needs it to resolve policy variables")?;

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

    if json {
        print_json(&policy, tier, net)
    } else {
        print_text(&policy, tier, net)
    }
}

fn tier_label(tier: Option<Tier>) -> &'static str {
    match tier {
        Some(Tier::Full) => Tier::Full.label(),
        Some(Tier::FsOnly) => Tier::FsOnly.label(),
        None => "macos-seatbelt",
    }
}

/// How `deny_resolved` secrets are actually kept from the agent on this tier.
fn masking_strategy(tier: Option<Tier>) -> &'static str {
    match tier {
        Some(Tier::Full) => "mount-masked",
        Some(Tier::FsOnly) => "allowlist-carved",
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
        // CPU time and counts print in their plain unit (seconds / count).
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
}
