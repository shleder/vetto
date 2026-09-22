//! One-command policy editing: `vetto allow` / `vetto deny`.
//!
//! Writes the project `vetto.toml` (or the user-global `~/.vetto/config.toml`
//! with `--global`), preserving comments and formatting via `toml_edit`.
//! Created files get a short header so the layer stays self-documenting.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use crate::policy::presets::{resolve_preset, KNOWN_PRESETS};

const PROJECT_HEADER: &str = r#"# vetto project policy.
# This file is merged over the built-in profile and agent preset; CLI flags win.
# Manage it with `vetto allow` / `vetto deny`, or by hand — every key is
# validated on load and documented in the README.
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    /// Append to both `allow_read` and `allow_write` under `[filesystem]`.
    FsReadWrite,
    /// Append to `allow_read` under `[filesystem]` only.
    FsRead,
    /// Append to `allow` under `[network]` and default the mode to allowlist.
    Net,
    /// Append to `net_presets` under `[network]` and default the mode to allowlist.
    NetPreset,
    /// Append to `allow_cidr` under `[network]` and default the mode to allowlist.
    NetCidr,
    /// Append to `paths` under `[display_only_deny]`.
    Deny,
}

impl Grant {
    fn section_key(self, read_only: bool) -> (&'static str, &'static str) {
        match self {
            Grant::Net => ("network", "allow"),
            Grant::NetPreset => ("network", "net_presets"),
            Grant::NetCidr => ("network", "allow_cidr"),
            Grant::Deny => ("display_only_deny", "paths"),
            Grant::FsReadWrite => {
                if read_only {
                    ("filesystem", "allow_read")
                } else {
                    ("filesystem", "allow_write")
                }
            }
            Grant::FsRead => ("filesystem", "allow_read"),
        }
    }

    fn describe(self) -> &'static str {
        match self {
            Grant::Net => "network domain allowlist",
            Grant::NetPreset => "network preset allowlist",
            Grant::NetCidr => "network CIDR allowlist",
            Grant::Deny => "masked secrets (reads denied)",
            Grant::FsReadWrite => "read + write grant",
            Grant::FsRead => "read-only grant",
        }
    }
}

/// Mutate a parsed policy document, appending `target` to the grant's array.
/// Returns `false` when the value was already present. A first network grant
/// switches an absent or `off` mode to `allowlist`; explicit modes are kept.
///
/// Malformed documents (e.g. a section shadowed by a scalar value) yield an
/// error instead of panicking: `allow`/`deny` run against user-controlled
/// files and must stay fail-closed.
pub fn edit_document(doc: &mut toml_edit::DocumentMut, grant: Grant, target: &str) -> Result<bool> {
    let (section, key) = grant.section_key(false);
    let table = doc.as_table_mut();
    if table.get(section).is_none() {
        table.insert(section, toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let inner = table
        .get_mut(section)
        .context("policy section went missing after insert")?
        .as_table_mut()
        .with_context(|| format!("policy section [{section}] is not a table"))?;
    if inner.get(key).is_none() {
        inner.insert(
            key,
            toml_edit::Item::Value(toml_edit::Value::Array(Default::default())),
        );
    }
    let array = inner
        .get_mut(key)
        .context("policy key went missing after insert")?
        .as_value_mut()
        .with_context(|| format!("policy key [{section}.{key}] is not a value"))?
        .as_array_mut()
        .with_context(|| format!("policy key [{section}.{key}] is not a string array"))?;
    let added = if array.iter().any(|v| v.as_str() == Some(target)) {
        false
    } else {
        array.push(target);
        true
    };

    if matches!(grant, Grant::Net | Grant::NetPreset | Grant::NetCidr) {
        let inner = doc
            .as_table_mut()
            .get_mut("network")
            .context("network section went missing after insert")?
            .as_table_mut()
            .context("policy section [network] is not a table")?;
        match inner.get_mut("mode") {
            None => {
                inner.insert(
                    "mode",
                    toml_edit::Item::Value(toml_edit::Value::from("allowlist")),
                );
            }
            Some(item) => {
                if item.as_str() == Some("off") {
                    *item = toml_edit::Item::Value(toml_edit::Value::from("allowlist"));
                }
            }
        }
    }
    Ok(added)
}

pub fn resolve_target_file(global: bool, custom_policy: Option<&Path>) -> Result<PathBuf> {
    if global {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("neither HOME nor USERPROFILE is set")?;
        return Ok(home.join(".vetto").join("config.toml"));
    }
    if let Some(custom) = custom_policy {
        return Ok(custom.to_path_buf());
    }

    let dot_vetto_policy = Path::new(".vetto").join("policy.toml");
    let policy_toml = Path::new("policy.toml");
    let vetto_toml = Path::new("vetto.toml");

    if dot_vetto_policy.is_file() {
        Ok(dot_vetto_policy)
    } else if policy_toml.is_file() {
        Ok(policy_toml.to_path_buf())
    } else if vetto_toml.is_file() {
        Ok(vetto_toml.to_path_buf())
    } else if Path::new(".vetto").is_dir() {
        Ok(dot_vetto_policy)
    } else {
        Ok(vetto_toml.to_path_buf())
    }
}

/// Validate and canonicalize a CIDR or IP target.
///
/// Accepts:
/// - CIDR notations: `10.0.0.0/8`, `192.168.1.0/24`, `fd00::/8`, `[2001:db8::]/32`
/// - Single IP addresses (optionally with port/protocol): `192.168.1.1`, `http://10.0.0.1:8080`,
///   `::1`, `[::1]:443`
///
/// Returns canonical `ip/prefix` format (e.g. `10.0.0.0/8`, `192.168.1.1/32`, `::1/128`).
pub fn parse_and_validate_cidr(raw: &str) -> Result<String> {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    }

    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let prefix_clean = prefix_part.trim();
        let prefix_num_str = if let Some(idx) = prefix_clean.find(['?', '#']) {
            &prefix_clean[..idx]
        } else {
            prefix_clean
        };
        let prefix_len: u8 = prefix_num_str
            .parse()
            .with_context(|| format!("invalid prefix in CIDR '{raw}'"))?;

        let ip_clean = ip_part.trim().trim_start_matches('[').trim_end_matches(']');
        let ip: std::net::IpAddr = ip_clean
            .parse()
            .with_context(|| format!("invalid IP in CIDR '{raw}'"))?;

        match ip {
            std::net::IpAddr::V4(_) if prefix_len > 32 => {
                bail!("IPv4 CIDR prefix length must be 0..=32, got {prefix_len}");
            }
            std::net::IpAddr::V6(_) if prefix_len > 128 => {
                bail!("IPv6 CIDR prefix length must be 0..=128, got {prefix_len}");
            }
            _ => {}
        }
        return Ok(format!("{ip}/{prefix_len}"));
    }

    let s_no_path = if let Some(idx) = s.find(['/', '?', '#']) {
        &s[..idx]
    } else {
        s
    };
    let s_no_port = crate::cred_broker::strip_domain_port(s_no_path);
    let ip_clean = s_no_port
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let ip: std::net::IpAddr = ip_clean
        .parse()
        .with_context(|| format!("invalid IP address '{raw}'"))?;

    let prefix_len = match ip {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    };
    Ok(format!("{ip}/{prefix_len}"))
}

pub fn try_parse_cidr_or_ip(raw: &str) -> Option<String> {
    parse_and_validate_cidr(raw).ok()
}

/// Normalize network targets: strip protocol prefixes (http://, https://),
/// trailing paths, queries, fragments, port numbers, trailing dots, and lowercase.
pub fn normalize_net_target(raw: &str) -> String {
    let mut s = raw.trim();
    if let Some(rest) = s.strip_prefix("https://") {
        s = rest;
    } else if let Some(rest) = s.strip_prefix("http://") {
        s = rest;
    }

    if let Some(idx) = s.find(['/', '?', '#']) {
        s = &s[..idx];
    }

    let s = crate::cred_broker::strip_domain_port(s);
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Apply a grant to the target policy file. Returns the file it wrote.
pub fn apply(
    grant: Grant,
    target: &str,
    global: bool,
    custom_policy: Option<&Path>,
) -> Result<PathBuf> {
    apply_with_quota(grant, target, None, global, custom_policy)
}

/// Apply a grant and optional quota to the target policy file. Returns the file it wrote.
pub fn apply_with_quota(
    grant: Grant,
    target: &str,
    quota: Option<&str>,
    global: bool,
    custom_policy: Option<&Path>,
) -> Result<PathBuf> {
    let path = resolve_target_file(global, custom_policy)?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
    }
    let raw = if path.exists() {
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?
    } else {
        PROJECT_HEADER.to_string()
    };
    let mut doc: toml_edit::DocumentMut = raw
        .parse()
        .with_context(|| format!("parse {}", path.display()))?;
    let _added = edit_document(&mut doc, grant, target)?;
    if let Some(q) = quota {
        set_domain_quota(&mut doc, target, q)?;
    }
    std::fs::write(&path, doc.to_string()).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// Mutate a parsed policy document to add or update a per-domain quota under `[network.net_quota]`.
pub fn set_domain_quota(doc: &mut toml_edit::DocumentMut, domain: &str, quota: &str) -> Result<()> {
    let clean_domain = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let table = doc.as_table_mut();
    if table.get("network").is_none() {
        table.insert("network", toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let net_table = table
        .get_mut("network")
        .context("network section went missing after insert")?
        .as_table_mut()
        .context("policy section [network] is not a table")?;

    if net_table.get("net_quota").is_none() {
        net_table.insert("net_quota", toml_edit::Item::Table(toml_edit::Table::new()));
    }
    let quota_item = net_table
        .get_mut("net_quota")
        .context("net_quota went missing after insert")?;

    if let Some(tbl) = quota_item.as_table_mut() {
        tbl.insert(
            &clean_domain,
            toml_edit::Item::Value(toml_edit::Value::from(quota)),
        );
    } else if let Some(inline) = quota_item.as_inline_table_mut() {
        inline.insert(&clean_domain, toml_edit::Value::from(quota));
    } else {
        bail!("network.net_quota is not a table");
    }
    Ok(())
}

/// Persist a network target (domain or IP/CIDR) to the policy file.
pub fn persist_net_target(
    target: &str,
    custom_policy: Option<&Path>,
) -> Result<(PathBuf, &'static str)> {
    let clean = target.trim();
    if let Some(cidr) = try_parse_cidr_or_ip(clean) {
        let path = apply(Grant::NetCidr, &cidr, false, custom_policy)?;
        Ok((path, "CIDR"))
    } else {
        let normalized = normalize_net_target(clean);
        if normalized.is_empty() {
            bail!("invalid network domain '{target}'");
        }
        let path = apply(Grant::Net, &normalized, false, custom_policy)?;
        Ok((path, "domain"))
    }
}

/// CLI entry point for `vetto allow`.
#[allow(clippy::too_many_arguments)]
pub fn run_allow(
    target: Option<&str>,
    preset: Option<&str>,
    quota: Option<&str>,
    read_only: bool,
    net: bool,
    cidr: bool,
    global: bool,
    custom_policy: Option<&Path>,
) -> Result<()> {
    if let Some(q) = quota {
        // Validate quota syntax early
        crate::policy::loader::parse_quota_bytes(q)?;
    }

    if let Some(p) = preset {
        if quota.is_some() {
            bail!("--quota cannot be specified with --preset");
        }
        let preset_clean = p.trim().to_ascii_lowercase();
        let domains = crate::policy::loader::expand_net_preset(&preset_clean)?;
        let path = apply(Grant::NetPreset, &preset_clean, global, custom_policy)?;
        println!(
            "vetto: preset `{}` granted (network preset: {}), policy file: {}",
            preset_clean,
            domains.join(", "),
            path.display()
        );
        println!("vetto: the grant applies to the next session");
        return Ok(());
    }

    let raw_target = target
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .context("target path, domain, CIDR, or --preset must be provided")?;

    if cidr {
        let normalized = parse_and_validate_cidr(raw_target)?;
        let path = apply_with_quota(Grant::NetCidr, &normalized, quota, global, custom_policy)?;
        if let Some(q) = quota {
            println!(
                "vetto: `{normalized}` granted ({}) with quota {q}, policy file: {}",
                Grant::NetCidr.describe(),
                path.display()
            );
        } else {
            println!(
                "vetto: `{normalized}` granted ({}), policy file: {}",
                Grant::NetCidr.describe(),
                path.display()
            );
        }
        println!("vetto: the grant applies to the next session");
        return Ok(());
    }

    if net || quota.is_some() {
        let candidate = raw_target.to_ascii_lowercase();
        if let Ok(domains) = crate::policy::loader::expand_net_preset(&candidate) {
            if quota.is_some() {
                bail!("--quota cannot be specified with preset '{candidate}'");
            }
            let path = apply(Grant::NetPreset, &candidate, global, custom_policy)?;
            println!(
                "vetto: preset `{}` granted (network preset: {}), policy file: {}",
                candidate,
                domains.join(", "),
                path.display()
            );
            println!("vetto: the grant applies to the next session");
            return Ok(());
        }

        if let Some(normalized_cidr) = try_parse_cidr_or_ip(raw_target) {
            let path = apply_with_quota(
                Grant::NetCidr,
                &normalized_cidr,
                quota,
                global,
                custom_policy,
            )?;
            if let Some(q) = quota {
                println!(
                    "vetto: `{normalized_cidr}` granted ({}) with quota {q}, policy file: {}",
                    Grant::NetCidr.describe(),
                    path.display()
                );
            } else {
                println!(
                    "vetto: `{normalized_cidr}` granted ({}), policy file: {}",
                    Grant::NetCidr.describe(),
                    path.display()
                );
            }
            println!("vetto: the grant applies to the next session");
            return Ok(());
        }

        let normalized = normalize_net_target(raw_target);
        if normalized.is_empty() {
            bail!("invalid network domain '{raw_target}'");
        }
        let path = apply_with_quota(Grant::Net, &normalized, quota, global, custom_policy)?;
        if let Some(q) = quota {
            println!(
                "vetto: `{normalized}` granted ({}) with quota {q}, policy file: {}",
                Grant::Net.describe(),
                path.display()
            );
        } else {
            println!(
                "vetto: `{normalized}` granted ({}), policy file: {}",
                Grant::Net.describe(),
                path.display()
            );
        }
        println!("vetto: the grant applies to the next session");
        return Ok(());
    }

    let grant = if read_only {
        Grant::FsRead
    } else {
        Grant::FsReadWrite
    };
    let path = apply(grant, raw_target, global, custom_policy)?;
    println!(
        "vetto: `{raw_target}` granted ({}), policy file: {}",
        grant.describe(),
        path.display()
    );
    println!("vetto: the grant applies to the next session");
    Ok(())
}

/// CLI entry point for `vetto deny`.
pub fn run_deny(
    target: Option<&str>,
    preset: Option<&str>,
    global: bool,
    custom_policy: Option<&Path>,
) -> Result<()> {
    let clean_preset = preset.map(str::trim).filter(|s| !s.is_empty());
    let clean_target = target.map(str::trim).filter(|s| !s.is_empty());

    let preset_name = clean_preset.or_else(|| {
        clean_target.filter(|&t| {
            !t.contains('/')
                && !t.contains('\\')
                && KNOWN_PRESETS.iter().any(|&p| p.eq_ignore_ascii_case(t))
        })
    });

    if let Some(preset_name) = preset_name {
        let paths = match resolve_preset(preset_name) {
            Some(paths) => paths,
            None => bail!(
                "unknown preset '{preset_name}' (known presets: {})",
                KNOWN_PRESETS.join(", ")
            ),
        };
        let mut path = PathBuf::new();
        for &p in paths {
            path = apply(Grant::Deny, p, global, custom_policy)?;
        }
        eprintln!(
            "vetto: preset `{preset_name}` denied (masked secrets: {}), policy file: {}",
            paths.join(", "),
            path.display()
        );
        return Ok(());
    }

    if let Some(t) = clean_target {
        let grant = Grant::Deny;
        let path = apply(grant, t, global, custom_policy)?;
        println!(
            "vetto: `{t}` denied ({}), policy file: {}",
            grant.describe(),
            path.display()
        );
        println!("vetto: the path is masked from the next session (reads denied)");
        return Ok(());
    }

    bail!("target path or --preset must be provided")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc_with(raw: &str) -> toml_edit::DocumentMut {
        raw.parse().expect("parse")
    }

    #[test]
    fn grant_then_dedupe_on_fresh_document() {
        let mut doc = doc_with(PROJECT_HEADER);
        assert!(edit_document(&mut doc, Grant::FsReadWrite, "/opt/data").expect("edit"));
        assert!(!edit_document(&mut doc, Grant::FsReadWrite, "/opt/data").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("\"/opt/data\""));
        assert!(s.contains("vetto project policy"));
    }

    #[test]
    fn comments_survive_edit() {
        let mut doc =
            doc_with("# my important comment\n[filesystem]\nallow_read = [\"/usr\"] # keep me\n");
        assert!(edit_document(&mut doc, Grant::FsRead, "/opt/extra").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("# my important comment"));
        assert!(s.contains("# keep me"));
        assert!(s.contains("\"/opt/extra\""));
    }

    #[test]
    fn net_grant_defaults_mode_to_allowlist() {
        let mut doc = doc_with(PROJECT_HEADER);
        assert!(edit_document(&mut doc, Grant::Net, "registry.npmjs.org").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("mode = \"allowlist\""));
        assert!(s.contains("\"registry.npmjs.org\""));
        // Explicit "off" is flipped so the grant takes effect.
        let mut doc2 = doc_with("[network]\nmode = \"off\"\n");
        assert!(edit_document(&mut doc2, Grant::Net, "example.com").expect("edit"));
        assert!(doc2.to_string().contains("mode = \"allowlist\""));
        // Explicit allowlist mode is preserved.
        let mut doc3 = doc_with("[network]\nmode = \"allowlist\"\nallow = []\n");
        assert!(edit_document(&mut doc3, Grant::Net, "example.com").expect("edit"));
        assert_eq!(doc3.to_string().matches("mode").count(), 1);
    }

    #[test]
    fn deny_grant_uses_display_only_deny() {
        let mut doc = doc_with(PROJECT_HEADER);
        assert!(edit_document(&mut doc, Grant::Deny, "$HOME/.aws/credentials").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("[display_only_deny]"));
        assert!(s.contains("\"$HOME/.aws/credentials\""));
    }

    #[test]
    fn malformed_document_errors_instead_of_panicking() {
        // A section shadowed by a scalar (or an array shadowed by one) must
        // surface as an error: allow/deny run against user-controlled files.
        let mut doc = doc_with("[filesystem]\nallow_write = \"/not-an-array\"\n");
        assert!(edit_document(&mut doc, Grant::FsReadWrite, "/opt/data").is_err());
        let mut doc2 = doc_with("network = \"off\"\n");
        assert!(edit_document(&mut doc2, Grant::Net, "example.com").is_err());
    }

    #[test]
    fn net_preset_grant_defaults_mode_to_allowlist() {
        let mut doc = doc_with(PROJECT_HEADER);
        assert!(edit_document(&mut doc, Grant::NetPreset, "npm").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("mode = \"allowlist\""));
        assert!(s.contains("\"npm\""));
        assert!(s.contains("net_presets = ["));
    }

    #[test]
    fn test_normalize_net_target() {
        assert_eq!(
            normalize_net_target("api.anthropic.com"),
            "api.anthropic.com"
        );
        assert_eq!(
            normalize_net_target("https://api.anthropic.com/v1/messages"),
            "api.anthropic.com"
        );
        assert_eq!(
            normalize_net_target("http://api.github.com:443/repos?query=1"),
            "api.github.com"
        );
        assert_eq!(
            normalize_net_target("*.githubusercontent.com:443"),
            "*.githubusercontent.com"
        );
        assert_eq!(
            normalize_net_target("REGISTRY.NPMJS.ORG."),
            "registry.npmjs.org"
        );
    }

    #[test]
    fn test_resolve_target_file_hierarchy() {
        let dir = std::env::temp_dir().join(format!("vetto-res-hierarchy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let custom = dir.join("custom.toml");
        assert_eq!(resolve_target_file(false, Some(&custom)).unwrap(), custom);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn net_cidr_grant_defaults_mode_to_allowlist() {
        let mut doc = doc_with(PROJECT_HEADER);
        assert!(edit_document(&mut doc, Grant::NetCidr, "10.0.0.0/8").expect("edit"));
        let s = doc.to_string();
        assert!(s.contains("mode = \"allowlist\""));
        assert!(s.contains("\"10.0.0.0/8\""));
        assert!(s.contains("allow_cidr = ["));
    }

    #[test]
    fn test_parse_and_validate_cidr() {
        assert_eq!(parse_and_validate_cidr("10.0.0.0/8").unwrap(), "10.0.0.0/8");
        assert_eq!(
            parse_and_validate_cidr("192.168.1.0/24").unwrap(),
            "192.168.1.0/24"
        );
        assert_eq!(
            parse_and_validate_cidr("192.168.1.50").unwrap(),
            "192.168.1.50/32"
        );
        assert_eq!(
            parse_and_validate_cidr("http://10.0.0.1:8080").unwrap(),
            "10.0.0.1/32"
        );
        assert_eq!(
            parse_and_validate_cidr("https://10.0.0.0/8").unwrap(),
            "10.0.0.0/8"
        );
        assert_eq!(parse_and_validate_cidr("::1").unwrap(), "::1/128");
        assert_eq!(parse_and_validate_cidr("[::1]:8080").unwrap(), "::1/128");
        assert_eq!(
            parse_and_validate_cidr("[2001:db8::]/32").unwrap(),
            "2001:db8::/32"
        );
        assert!(parse_and_validate_cidr("10.0.0.1/33").is_err());
        assert!(parse_and_validate_cidr("api.anthropic.com").is_err());
        assert!(parse_and_validate_cidr("not_an_ip").is_err());
    }

    #[test]
    fn test_run_allow_with_net_preset_and_custom_policy() {
        let dir = std::env::temp_dir().join(format!("vetto-run-allow-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let custom = dir.join("policy.toml");

        // Allow preset npm
        run_allow(
            Some("npm"),
            None,
            None,
            false,
            true,
            false,
            false,
            Some(&custom),
        )
        .expect("allow preset");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("mode = \"allowlist\""));
        assert!(content.contains("\"npm\""));

        // Allow wildcard domain
        run_allow(
            Some("*.anthropic.com:443"),
            None,
            None,
            false,
            true,
            false,
            false,
            Some(&custom),
        )
        .expect("allow wildcard");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"*.anthropic.com\""));

        // Allow filesystem path
        run_allow(
            Some("/tmp/scratch"),
            None,
            None,
            false,
            false,
            false,
            false,
            Some(&custom),
        )
        .expect("allow fs");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"/tmp/scratch\""));

        // Allow CIDR via --net
        run_allow(
            Some("10.0.0.0/8"),
            None,
            None,
            false,
            true,
            false,
            false,
            Some(&custom),
        )
        .expect("allow cidr via net");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"10.0.0.0/8\""));
        assert!(content.contains("allow_cidr = ["));

        // Allow bare IP via --net (auto-expanded to /32)
        run_allow(
            Some("192.168.1.100"),
            None,
            None,
            false,
            true,
            false,
            false,
            Some(&custom),
        )
        .expect("allow bare ip via net");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"192.168.1.100/32\""));

        // Allow CIDR via explicit --cidr
        run_allow(
            Some("172.16.0.0/12"),
            None,
            None,
            false,
            false,
            true,
            false,
            Some(&custom),
        )
        .expect("allow cidr via cidr");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"172.16.0.0/12\""));

        // Allow domain with quota
        run_allow(
            Some("api.openai.com"),
            None,
            Some("100mb"),
            false,
            true,
            false,
            false,
            Some(&custom),
        )
        .expect("allow domain with quota");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"api.openai.com\""));
        assert!(content.contains("net_quota"));
        assert!(content.contains("\"100mb\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_domain_quota_creates_and_updates_net_quota() {
        let mut doc = doc_with(PROJECT_HEADER);
        set_domain_quota(&mut doc, "api.openai.com", "100mb").expect("set quota");
        set_domain_quota(&mut doc, "github.com", "1gb").expect("set quota 2");
        let s = doc.to_string();
        assert!(s.contains("net_quota"));
        assert!(
            s.contains("\"api.openai.com\" = \"100mb\"")
                || s.contains("api.openai.com = \"100mb\"")
        );
        assert!(s.contains("\"github.com\" = \"1gb\"") || s.contains("github.com = \"1gb\""));
    }

    #[test]
    fn existing_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("vetto-edit-roundtrip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vetto.toml");
        std::fs::write(&path, PROJECT_HEADER).unwrap();
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut doc: toml_edit::DocumentMut = raw.parse().unwrap();
        edit_document(&mut doc, Grant::FsReadWrite, "/opt/data").expect("edit");
        std::fs::write(&path, doc.to_string()).unwrap();
        let on_disk = std::fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("\"/opt/data\""));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_run_deny_presets() {
        let dir =
            std::env::temp_dir().join(format!("vetto-run-deny-presets-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let custom = dir.join("policy.toml");

        // Test --preset ssh
        run_deny(None, Some("ssh"), false, Some(&custom)).expect("deny ssh preset");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("[display_only_deny]"));
        assert!(content.contains("\"$HOME/.ssh\""));

        // Test --preset aws
        run_deny(None, Some("aws"), false, Some(&custom)).expect("deny aws preset");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"$HOME/.aws\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_deny_positional_preset() {
        let dir = std::env::temp_dir().join(format!("vetto-run-deny-pos-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let custom = dir.join("policy.toml");

        // Test positional call with preset name: target = Some("docker")
        run_deny(Some("docker"), None, false, Some(&custom)).expect("deny docker positional");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("[display_only_deny]"));
        assert!(content.contains("\"$HOME/.docker\""));
        assert!(content.contains("\"$HOME/.docker/config.json\""));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_run_deny_unknown_preset_errors() {
        let err = run_deny(None, Some("unknown_foobar"), false, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("unknown preset 'unknown_foobar'"));
        assert!(msg.contains("known presets:"));
    }

    #[test]
    fn test_run_deny_missing_target_and_preset_errors() {
        let err = run_deny(None, None, false, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("target path or --preset must be provided"));
    }

    #[test]
    fn test_run_deny_regular_target() {
        let dir =
            std::env::temp_dir().join(format!("vetto-run-deny-target-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let custom = dir.join("policy.toml");

        run_deny(Some("~/.custom/secret.txt"), None, false, Some(&custom)).expect("deny path");
        let content = std::fs::read_to_string(&custom).unwrap();
        assert!(content.contains("\"~/.custom/secret.txt\""));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
