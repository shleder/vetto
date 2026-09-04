//! One-command policy editing: `vetto allow` / `vetto deny`.
//!
//! Writes the project `vetto.toml` (or the user-global `~/.vetto/config.toml`
//! with `--global`), preserving comments and formatting via `toml_edit`.
//! Created files get a short header so the layer stays self-documenting.

use anyhow::{Context, Result};
use std::path::PathBuf;

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
    /// Append to `paths` under `[display_only_deny]`.
    Deny,
}

impl Grant {
    fn section_key(self, read_only: bool) -> (&'static str, &'static str) {
        match self {
            Grant::Net => ("network", "allow"),
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

    if matches!(grant, Grant::Net) {
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

fn resolve_target_file(global: bool) -> Result<PathBuf> {
    if global {
        let home = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(PathBuf::from)
            .context("neither HOME nor USERPROFILE is set")?;
        return Ok(home.join(".vetto").join("config.toml"));
    }
    Ok(PathBuf::from("vetto.toml"))
}

/// Apply a grant to the target policy file. Returns the file it wrote.
fn apply(grant: Grant, target: &str, global: bool) -> Result<PathBuf> {
    let path = resolve_target_file(global)?;
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
    std::fs::write(&path, doc.to_string()).with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// CLI entry point for `vetto allow`.
pub fn run_allow(target: &str, read_only: bool, net: bool, global: bool) -> Result<()> {
    let grant = if net {
        Grant::Net
    } else if read_only {
        Grant::FsRead
    } else {
        Grant::FsReadWrite
    };
    let path = apply(grant, target, global)?;
    println!(
        "vetto: `{target}` granted ({}), policy file: {}",
        grant.describe(),
        path.display()
    );
    println!("vetto: the grant applies to the next session");
    Ok(())
}

/// CLI entry point for `vetto deny`.
pub fn run_deny(target: &str, global: bool) -> Result<()> {
    let grant = Grant::Deny;
    let path = apply(grant, target, global)?;
    println!(
        "vetto: `{target}` denied ({}), policy file: {}",
        grant.describe(),
        path.display()
    );
    println!("vetto: the path is masked from the next session (reads denied)");
    Ok(())
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
}
