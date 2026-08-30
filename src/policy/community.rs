//! Curated community policy templates for common software ecosystems.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

pub const COMMUNITY_POLICIES: &[(&str, &str, &str)] = &[
    (
        "python-dev",
        "Python development sandbox (uv, poetry, virtualenv, pip caching, tests)",
        include_str!("../../policies/community/python-dev.toml"),
    ),
    (
        "node-dev",
        "Node.js / TypeScript sandbox (npm, yarn, pnpm, node_modules, build caches)",
        include_str!("../../policies/community/node-dev.toml"),
    ),
    (
        "rust-dev",
        "Rust development sandbox (Cargo, rustc, target/, crates.io, audit)",
        include_str!("../../policies/community/rust-dev.toml"),
    ),
    (
        "java-dev",
        "Java / JVM development sandbox (Maven, Gradle, .m2, .gradle cache)",
        include_str!("../../policies/community/java-dev.toml"),
    ),
    (
        "data-science",
        "Data science sandbox (Python, Jupyter, Pandas, PyTorch datasets, local notebooks)",
        include_str!("../../policies/community/data-science.toml"),
    ),
    (
        "read-only-audit",
        "Strict read-only analysis profile (no writes allowed to project code)",
        include_str!("../../policies/community/read-only-audit.toml"),
    ),
    (
        "yolo-web",
        "Web application sandbox with permissive development network egress",
        include_str!("../../policies/community/yolo-web.toml"),
    ),
];

pub fn get_community_policy(name: &str) -> Option<&'static str> {
    for (n, _, content) in COMMUNITY_POLICIES {
        if *n == name {
            return Some(content);
        }
    }
    None
}

pub fn list_community_policies() -> Vec<(&'static str, &'static str)> {
    COMMUNITY_POLICIES
        .iter()
        .map(|(n, d, _)| (*n, *d))
        .collect()
}

pub fn install_community_policy(name: &str, project_dir: &Path, force: bool) -> Result<PathBuf> {
    let content = get_community_policy(name).ok_or_else(|| {
        let available = COMMUNITY_POLICIES
            .iter()
            .map(|(n, _, _)| *n)
            .collect::<Vec<_>>()
            .join(", ");
        anyhow::anyhow!("unknown community policy '{name}'; available: {available}")
    })?;

    let target_path = project_dir.join("vetto.toml");
    if target_path.exists() && !force {
        bail!(
            "policy file already exists at {}; use --force to overwrite",
            target_path.display()
        );
    }

    fs::write(&target_path, content.as_bytes())
        .with_context(|| format!("failed to write policy to {}", target_path.display()))?;

    Ok(target_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_community_policies_present_and_valid() {
        assert!(COMMUNITY_POLICIES.len() >= 7);
        for (name, desc, content) in COMMUNITY_POLICIES {
            assert!(!name.is_empty());
            assert!(!desc.is_empty());
            assert!(!content.is_empty());
            assert!(content.contains("[filesystem]") || content.contains("[metadata]"));
        }
    }
}
