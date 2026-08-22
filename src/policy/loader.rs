//! Policy loading: profile name -> resolved `Policy`.
//!
//! Loader rules (spec v3):
//! 1. Globs never reach the enforcement layer; they are expanded at load time.
//! 2. On Tier FULL, `display_only_deny` paths are masked via bind-mount
//!    overlays in the sandbox mount namespace (see sandbox/linux/mounts.rs).
//!    Landlock itself has no subtractive rules.
//! 3. Secrets under $HOME are denied by omission from `allow_read`.
//! 4. `~/.gitconfig` is included read-only on purpose (commit UX).
//! 5. On Tier FS-ONLY there are no mount namespaces, so intra-project
//!    secrets cannot be overlay-masked. Instead the loader enumerates the
//!    project tree (bounded) into an explicit per-entry read allowlist,
//!    excluding secret-shaped files. Writes stay whole-tree so agents can
//!    still create new files. If the tree exceeds the enumeration budget we
//!    fall back to a single project-wide read rule and record a LOUD warning.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::checker;
use super::defaults;
use super::glob_resolve::{self, Vars};
use super::types::{DenyEntry, Policy, Tier};

/// Enumeration budget for FS-ONLY project masking (entries, not bytes).
const FS_ONLY_ENUMERATION_BUDGET: usize = 20_000;

#[derive(Deserialize, Debug)]
struct RawProfile {
    filesystem: RawFs,
    #[serde(default)]
    display_only_deny: Option<RawDeny>,
}

#[derive(Deserialize, Debug)]
struct RawFs {
    allow_write: Vec<String>,
    #[serde(default)]
    allow_read: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct RawDeny {
    #[serde(default)]
    paths: Vec<String>,
}

/// Load a policy either from a built-in profile name or a custom TOML path,
/// resolved for the given tier.
pub fn load(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
) -> Result<Policy> {
    let raw_text = match custom_path {
        Some(p) => std::fs::read_to_string(p)
            .with_context(|| format!("failed to read policy file {}", p.display()))?,
        None => match defaults::builtin(profile) {
            Some(text) => text.to_string(),
            None => bail!(
                "unknown profile '{}'; known profiles: {}",
                profile,
                defaults::PROFILE_NAMES.join(", ")
            ),
        },
    };

    let raw: RawProfile = toml::from_str(&raw_text)
        .with_context(|| format!("failed to parse policy '{}'", profile))?;

    let mut warnings = Vec::new();
    let vars = Vars { project, home };

    // --- write roots -------------------------------------------------------
    let mut allow_write = resolve_list(&raw.filesystem.allow_write, &vars);

    // --- read roots --------------------------------------------------------
    let mut allow_read = resolve_list(&raw.filesystem.allow_read, &vars);

    // --- deny set ----------------------------------------------------------
    let deny_patterns = raw
        .display_only_deny
        .map(|d| d.paths)
        .unwrap_or_default();
    let mut deny_resolved: Vec<DenyEntry> = Vec::new();
    let mut deny_set: BTreeSet<PathBuf> = BTreeSet::new();
    for entry in &deny_patterns {
        for p in glob_resolve::resolve_entry(entry, &vars) {
            if deny_set.insert(p.clone()) {
                if let Ok(meta) = std::fs::symlink_metadata(&p) {
                    deny_resolved.push(DenyEntry {
                        path: p,
                        is_dir: meta.is_dir(),
                    });
                }
            }
        }
    }

    // --- FS-ONLY project masking by enumeration -----------------------------
    if tier == Tier::FsOnly {
        mask_project_reads_for_fs_only(
            &mut allow_read,
            &allow_write,
            &deny_set,
            &mut warnings,
        );
    }

    // Dedup + sanity checks.
    allow_write.sort();
    allow_write.dedup();
    allow_read.sort();
    allow_read.dedup();

    let mut policy = Policy {
        name: if custom_path.is_some() {
            format!("custom:{}", profile)
        } else {
            profile.to_string()
        },
        allow_write,
        allow_read,
        deny_resolved,
        warnings,
    };
    checker::check(&mut policy);
    Ok(policy)
}

fn resolve_list(entries: &[String], vars: &Vars) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for e in entries {
        for p in glob_resolve::resolve_entry(e, vars) {
            out.insert(p);
        }
    }
    out.into_iter().collect()
}

fn mask_project_reads_for_fs_only(
    allow_read: &mut Vec<PathBuf>,
    allow_write: &[PathBuf],
    deny_set: &BTreeSet<PathBuf>,
    warnings: &mut Vec<String>,
) {
    let project_roots: Vec<PathBuf> = allow_write
        .iter()
        .filter(|p| !is_temp_root(p))
        .cloned()
        .collect();
    if project_roots.is_empty() {
        return;
    }

    // Remove any existing whole-tree read rules that cover the project roots
    // (e.g. a broad "$HOME" read entry would defeat the enumeration).
    let before = allow_read.len();
    allow_read.retain(|p| !project_roots.iter().any(|r| p == r));
    if allow_read.len() != before {
        warnings.push(
            "fs-only tier: removed a read rule that covered a write root \
             wholesale (would have defeated secret masking)"
                .to_string(),
        );
    }

    let mut enumerated = 0usize;
    let mut excluded = 0usize;
    for root in &project_roots {
        if !root.exists() {
            continue;
        }
        if enumerate_tree(root, &deny_set, &mut allow_read, &mut enumerated, &mut excluded).is_err()
        {
            break; // budget exceeded -> fallback below
        }
    }

    if excluded > 0 {
        warnings.push(format!(
            "fs-only tier: {excluded} secret-shaped project file(s) excluded from read access \
             by tree enumeration"
        ));
    }

    if enumerated > FS_ONLY_ENUMERATION_BUDGET {
        warnings.push(
            "fs-only tier: project tree exceeds enumeration budget; falling back to \
             WHOLE-TREE read access. Intra-project secrets (.env, *.pem, *.key) are NOT \
             masked in this session. Prefer Tier FULL (enable unprivileged userns)."
                .to_string(),
        );
        // Restore whole-tree read+write semantics.
        *allow_read = allow_read
            .iter()
            .filter(|p| !project_roots.contains(p))
            .cloned()
            .collect();
        for r in &project_roots {
            allow_read.push(r.clone());
        }
    }
}

#[derive(PartialEq)]
enum Cleanliness {
    /// No denied path anywhere beneath this directory: it can become ONE
    /// blanket Landlock read rule covering the whole subtree.
    Clean,
    /// Contains at least one excluded path; children were emitted instead.
    Dirty,
}

/// Post-order walk emitting minimal read roots whose subtrees contain zero
/// secret-shaped / deny-listed paths. Opaque dependency dirs (.git,
/// node_modules, target) get their own blanket rules and do NOT taint the
/// parent (they are trusted caches per profile semantics; documented).
///
/// Returns `Err(())` when the enumeration budget is exceeded.
fn enumerate_tree(
    dir: &Path,
    deny_set: &BTreeSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    count: &mut usize,
    excluded: &mut usize,
) -> Result<Cleanliness, ()> {
    const SKIP_DIRS: [&str; 3] = [".git", "node_modules", "target"];

    if *count > FS_ONLY_ENUMERATION_BUDGET {
        return Err(());
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(Cleanliness::Dirty);
    };

    let mut all_clean = true;
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();

        if meta.is_dir() {
            if SKIP_DIRS.contains(&name.as_str()) {
                // Trusted opaque tree: blanket-read it without descending.
                *count += 1;
                out.push(path);
                continue;
            }
            match enumerate_tree(&path, deny_set, out, count, excluded) {
                Err(()) => return Err(()),
                Ok(Cleanliness::Clean) => {}
                Ok(Cleanliness::Dirty) => all_clean = false,
            }
            *count += 1;
        } else {
            *count += 1;
            if super::glob_resolve::is_secret_shaped(&path) || deny_set.contains(&path) {
                *excluded += 1;
                all_clean = false;
            }
        }
        if *count > FS_ONLY_ENUMERATION_BUDGET {
            return Err(());
        }
    }

    if all_clean {
        out.push(dir.to_path_buf());
        Ok(Cleanliness::Clean)
    } else {
        Ok(Cleanliness::Dirty)
    }
}

fn is_temp_root(p: &Path) -> bool {
    p == Path::new("/tmp")
}
