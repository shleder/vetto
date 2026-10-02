//! Variable normalization, path resolution, and FS-ONLY masks.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Result};

use super::merge::MergedPolicy;
use crate::policy::checker;
use crate::policy::defaults;
use crate::policy::glob_resolve::{self, Vars};
use crate::policy::presets;
use crate::policy::secretscan;
use crate::policy::types::{
    lexical_normalize, DenyEntry, EnvironmentPolicy, Policy, SeccompProfile, Tier,
};

/// Enumeration budget for FS-ONLY project masking (entries, not bytes).
pub const FS_ONLY_ENUMERATION_BUDGET: usize = 20_000;

pub const PACKAGE_CACHE_PATHS: &[&str] = &[
    ".npm",
    ".cache/pip",
    ".cache/uv",
    ".cache/yarn",
    ".cargo/registry",
    ".cargo/git",
    "go/pkg/mod",
    ".cache/ms-playwright",
    ".cache/puppeteer",
    ".cache/huggingface",
    ".cache/transformers",
    ".cache/torch",
];

pub fn resolve_package_cache_paths(home: &Path) -> Vec<PathBuf> {
    PACKAGE_CACHE_PATHS.iter().map(|p| home.join(p)).collect()
}

pub fn agent_root(home: &Path, agent: &str) -> Result<PathBuf> {
    let canon = defaults::canonical_agent_name(agent).unwrap_or(agent);
    let suffix = match canon {
        "codex" => PathBuf::from(".codex"),
        "claude" => PathBuf::from(".claude"),
        "antigravity" | "agy" => PathBuf::from(".gemini"),
        "aider" => PathBuf::from(".aider"),
        "cursor" => PathBuf::from(".cursor"),
        "cline" => PathBuf::from(".cline"),
        "opencode" => PathBuf::from(".config/opencode"),
        "copilot" => PathBuf::from(".config/github-copilot"),
        "windsurf" => PathBuf::from(".windsurf"),
        "goose" => PathBuf::from(".config/goose"),
        "openhands" => PathBuf::from(".openhands"),
        "devin" => PathBuf::from(".devin"),
        "smolagents" => PathBuf::from(".cache/smolagents"),
        "amp" => PathBuf::from(".amp"),
        "omp" => PathBuf::from(".omp"),
        "zcode" => PathBuf::from(".zcode"),
        "kimi" => PathBuf::from(".kimi"),
        "grok" => PathBuf::from(".grok"),
        "hermes" => PathBuf::from(".hermes"),
        "kilo" => PathBuf::from(".kilo"),
        "pi" => PathBuf::from(".pi"),
        "command_code" => PathBuf::from(".command-code"),
        "freebuff" => PathBuf::from(".freebuff"),
        "deepseek_harness" => PathBuf::from(".deepseek"),
        "omnigent" => PathBuf::from(".omnigent"),
        "crewai" => PathBuf::from(".crewai"),
        "autogen" => PathBuf::from(".autogen"),
        "custom" => PathBuf::from(".config/vetto/agents/custom"),
        _ => bail!(
            "unknown agent '{}'; known agents: {}",
            agent,
            defaults::AGENT_PROFILE_NAMES.join(", ")
        ),
    };
    Ok(home.join(suffix))
}

pub fn build_policy(
    profile: &str,
    custom: bool,
    project: &Path,
    home: &Path,
    tier: Tier,
    merged: &MergedPolicy,
    agent: Option<&Path>,
) -> Result<Policy> {
    let runtime_dir = resolve_runtime_dir();
    let vars = Vars {
        project,
        home,
        runtime_dir: runtime_dir.as_deref(),
    };
    let mut warnings = Vec::new();

    let mut allow_write_resolved = resolve_list(&merged.allow_write, &vars, agent)?;
    let mut allow_read_resolved = resolve_list(&merged.allow_read, &vars, agent)?;
    let mut deny_write_resolved = resolve_list(&merged.deny_write, &vars, agent)?;
    let deny_read_resolved = resolve_list(&merged.deny_read, &vars, agent)?;
    let ro_mounts_resolved = resolve_list(&merged.ro_mounts, &vars, agent)?;

    for ro in &ro_mounts_resolved {
        if !allow_read_resolved.contains(ro) {
            allow_read_resolved.push(ro.clone());
        }
    }

    if merged.read_only_caches {
        for cache_path in resolve_package_cache_paths(home) {
            if !allow_read_resolved.contains(&cache_path) {
                allow_read_resolved.push(cache_path.clone());
            }
            if !deny_write_resolved.contains(&cache_path) {
                deny_write_resolved.push(cache_path.clone());
            }
            allow_write_resolved.retain(|p| p != &cache_path && !p.starts_with(&cache_path));
        }
    }

    let mut deny_resolved = Vec::new();
    let mut deny_set = BTreeSet::new();

    // Accumulate all deny sources: deny_paths, deny_read, deny_write, deny_preset, deny_glob, deny_unix_sockets
    let mut all_deny_entries: Vec<String> = merged
        .deny_paths
        .iter()
        .chain(merged.deny_read.iter())
        .chain(merged.deny_write.iter())
        .chain(merged.deny_unix_sockets.iter())
        .cloned()
        .collect();

    for preset_name in &merged.deny_preset {
        if let Some(paths) = presets::resolve_preset(preset_name) {
            for p in paths {
                all_deny_entries.push((*p).to_string());
            }
        } else {
            warnings.push(format!("unknown deny_preset '{preset_name}'"));
        }
    }

    for glob_pat in &merged.deny_glob {
        all_deny_entries.push(glob_pat.clone());
    }

    for entry in &all_deny_entries {
        for path in resolve_list(std::slice::from_ref(entry), &vars, agent)? {
            if let Some(agent_dir) = agent {
                if path == agent_dir {
                    continue;
                }
            }
            if deny_set.insert(path.clone()) {
                if let Ok(meta) = std::fs::symlink_metadata(&path) {
                    deny_resolved.push(DenyEntry {
                        path,
                        is_dir: meta.is_dir(),
                    });
                }
            }
        }
    }

    if merged.auto_deny_secrets {
        let scan_result =
            secretscan::scan_directory(project, &secretscan::SecretScanOptions::default());
        if scan_result.timed_out {
            warnings.push("auto_deny_secrets scan timed out; partial scan completed".to_string());
        }
        for secret_path in scan_result.unique_paths() {
            if deny_set.insert(secret_path.clone()) {
                deny_resolved.push(DenyEntry {
                    path: secret_path,
                    is_dir: false,
                });
            }
        }
    }

    // Subtractive rules enforcement on resolved allow roots:
    // 1. Remove deny_write paths from allow_write
    if !deny_write_resolved.is_empty() {
        allow_write_resolved.retain(|allowed| {
            !deny_write_resolved
                .iter()
                .any(|denied| allowed == denied || allowed.starts_with(denied))
        });
    }

    // 2. Remove deny_read paths from allow_read
    if !deny_read_resolved.is_empty() {
        allow_read_resolved.retain(|allowed| {
            !deny_read_resolved
                .iter()
                .any(|denied| allowed == denied || allowed.starts_with(denied))
        });
    }

    if tier == Tier::FsOnly {
        mask_project_reads_for_fs_only(
            &mut allow_read_resolved,
            &allow_write_resolved,
            &deny_set,
            &mut warnings,
            project,
        )?;
    }

    if !merged.allow_unix_sockets.is_empty() {
        if let Ok(unix_paths) = resolve_list(&merged.allow_unix_sockets, &vars, agent) {
            for up in unix_paths {
                if !allow_read_resolved.contains(&up) {
                    allow_read_resolved.push(up.clone());
                }
                if !allow_write_resolved.contains(&up) {
                    allow_write_resolved.push(up);
                }
            }
        }
    }

    if !merged.deny_unix_sockets.is_empty() {
        if let Ok(denied_sock_paths) = resolve_list(&merged.deny_unix_sockets, &vars, agent) {
            allow_write_resolved.retain(|allowed| {
                !denied_sock_paths
                    .iter()
                    .any(|denied| allowed == denied || allowed.starts_with(denied))
            });
            allow_read_resolved.retain(|allowed| {
                !denied_sock_paths
                    .iter()
                    .any(|denied| allowed == denied || allowed.starts_with(denied))
            });
        }
    }

    allow_write_resolved.sort();
    allow_write_resolved.dedup();
    allow_read_resolved.sort();
    allow_read_resolved.dedup();

    let metadata = merged.metadata.clone();
    let name = if metadata.name.is_empty() {
        if custom {
            format!("custom:{profile}")
        } else {
            profile.to_string()
        }
    } else {
        metadata.name.clone()
    };

    let seccomp_profile = match merged.seccomp_profile.as_deref() {
        Some(name) => match SeccompProfile::parse(name) {
            Some(prof) => prof,
            None => bail!("unknown seccomp_profile '{name}'; known profiles: default, agent-min"),
        },
        None => SeccompProfile::Default,
    };

    let mut policy = Policy {
        name,
        metadata,
        limits: merged.limits.clone(),
        allow_write: allow_write_resolved,
        allow_read: allow_read_resolved,
        deny_write: deny_write_resolved,
        deny_read: deny_read_resolved,
        deny_resolved,
        environment: EnvironmentPolicy {
            pass_through: normalize_env_patterns(merged.pass_through.clone()),
            deny: normalize_env_patterns(merged.deny_env.clone()),
        },
        deny_network: !merged.deny_network.is_empty(),
        network_mode: merged.network_mode.clone(),
        network_allow: merged.network_allow.clone(),
        allow_cidr: merged.allow_cidr.clone(),
        net_quota: merged.net_quota.clone(),
        net_bind_ports: merged.net_bind_ports.clone(),
        net_connect_ports: merged.net_connect_ports.clone(),
        allow_unix_sockets: merged.allow_unix_sockets.clone(),
        deny_unix_sockets: merged.deny_unix_sockets.clone(),
        seccomp_profile,
        seccomp_notify: merged.seccomp_notify.clone(),
        cgroup: merged.cgroup.clone(),
        cpu_max: merged.cpu_max.clone(),
        io_priority: merged.io_priority.clone(),
        dev_allow: merged.dev_allow.clone(),
        oslog: merged.oslog,
        lpac: merged.lpac,
        is_immutable: merged.is_immutable,
        system_log: merged.system_log,
        auto_deny_secrets: merged.auto_deny_secrets,
        secret_proxies: merged.secret_proxies.clone(),
        ro_mounts: ro_mounts_resolved,
        git_guard: merged.git_guard,
        snapshot: merged.snapshot,
        read_only_caches: merged.read_only_caches,
        shadow: merged.shadow,
        tmpfs_tmp: merged.tmpfs_tmp.unwrap_or(true),
        warnings,
    };
    checker::check(&mut policy)?;
    Ok(policy)
}

pub fn resolve_runtime_dir() -> Option<PathBuf> {
    if let Some(val) = std::env::var_os("XDG_RUNTIME_DIR") {
        if !val.is_empty() {
            return Some(PathBuf::from(val));
        }
    }
    #[cfg(target_os = "linux")]
    {
        let uid = unsafe { libc::getuid() };
        Some(PathBuf::from(format!("/run/user/{uid}")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub fn normalize_env_patterns(patterns: Vec<String>) -> Vec<String> {
    let mut out = BTreeSet::new();
    for pattern in patterns {
        let prefix = pattern.strip_suffix('*').unwrap_or(&pattern);
        if prefix.is_empty()
            || pattern == "*"
            || pattern.contains('=')
            || pattern.contains('\0')
            || prefix
                .chars()
                .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_'))
            || (pattern.contains('*') && !pattern.ends_with('*'))
        {
            continue;
        }
        out.insert(pattern);
    }
    out.into_iter().collect()
}

pub fn resolve_list(
    entries: &[String],
    vars: &Vars,
    agent: Option<&Path>,
) -> Result<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    for e in entries {
        if e.contains("$AGENT") && agent.is_none() {
            bail!("policy path '{}' requires an agent context for $AGENT", e);
        }
        for p in glob_resolve::resolve_entry_with_agent(e, vars, agent) {
            out.insert(p);
        }
    }
    Ok(out.into_iter().collect())
}

pub fn absolute_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    Some(if path.is_absolute() {
        path.to_path_buf()
    } else {
        let base = if base.is_absolute() {
            base.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(base)
        };
        base.join(path)
    })
}

pub fn lexical_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    absolute_for_containment(path, base).map(|absolute| lexical_normalize(&absolute))
}

pub fn normalize_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    let absolute = absolute_for_containment(path, base)?;

    if let Ok(canonical) = std::fs::canonicalize(&absolute) {
        return Some(canonical);
    }

    let mut unresolved: Vec<OsString> = Vec::new();
    let mut cursor = absolute.as_path();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(cursor) {
            let mut resolved = canonical;
            for component in unresolved.iter().rev() {
                resolved.push(component);
            }
            return Some(lexical_normalize(&resolved));
        }

        let name = cursor.file_name()?.to_os_string();
        unresolved.push(name);
        let parent = cursor.parent()?;
        if parent == cursor {
            return None;
        }
        cursor = parent;
    }
}

pub fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

pub fn mask_project_reads_for_fs_only(
    allow_read: &mut Vec<PathBuf>,
    allow_write: &[PathBuf],
    deny_set: &BTreeSet<PathBuf>,
    warnings: &mut Vec<String>,
    project: &Path,
) -> Result<()> {
    let project_roots: Vec<PathBuf> = allow_write
        .iter()
        .filter(|p| !is_temp_root(p))
        .cloned()
        .collect();
    if project_roots.is_empty() {
        return Ok(());
    }

    let dir_roots: Vec<PathBuf> = project_roots
        .iter()
        .filter(|root| {
            std::fs::symlink_metadata(root)
                .map(|m| m.is_dir())
                .unwrap_or(false)
        })
        .cloned()
        .collect();

    let normalized_dir_roots: Vec<(PathBuf, PathBuf)> = dir_roots
        .iter()
        .map(|root| {
            Some((
                lexical_for_containment(root, project)?,
                normalize_for_containment(root, project)?,
            ))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow!("fs-only tier: could not normalize a project root safely"))?;
    let before = allow_read.len();
    allow_read.retain(|p| {
        let Some(lexical) = lexical_for_containment(p, project) else {
            return false;
        };
        let Some(normalized) = normalize_for_containment(p, project) else {
            return false;
        };
        !normalized_dir_roots
            .iter()
            .any(|(root_lexical, root_canonical)| {
                paths_overlap(&lexical, root_lexical) || paths_overlap(&normalized, root_canonical)
            })
    });
    if allow_read.len() != before {
        warnings.push(
            "fs-only tier: removed a read rule that covered a write root \
             wholesale (would have defeated secret masking)"
                .to_string(),
        );
    }

    let mut enumerated = 0usize;
    let mut excluded = 0usize;
    for root in &dir_roots {
        match enumerate_tree(root, deny_set, allow_read, &mut enumerated, &mut excluded) {
            Ok(_) => {}
            Err(EnumerationError::BudgetExceeded) => {
                bail!(
                    "fs-only tier: project tree exceeds the {}-entry enumeration budget; refusing to run rather than fall back to whole-tree read access",
                    FS_ONLY_ENUMERATION_BUDGET
                );
            }
            Err(EnumerationError::Io {
                operation,
                path,
                source,
            }) => {
                bail!(
                    "fs-only tier: {operation} failed for '{}': {source}; refusing to run",
                    path.display()
                );
            }
        }
    }

    for root in &project_roots {
        if is_enumeration_excluded(root, deny_set) {
            if let Some(pos) = allow_read.iter().position(|p| p == root) {
                allow_read.remove(pos);
                excluded += 1;
            }
        }
    }

    if excluded > 0 {
        warnings.push(format!(
            "fs-only tier: {excluded} secret-shaped or denied project entry(s) excluded from read access \
             by tree enumeration"
        ));
    }

    debug_assert!(enumerated <= FS_ONLY_ENUMERATION_BUDGET);
    Ok(())
}

#[derive(Debug, PartialEq)]
pub enum Cleanliness {
    Clean,
    Dirty,
}

#[derive(Debug)]
pub enum EnumerationError {
    BudgetExceeded,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

pub fn is_enumeration_excluded(path: &Path, deny_set: &BTreeSet<PathBuf>) -> bool {
    deny_set.contains(path) || glob_resolve::is_secret_shaped(path)
}

pub fn enumerate_tree(
    dir: &Path,
    deny_set: &BTreeSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    count: &mut usize,
    excluded: &mut usize,
) -> std::result::Result<Cleanliness, EnumerationError> {
    if *count > FS_ONLY_ENUMERATION_BUDGET {
        return Err(EnumerationError::BudgetExceeded);
    }

    if is_enumeration_excluded(dir, deny_set) {
        *excluded += 1;
        return Ok(Cleanliness::Dirty);
    }

    let out_start = out.len();
    let entries = std::fs::read_dir(dir).map_err(|source| EnumerationError::Io {
        operation: "read_dir",
        path: dir.to_path_buf(),
        source,
    })?;

    let mut all_clean = true;
    for entry in entries {
        let entry = entry.map_err(|source| EnumerationError::Io {
            operation: "directory entry iteration",
            path: dir.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        *count += 1;
        if *count > FS_ONLY_ENUMERATION_BUDGET {
            return Err(EnumerationError::BudgetExceeded);
        }

        let meta = std::fs::symlink_metadata(&path).map_err(|source| EnumerationError::Io {
            operation: "symlink_metadata",
            path: path.clone(),
            source,
        })?;
        if meta.is_dir() {
            if is_enumeration_excluded(&path, deny_set) {
                *excluded += 1;
                all_clean = false;
                continue;
            }
            match enumerate_tree(&path, deny_set, out, count, excluded) {
                Err(error) => return Err(error),
                Ok(Cleanliness::Clean) => {}
                Ok(Cleanliness::Dirty) => all_clean = false,
            }
        } else if meta.file_type().is_symlink() {
            all_clean = false;
        } else {
            if is_enumeration_excluded(&path, deny_set) {
                *excluded += 1;
                all_clean = false;
            } else {
                out.push(path);
            }
        }
    }

    if all_clean {
        out.truncate(out_start);
        out.push(dir.to_path_buf());
        Ok(Cleanliness::Clean)
    } else {
        Ok(Cleanliness::Dirty)
    }
}

pub fn is_temp_root(p: &Path) -> bool {
    p == Path::new("/tmp") || p == Path::new("/var/tmp") || p.starts_with("/dev/")
}
