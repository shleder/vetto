//! Policy loading: profile name/context -> resolved `Policy`.
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
//!    excluding secret-shaped files and directories. Writes stay whole-tree so agents can
//!    still create new files. If the tree exceeds the enumeration budget we
//!    fail closed rather than reintroducing a project-wide read rule.

use std::collections::{BTreeSet, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use super::checker;
use super::defaults;
use super::glob_resolve::{self, Vars};
use super::types::{DenyEntry, EnvironmentPolicy, Policy, PolicyMetadata, ResourceLimits, Tier};

/// Enumeration budget for FS-ONLY project masking (entries, not bytes).
const FS_ONLY_ENUMERATION_BUDGET: usize = 20_000;

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields)]
struct RawLayer {
    #[serde(default)]
    metadata: Option<RawMetadata>,
    #[serde(default)]
    filesystem: Option<RawFilesystem>,
    #[serde(default)]
    display_only_deny: Option<RawDeny>,
    #[serde(default)]
    environment: Option<RawEnvironment>,
    #[serde(default)]
    conditions: Option<RawConditions>,
    #[serde(default)]
    limits: Option<RawLimits>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawMetadata {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    extends: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawFilesystem {
    #[serde(default)]
    allow_write: Option<RawStringList>,
    #[serde(default)]
    allow_read: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawDeny {
    #[serde(default)]
    paths: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawEnvironment {
    #[serde(default)]
    pass_through: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawConditions {
    #[serde(default)]
    branch: Option<RawStringList>,
    #[serde(default)]
    file_exists: Option<RawStringList>,
    #[serde(default)]
    project_contains: Option<RawStringList>,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields)]
struct RawLimits {
    #[serde(default)]
    cpu_seconds: Option<u64>,
    #[serde(default)]
    address_space_bytes: Option<u64>,
    #[serde(default)]
    processes: Option<u64>,
    #[serde(default)]
    open_files: Option<u64>,
}

impl RawLimits {
    fn to_resource_limits(&self) -> ResourceLimits {
        ResourceLimits {
            cpu_seconds: self.cpu_seconds,
            address_space_bytes: self.address_space_bytes,
            processes: self.processes,
            open_files: self.open_files,
        }
    }
}

/// A small string-or-array form keeps conditions and inheritance convenient
/// without introducing a general policy language.
#[derive(Deserialize, Debug, Clone)]
#[serde(untagged)]
enum RawStringList {
    One(String),
    Many(Vec<String>),
}

impl RawStringList {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Default)]
struct MergedPolicy {
    metadata: PolicyMetadata,
    limits: ResourceLimits,
    allow_write: Vec<String>,
    allow_read: Vec<String>,
    deny_paths: Vec<String>,
    pass_through: Vec<String>,
}

impl MergedPolicy {
    fn apply(&mut self, layer: &RawLayer) {
        if let Some(metadata) = &layer.metadata {
            if let Some(name) = &metadata.name {
                if !name.is_empty() {
                    self.metadata.name = name.clone();
                }
            }
            if let Some(description) = &metadata.description {
                self.metadata.description = description.clone();
            }
        }

        if let Some(filesystem) = &layer.filesystem {
            if let Some(allow_write) = &filesystem.allow_write {
                self.allow_write.extend(allow_write.clone().into_vec());
            }
            if let Some(allow_read) = &filesystem.allow_read {
                self.allow_read.extend(allow_read.clone().into_vec());
            }
        }
        if let Some(deny) = &layer.display_only_deny {
            if let Some(paths) = &deny.paths {
                self.deny_paths.extend(paths.clone().into_vec());
            }
        }
        if let Some(environment) = &layer.environment {
            if let Some(pass_through) = &environment.pass_through {
                self.pass_through.extend(pass_through.clone().into_vec());
            }
        }
        if let Some(limits) = &layer.limits {
            self.limits.merge_strictest(&limits.to_resource_limits());
        }
    }

    fn deduplicate(&mut self) {
        deduplicate_strings(&mut self.allow_write);
        deduplicate_strings(&mut self.allow_read);
        deduplicate_strings(&mut self.deny_paths);
        deduplicate_strings(&mut self.pass_through);
        deduplicate_strings(&mut self.metadata.extends);
    }
}

/// Additive command-line-ready policy changes. There is intentionally no
/// clear, replace, or remove operation: a compatibility override cannot erase
/// a base deny rule or replace the base environment allowlist.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyOverrides {
    pub allow_write: Vec<String>,
    pub allow_read: Vec<String>,
    pub display_only_deny: Vec<String>,
    pub pass_through: Vec<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub limits: Option<ResourceLimits>,
}

/// Context for the layered policy loader. The default enables the project
/// `vetto.toml` layer when it exists; the legacy `load` API opts out so its
/// historical callers retain base-profile-only behavior.
#[derive(Debug, Clone)]
pub struct PolicyLoadOptions {
    pub agent: Option<String>,
    pub branch: Option<String>,
    pub project_policy: Option<PathBuf>,
    pub include_project_policy: bool,
    pub overrides: PolicyOverrides,
}

impl Default for PolicyLoadOptions {
    fn default() -> Self {
        Self {
            agent: None,
            branch: None,
            project_policy: None,
            include_project_policy: true,
            overrides: PolicyOverrides::default(),
        }
    }
}

struct ConditionContext<'a> {
    project: &'a Path,
    branch: Option<&'a str>,
}

/// Known agent roots are fixed rather than derived from arbitrary input.
fn agent_root(home: &Path, agent: &str) -> Result<PathBuf> {
    let suffix = match agent {
        "codex" => PathBuf::from(".codex"),
        "claude" => PathBuf::from(".claude"),
        "aider" => PathBuf::from(".aider"),
        "cursor" => PathBuf::from(".cursor"),
        "cline" => PathBuf::from(".cline"),
        "opencode" => PathBuf::from(".config/opencode"),
        "copilot" => PathBuf::from(".config/github-copilot"),
        "custom" => PathBuf::from(".config/vetto/agents/custom"),
        _ => bail!(
            "unknown agent '{}'; known agents: {}",
            agent,
            defaults::AGENT_PROFILE_NAMES.join(", ")
        ),
    };
    Ok(home.join(suffix))
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
    let options = PolicyLoadOptions {
        include_project_policy: false,
        ..PolicyLoadOptions::default()
    };
    load_with_options(profile, custom_path, project, home, tier, &options)
}

/// Load a policy with optional agent, project, condition, and CLI override
/// context. Layers are applied in this order:
/// built-in profile -> inherited profiles -> agent preset -> project
/// `vetto.toml` -> explicit CLI policy -> additive CLI overrides.
pub fn load_with_options(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
    options: &PolicyLoadOptions,
) -> Result<Policy> {
    let mut merged = MergedPolicy::default();
    merged.metadata.name = if custom_path.is_some() {
        format!("custom:{profile}")
    } else {
        profile.to_string()
    };

    let branch = options
        .branch
        .clone()
        .or_else(|| detect_git_branch(project));
    let context = ConditionContext {
        project,
        branch: branch.as_deref(),
    };
    // A custom `--policy` historically allowed an arbitrary display name.
    // Keep that compatibility by allowing an unknown profile only when the
    // explicit file supplies the base layer; named profiles remain strict.
    let base_profile = defaults::builtin(profile).map(|_| profile);
    if base_profile.is_none() && custom_path.is_none() {
        bail!(
            "unknown profile '{}'; known profiles: {}",
            profile,
            defaults::PROFILE_NAMES.join(", ")
        );
    }
    let mut stack = base_profile
        .map(|profile| vec![profile.to_string()])
        .unwrap_or_default();

    if let Some(base_profile) = base_profile {
        let base_text = defaults::builtin(base_profile).expect("base profile checked above");
        let base = parse_layer(base_text, base_profile)?;
        // Keep the safe environment baseline if a built-in profile omits
        // `[environment]`; later layers remain additive.
        if base.environment.is_none() {
            merged.pass_through = defaults::default_env_passthrough();
        }
        merge_layer(&base, base_profile, &context, &mut stack, &mut merged)?;
    }

    let agent_path = match options.agent.as_deref() {
        Some(agent) => Some(agent_root(home, agent)?),
        None => None,
    };
    if let Some(agent) = options.agent.as_deref() {
        let text = defaults::agent_builtin(agent).ok_or_else(|| {
            anyhow!(
                "unknown agent '{}'; known agents: {}",
                agent,
                defaults::AGENT_PROFILE_NAMES.join(", ")
            )
        })?;
        let layer = parse_layer(text, &format!("agent:{agent}"))?;
        merge_layer(
            &layer,
            &format!("agent:{agent}"),
            &context,
            &mut stack,
            &mut merged,
        )?;
    }

    let mut applied_project_path = None;
    if options.include_project_policy {
        let (path, explicit) = match &options.project_policy {
            Some(path) => (Some(path.clone()), true),
            None => {
                let path = project.join("vetto.toml");
                let usable = std::fs::symlink_metadata(&path)
                    .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
                    .unwrap_or(false);
                (usable.then_some(path), false)
            }
        };
        if let Some(path) = path {
            if explicit
                && std::fs::symlink_metadata(&path)
                    .map(|metadata| metadata.file_type().is_symlink())
                    .unwrap_or(false)
            {
                bail!(
                    "project policy file '{}' must not be a symlink",
                    path.display()
                );
            }
            let text = std::fs::read_to_string(&path).with_context(|| {
                format!("failed to read project policy file {}", path.display())
            })?;
            let label = path.display().to_string();
            let layer = parse_layer(&text, &label)?;
            merge_layer(&layer, &label, &context, &mut stack, &mut merged)?;
            applied_project_path = Some(path);
        } else if explicit {
            let path = options
                .project_policy
                .as_deref()
                .map_or_else(|| Path::new("vetto.toml"), |path| path);
            bail!("project policy file '{}' was not found", path.display());
        }
    }

    // `--policy` is an explicit CLI layer, so it is applied after the
    // project policy even when it points at the same file. Avoid only the
    // exact duplicate case, preserving deterministic additive semantics.
    if let Some(path) = custom_path {
        let duplicate_project = applied_project_path
            .as_deref()
            .and_then(|project_path| same_file_path(project_path, path))
            .unwrap_or(false);
        if !duplicate_project {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read policy file {}", path.display()))?;
            let label = format!("cli:{}", path.display());
            let layer = parse_layer(&text, &label)?;
            merge_layer(&layer, &label, &context, &mut stack, &mut merged)?;
        }
    }

    apply_overrides(&mut merged, &options.overrides);
    merged.deduplicate();
    if merged.allow_write.is_empty() {
        bail!("effective policy has no filesystem.allow_write roots");
    }

    build_policy(
        profile,
        custom_path.is_some(),
        project,
        home,
        tier,
        &merged,
        agent_path.as_deref(),
    )
}

/// Compatibility alias for callers that prefer an explicit context name.
pub fn load_with_context(
    profile: &str,
    custom_path: Option<&Path>,
    project: &Path,
    home: &Path,
    tier: Tier,
    options: &PolicyLoadOptions,
) -> Result<Policy> {
    load_with_options(profile, custom_path, project, home, tier, options)
}

fn parse_layer(text: &str, label: &str) -> Result<RawLayer> {
    toml::from_str(text).with_context(|| format!("failed to parse policy '{label}'"))
}

fn merge_layer(
    layer: &RawLayer,
    source: &str,
    context: &ConditionContext<'_>,
    stack: &mut Vec<String>,
    merged: &mut MergedPolicy,
) -> Result<()> {
    if let Some(conditions) = &layer.conditions {
        if !conditions_match(conditions, context) {
            return Ok(());
        }
    }

    let parents = layer
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.extends.clone())
        .map(RawStringList::into_vec)
        .unwrap_or_default();
    for parent in parents {
        validate_parent_name(&parent)?;
        if stack.iter().any(|current| current == &parent) {
            bail!("policy inheritance cycle involving '{parent}' in {source}");
        }
        let text = defaults::builtin(&parent).ok_or_else(|| {
            anyhow!(
                "unknown inherited profile '{}'; only built-in profiles may be extended",
                parent
            )
        })?;
        let parent_layer = parse_layer(text, &format!("inherited:{parent}"))?;
        stack.push(parent.clone());
        merge_layer(
            &parent_layer,
            &format!("inherited:{parent}"),
            context,
            stack,
            merged,
        )?;
        stack.pop();
        if !merged.metadata.extends.contains(&parent) {
            merged.metadata.extends.push(parent);
        }
    }

    merged.apply(layer);
    Ok(())
}

fn validate_parent_name(parent: &str) -> Result<()> {
    if parent.is_empty()
        || parent == "."
        || parent == ".."
        || parent.contains('/')
        || parent.contains('\\')
        || parent
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '_' || ch == '-'))
    {
        bail!("invalid inherited profile name '{parent}'");
    }
    Ok(())
}

fn apply_overrides(merged: &mut MergedPolicy, overrides: &PolicyOverrides) {
    merged.allow_write.extend(overrides.allow_write.clone());
    merged.allow_read.extend(overrides.allow_read.clone());
    merged
        .deny_paths
        .extend(overrides.display_only_deny.clone());
    merged.pass_through.extend(overrides.pass_through.clone());
    if let Some(name) = &overrides.name {
        if !name.is_empty() {
            merged.metadata.name = name.clone();
        }
    }
    if let Some(description) = &overrides.description {
        merged.metadata.description = description.clone();
    }
    if let Some(limits) = &overrides.limits {
        merged.limits.merge_strictest(limits);
    }
}

fn build_policy(
    profile: &str,
    custom: bool,
    project: &Path,
    home: &Path,
    tier: Tier,
    merged: &MergedPolicy,
    agent: Option<&Path>,
) -> Result<Policy> {
    let vars = Vars { project, home };
    let mut warnings = Vec::new();
    let mut allow_write = resolve_list(&merged.allow_write, &vars, agent)?;
    let mut allow_read = resolve_list(&merged.allow_read, &vars, agent)?;

    let mut deny_resolved = Vec::new();
    let mut deny_set = BTreeSet::new();
    for entry in &merged.deny_paths {
        for path in resolve_list(std::slice::from_ref(entry), &vars, agent)? {
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

    if tier == Tier::FsOnly {
        mask_project_reads_for_fs_only(
            &mut allow_read,
            &allow_write,
            &deny_set,
            &mut warnings,
            project,
        )?;
    }

    allow_write.sort();
    allow_write.dedup();
    allow_read.sort();
    allow_read.dedup();
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
    let mut policy = Policy {
        name,
        metadata,
        limits: merged.limits.clone(),
        allow_write,
        allow_read,
        deny_resolved,
        environment: EnvironmentPolicy {
            pass_through: normalize_env_patterns(merged.pass_through.clone()),
        },
        warnings,
    };
    checker::check(&mut policy);
    Ok(policy)
}

fn deduplicate_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn same_file_path(left: &Path, right: &Path) -> Option<bool> {
    let left = std::fs::canonicalize(left).ok()?;
    let right = std::fs::canonicalize(right).ok()?;
    Some(left == right)
}

fn normalize_env_patterns(patterns: Vec<String>) -> Vec<String> {
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

fn resolve_list(entries: &[String], vars: &Vars, agent: Option<&Path>) -> Result<Vec<PathBuf>> {
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

fn detect_git_branch(project: &Path) -> Option<String> {
    let head_path = project.join(".git/HEAD");
    let metadata = std::fs::symlink_metadata(&head_path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    let head = std::fs::read_to_string(head_path).ok()?;
    let reference = head.trim().strip_prefix("ref: refs/heads/")?;
    if reference.is_empty() || reference.contains('\0') || reference.contains("..") {
        return None;
    }
    Some(reference.to_string())
}

fn conditions_match(conditions: &RawConditions, context: &ConditionContext<'_>) -> bool {
    if let Some(branches) = &conditions.branch {
        let branches = branches.clone().into_vec();
        if !context
            .branch
            .is_some_and(|branch| branches.iter().any(|candidate| candidate == branch))
        {
            return false;
        }
    }
    if let Some(paths) = &conditions.file_exists {
        if !paths
            .clone()
            .into_vec()
            .iter()
            .all(|path| safe_project_file_exists(context.project, path))
        {
            return false;
        }
    }
    if let Some(needles) = &conditions.project_contains {
        if !needles
            .clone()
            .into_vec()
            .iter()
            .all(|needle| project_contains(context.project, needle))
        {
            return false;
        }
    }
    true
}

fn safe_project_file_exists(project: &Path, raw: &str) -> bool {
    if raw.is_empty() || raw.contains("$HOME") || raw.contains("$AGENT") {
        return false;
    }
    let Some(project_absolute) =
        absolute_for_containment(Path::new("."), project).map(|path| lexical_normalize(&path))
    else {
        return false;
    };
    let (relative, project_variable) = match raw.strip_prefix("$PROJECT") {
        Some(relative) => (relative.trim_start_matches(['/', '\\']), true),
        None => (raw, false),
    };
    let candidate = if !project_variable && Path::new(relative).is_absolute() {
        PathBuf::from(relative)
    } else {
        project_absolute.join(relative.trim_start_matches(['/', '\\']))
    };
    let Some(project_root) = lexical_for_containment(&project_absolute, &project_absolute) else {
        return false;
    };
    let Some(candidate_lexical) = lexical_for_containment(&candidate, &project_absolute) else {
        return false;
    };
    if !candidate_lexical.starts_with(&project_root) {
        return false;
    }
    !contains_symlink_component(&project_absolute, &candidate_lexical)
}

fn contains_symlink_component(project: &Path, candidate: &Path) -> bool {
    let Some(project_root) = lexical_for_containment(project, project) else {
        return true;
    };
    let Ok(relative) = candidate.strip_prefix(&project_root) else {
        return true;
    };
    let mut cursor = project.to_path_buf();
    let Ok(root_metadata) = std::fs::symlink_metadata(&cursor) else {
        return true;
    };
    if root_metadata.file_type().is_symlink() {
        return true;
    }
    for component in relative.components() {
        let Component::Normal(component) = component else {
            continue;
        };
        cursor.push(component);
        let Ok(metadata) = std::fs::symlink_metadata(&cursor) else {
            return true;
        };
        if metadata.file_type().is_symlink() {
            return true;
        }
    }
    false
}

const PROJECT_CONTAINS_FILE_BUDGET: usize = 4_096;
const PROJECT_CONTAINS_BYTE_BUDGET: usize = 8 * 1024 * 1024;

fn project_contains(project: &Path, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let Some(project_absolute) =
        absolute_for_containment(Path::new("."), project).map(|path| lexical_normalize(&path))
    else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(&project_absolute) else {
        return false;
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return false;
    }
    let needle = needle.as_bytes();
    let mut files = 0usize;
    let mut bytes = 0usize;
    project_contains_in_dir(&project_absolute, needle, &mut files, &mut bytes)
}

fn project_contains_in_dir(
    dir: &Path,
    needle: &[u8],
    files: &mut usize,
    bytes: &mut usize,
) -> bool {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return false;
    };
    for entry in entries.flatten() {
        if *files >= PROJECT_CONTAINS_FILE_BUDGET || *bytes >= PROJECT_CONTAINS_BYTE_BUDGET {
            return false;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if metadata.file_type().is_symlink() || super::glob_resolve::is_secret_shaped(&path) {
            continue;
        }
        if metadata.is_dir() {
            if project_contains_in_dir(&path, needle, files, bytes) {
                return true;
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        *files += 1;
        let remaining = PROJECT_CONTAINS_BYTE_BUDGET.saturating_sub(*bytes);
        let Ok(file) = std::fs::File::open(&path) else {
            continue;
        };
        let mut content = Vec::new();
        let read = file
            .take(remaining as u64)
            .read_to_end(&mut content)
            .unwrap_or(0);
        *bytes = (*bytes).saturating_add(read);
        if content.windows(needle.len()).any(|window| window == needle) {
            return true;
        }
    }
    false
}

/// Make a policy path absolute without following symlinks.
fn absolute_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
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

fn lexical_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
    absolute_for_containment(path, base).map(|absolute| lexical_normalize(&absolute))
}

/// Normalize a policy path for containment comparisons.
///
/// Existing paths are canonicalized first, so symlink aliases compare by
/// their resolved target. For a path that does not exist yet, walk upward to
/// the nearest canonicalizable ancestor and append the remaining components;
/// an unresolvable path returns `None` so callers can drop it fail-closed.
fn normalize_for_containment(path: &Path, base: &Path) -> Option<PathBuf> {
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

/// Collapse `.` and `..` without following symlinks. This is only the
/// fallback for non-existent suffixes after existing ancestors were
/// canonicalized.
fn lexical_normalize(path: &Path) -> PathBuf {
    let has_root = path.has_root();
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() && !has_root {
                    normalized.push(component.as_os_str());
                }
            }
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    normalized
}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn mask_project_reads_for_fs_only(
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

    // Remove every read rule that intersects a project root. Both ancestors
    // and descendants can re-grant a secret after enumeration; aliases must
    // be normalized first so `..`, `.`, and existing symlinks cannot evade
    // this check.
    let normalized_project_roots: Vec<(PathBuf, PathBuf)> = project_roots
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
            // A rule that cannot be normalized is unusable safely; dropping
            // it is fail-closed and cannot widen the readable tree.
            return false;
        };
        !normalized_project_roots
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
    for root in &project_roots {
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
enum Cleanliness {
    /// No denied path anywhere beneath this directory: it can become ONE
    /// blanket Landlock read rule covering the whole subtree.
    Clean,
    /// Contains at least one excluded path; children were emitted instead.
    Dirty,
}

#[derive(Debug)]
enum EnumerationError {
    BudgetExceeded,
    Io {
        operation: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
}

fn is_enumeration_excluded(path: &Path, deny_set: &BTreeSet<PathBuf>) -> bool {
    deny_set.contains(path) || super::glob_resolve::is_secret_shaped(path)
}

/// Post-order walk emitting minimal read roots whose subtrees contain zero
/// secret-shaped / deny-listed paths. Every directory is traversed, including
/// `.git`, `node_modules`, and `target`; no opaque-directory blanket bypass is
/// allowed. The enumeration budget bounds the total walk.
///
/// Returns an error when the enumeration budget is exceeded or any filesystem
/// operation fails. A partial walk is never treated as clean, because doing so
/// could emit a blanket read rule over entries that were not inspected.
fn enumerate_tree(
    dir: &Path,
    deny_set: &BTreeSet<PathBuf>,
    out: &mut Vec<PathBuf>,
    count: &mut usize,
    excluded: &mut usize,
) -> std::result::Result<Cleanliness, EnumerationError> {
    if *count > FS_ONLY_ENUMERATION_BUDGET {
        return Err(EnumerationError::BudgetExceeded);
    }

    // Check the root itself before opening it. This covers a denied or
    // secret-shaped project root as well as directories below the root, and
    // intentionally avoids recursing into an excluded subtree at all.
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
            // Never turn a symlink into an enforcement rule. Landlock makes
            // its decision on the resolved inode, but omitting the alias is
            // the simplest fail-closed behavior for the enumerated tier.
            all_clean = false;
        } else {
            if is_enumeration_excluded(&path, deny_set) {
                *excluded += 1;
                all_clean = false;
            } else {
                // If a sibling later makes this directory dirty, ordinary
                // files still need exact read/execute rules. A clean parent
                // collapses these entries back to one directory rule below.
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

fn is_temp_root(p: &Path) -> bool {
    // Not "project" roots for enumeration purposes: temp sinks and device
    // sinks are global, not part of the agent's project tree.
    p == Path::new("/tmp") || p.starts_with("/dev/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumeration_budget_returns_error_instead_of_fallback() {
        let root = std::env::temp_dir().join(format!("vetto-policy-budget-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("ordinary.txt"), "ok").unwrap();

        let mut out = Vec::new();
        let mut count = FS_ONLY_ENUMERATION_BUDGET;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        let _ = std::fs::remove_dir_all(&root);
        assert!(result.is_err(), "budget overflow must be an error");
        assert!(out.is_empty(), "overflow must not emit a read root");
    }

    #[test]
    fn enumeration_read_dir_failure_is_fatal() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-missing-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        assert!(
            matches!(
                &result,
                Err(EnumerationError::Io {
                    operation: "read_dir",
                    ..
                })
            ),
            "missing roots must fail instead of becoming Dirty: {result:?}"
        );
        assert!(out.is_empty(), "failed walks must not emit read roots");
    }

    #[test]
    fn fs_only_propagates_walk_failures_to_policy_load() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-missing-mask-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let mut allow_read = vec![PathBuf::from("/dev/null")];
        let mut warnings = Vec::new();
        let result = mask_project_reads_for_fs_only(
            &mut allow_read,
            std::slice::from_ref(&root),
            &BTreeSet::new(),
            &mut warnings,
            &root,
        );

        assert!(
            result.is_err(),
            "a failed project walk must reject FS-ONLY policy"
        );
        assert_eq!(allow_read, vec![PathBuf::from("/dev/null")]);
    }

    #[test]
    fn denied_directories_are_pruned_before_recursion_including_root() {
        let root = std::env::temp_dir().join(format!("vetto-policy-denied-{}", std::process::id()));
        let denied_child = root.join("private");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&denied_child).unwrap();
        std::fs::write(denied_child.join("ordinary.txt"), "must not be walked").unwrap();

        let mut deny_set = BTreeSet::new();
        deny_set.insert(denied_child.clone());
        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &deny_set, &mut out, &mut count, &mut excluded);

        assert!(matches!(result, Ok(Cleanliness::Dirty)));
        assert_eq!(excluded, 1, "the denied child itself is excluded");
        assert!(
            out.is_empty(),
            "a denied descendant must prevent a blanket rule"
        );

        let _ = std::fs::remove_dir_all(&root);

        let denied_root =
            std::env::temp_dir().join(format!("vetto-policy-denied-root-{}", std::process::id()));
        std::fs::create_dir_all(denied_root.join("nested")).unwrap();
        std::fs::write(denied_root.join("nested/file.txt"), "must not be walked").unwrap();
        let mut deny_set = BTreeSet::new();
        deny_set.insert(denied_root.clone());
        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&denied_root, &deny_set, &mut out, &mut count, &mut excluded);

        assert!(matches!(result, Ok(Cleanliness::Dirty)));
        assert_eq!(excluded, 1, "the denied root itself is excluded");
        assert_eq!(count, 0, "a denied root must not be recursed into");
        assert!(
            out.is_empty(),
            "a denied root must not become a blanket rule"
        );
        let _ = std::fs::remove_dir_all(&denied_root);
    }

    #[test]
    fn secret_shaped_directories_are_pruned_before_recursion() {
        let root = std::env::temp_dir().join(format!(
            "vetto-policy-secret-dir-{}.pem",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("nested")).unwrap();
        std::fs::write(root.join("nested/ordinary.txt"), "must not be walked").unwrap();

        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        assert!(matches!(result, Ok(Cleanliness::Dirty)));
        assert_eq!(excluded, 1, "the secret-shaped root itself is excluded");
        assert_eq!(count, 0, "a secret-shaped root must not be recursed into");
        assert!(
            out.is_empty(),
            "a secret-shaped root must not become a blanket rule"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn dirty_directory_keeps_exact_rules_for_ordinary_file_siblings() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-dirty-sibling-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join(".env"), "secret").unwrap();
        std::fs::write(root.join("agent-bin"), "ordinary").unwrap();

        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        assert!(matches!(result, Ok(Cleanliness::Dirty)));
        assert_eq!(excluded, 1);
        assert_eq!(out, vec![root.join("agent-bin")]);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn fs_only_removes_intersecting_read_aliases() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-overlap-{}", std::process::id()));
        let ancestor = root.parent().unwrap().to_path_buf();
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("subdir")).unwrap();

        let mut allow_read = vec![
            ancestor.clone(),
            root.join("subdir"),
            root.join("subdir/../subdir"),
            PathBuf::from("/dev/null"),
        ];

        #[cfg(unix)]
        let alias = {
            use std::os::unix::fs::symlink;
            let alias = root.with_extension("alias");
            let _ = std::fs::remove_file(&alias);
            symlink(&root, &alias).unwrap();
            allow_read.push(alias.join("subdir"));
            alias
        };

        let mut warnings = Vec::new();
        mask_project_reads_for_fs_only(
            &mut allow_read,
            std::slice::from_ref(&root),
            &BTreeSet::new(),
            &mut warnings,
            &root,
        )
        .unwrap();

        #[cfg(unix)]
        let _ = std::fs::remove_file(&alias);

        assert!(allow_read.contains(&PathBuf::from("/dev/null")));
        assert!(!allow_read.contains(&ancestor));
        assert!(allow_read
            .iter()
            .all(|path| path == Path::new("/dev/null") || path.starts_with(&root)));
        #[cfg(unix)]
        assert!(!allow_read.iter().any(|path| path.starts_with(&alias)));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn opaque_directory_names_are_recursed_for_secrets() {
        let root = std::env::temp_dir().join(format!("vetto-policy-opaque-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (dir, file) in [
            (".git", ".env"),
            ("node_modules", "credential.pem"),
            ("target", "private.key"),
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join(file), "secret").unwrap();
        }

        let mut out = Vec::new();
        let mut count = 0;
        let mut excluded = 0;
        let result = enumerate_tree(&root, &BTreeSet::new(), &mut out, &mut count, &mut excluded);

        let _ = std::fs::remove_dir_all(&root);
        assert!(matches!(result, Ok(Cleanliness::Dirty)));
        assert_eq!(excluded, 3);
        assert!(
            out.is_empty(),
            "secret-bearing opaque dirs must not be blanket-read"
        );
    }

    #[test]
    fn supported_policy_sections_load_and_unknown_fields_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "vetto-policy-schema-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let policy_path = root.join("policy.toml");
        let valid = r#"
[filesystem]
allow_write = ["$PROJECT"]
allow_read = ["/dev/null"]

[metadata]
name = "schema-positive"
description = "schema test"

[display_only_deny]
paths = ["$PROJECT/.env"]

[environment]
pass_through = ["HOME"]
"#;
        std::fs::write(&policy_path, valid).unwrap();
        let loaded = load(
            "schema-positive",
            Some(&policy_path),
            &root,
            &root,
            Tier::Full,
        )
        .expect("all currently supported policy sections should load");
        assert_eq!(loaded.allow_write, vec![root.clone()]);
        assert_eq!(loaded.metadata.name, "schema-positive");
        assert_eq!(loaded.metadata.description, "schema test");
        assert_eq!(loaded.environment.pass_through, vec!["HOME".to_string()]);

        // Unknown top-level names are still rejected. Silently accepting one
        // would make a user believe a requested restriction was active.
        for (tag, extra) in [
            ("network", "network = \"off\""),
            ("network table", "[network]\nmode = \"off\""),
            ("project table", "[project]\nname = \"demo\""),
            ("secrets table", "[secrets]\npaths = []"),
            (
                "agent overrides table",
                "[agent_overrides]\nallow_read = []",
            ),
            ("ci table", "[ci]\nstrict = true"),
            ("future", "future_option = true"),
        ] {
            let text = format!("{valid}\n{extra}\n");
            std::fs::write(&policy_path, text).unwrap();
            let error = load(
                "schema-negative",
                Some(&policy_path),
                &root,
                &root,
                Tier::Full,
            )
            .expect_err("unknown top-level policy fields must be rejected");
            assert!(
                format!("{error:#}").contains("unknown field"),
                "{tag} should report an unknown field, got: {error:#}"
            );
        }

        for (tag, text) in [
            (
                "metadata nested unknown",
                "[filesystem]\nallow_write = [\"$PROJECT\"]\n[metadata]\nowner = \"security\"\n",
            ),
            (
                "filesystem nested unknown",
                "[filesystem]\nallow_write = [\"$PROJECT\"]\nmetadata = true\n",
            ),
            (
                "deny nested unknown",
                "[filesystem]\nallow_write = [\"$PROJECT\"]\n[display_only_deny]\nconditions = []\n",
            ),
            (
                "environment nested unknown",
                "[filesystem]\nallow_write = [\"$PROJECT\"]\n[environment]\nnetwork = true\n",
            ),
            (
                "conditions nested unknown",
                "[filesystem]\nallow_write = [\"$PROJECT\"]\n[conditions]\nnetwork = true\n",
            ),
        ] {
            std::fs::write(&policy_path, text).unwrap();
            let error = load(
                "schema-negative-nested",
                Some(&policy_path),
                &root,
                &root,
                Tier::Full,
            )
            .expect_err("unknown nested policy fields must be rejected");
            assert!(
                format!("{error:#}").contains("unknown field"),
                "{tag} should report an unknown field, got: {error:#}"
            );
        }

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn layered_policy_supports_inheritance_conditions_agent_and_overrides() {
        let root = std::env::temp_dir().join(format!(
            "vetto-policy-layered-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock before epoch")
                .as_nanos()
        ));
        let home = root.join("home");
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(root.join("src/marker.txt"), "layer-marker").unwrap();
        let project_policy = root.join("vetto.toml");
        std::fs::write(
            &project_policy,
            r#"
[metadata]
name = "project-policy"
description = "project layer"
extends = "strict"

[conditions]
branch = "feature/security"
file_exists = "src/marker.txt"
project_contains = "layer-marker"

[filesystem]
allow_read = ["$PROJECT/src"]

[environment]
pass_through = ["SAFE_PROJECT_VAR"]
"#,
        )
        .unwrap();

        let options = PolicyLoadOptions {
            branch: Some("feature/security".to_string()),
            agent: Some("codex".to_string()),
            overrides: PolicyOverrides {
                allow_read: vec!["/dev/zero".to_string()],
                pass_through: vec!["SAFE_CLI_VAR".to_string()],
                description: Some("CLI layer".to_string()),
                ..PolicyOverrides::default()
            },
            ..PolicyLoadOptions::default()
        };
        let policy = load_with_options("default", None, &root, &home, Tier::Full, &options)
            .expect("all supported layers should load");

        assert_eq!(policy.metadata.name, "project-policy");
        assert_eq!(policy.metadata.description, "CLI layer");
        assert!(policy.metadata.extends.contains(&"strict".to_string()));
        assert!(policy.allow_read.contains(&root.join("src")));
        assert!(policy.allow_read.contains(&PathBuf::from("/dev/zero")));
        assert!(policy
            .environment
            .pass_through
            .contains(&"SAFE_PROJECT_VAR".to_string()));
        assert!(policy
            .environment
            .pass_through
            .contains(&"SAFE_CLI_VAR".to_string()));
        assert!(policy.allow_read.contains(&home.join(".codex/cache")));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn conditions_false_skip_project_layer_and_agent_requires_context() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-conditions-{}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let project_policy = root.join("vetto.toml");
        std::fs::write(
            &project_policy,
            r#"
[conditions]
branch = "never-this-branch"
[filesystem]
allow_read = ["$PROJECT/conditional-read"]
"#,
        )
        .unwrap();

        let policy = load_with_options(
            "default",
            None,
            &root,
            &home,
            Tier::Full,
            &PolicyLoadOptions::default(),
        )
        .unwrap();
        assert!(!policy.allow_read.contains(&root.join("conditional-read")));

        let bad = root.join("bad.toml");
        std::fs::write(&bad, "[filesystem]\nallow_write = [\"$AGENT/work\"]\n").unwrap();
        let error = load("bad-agent-context", Some(&bad), &root, &home, Tier::Full)
            .expect_err("$AGENT must not be accepted without an agent context");
        assert!(error.to_string().contains("requires an agent context"));

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn environment_normalization_never_turns_star_into_full_inheritance() {
        let values = normalize_env_patterns(vec![
            "*".to_string(),
            "LC_*".to_string(),
            "SAFE_NAME".to_string(),
            "BAD-NAME".to_string(),
        ]);
        assert_eq!(values, vec!["LC_*".to_string(), "SAFE_NAME".to_string()]);
    }

    #[test]
    fn limits_merge_only_tightens_and_unknown_limit_fields_fail() {
        let root = std::env::temp_dir().join(format!("vetto-policy-limits-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let base = root.join("base.toml");
        std::fs::write(
            &base,
            r#"
[filesystem]
allow_write = ["$PROJECT"]

[limits]
cpu_seconds = 100
address_space_bytes = 2000
processes = 30
open_files = 400
"#,
        )
        .unwrap();
        let project = root.join("vetto.toml");
        std::fs::write(
            &project,
            r#"
[limits]
cpu_seconds = 50
address_space_bytes = 4000
processes = 20
open_files = 500
"#,
        )
        .unwrap();
        let options = PolicyLoadOptions {
            project_policy: Some(project.clone()),
            overrides: PolicyOverrides {
                limits: Some(ResourceLimits {
                    cpu_seconds: Some(75),
                    address_space_bytes: Some(1000),
                    processes: Some(40),
                    open_files: Some(100),
                }),
                ..PolicyOverrides::default()
            },
            ..PolicyLoadOptions::default()
        };
        let policy =
            load_with_options("custom", Some(&base), &root, &root, Tier::Full, &options).unwrap();
        assert_eq!(policy.limits.cpu_seconds, Some(50));
        assert_eq!(policy.limits.address_space_bytes, Some(1000));
        assert_eq!(policy.limits.processes, Some(20));
        assert_eq!(policy.limits.open_files, Some(100));

        std::fs::write(&project, "[limits]\nunknown_limit = 1\n").unwrap();
        let error = load_with_options(
            "custom",
            Some(&base),
            &root,
            &root,
            Tier::Full,
            &PolicyLoadOptions::default(),
        )
        .expect_err("unknown limits fields must be rejected");
        assert!(format!("{error:#}").contains("unknown field"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn inheritance_rejects_unknown_profiles_and_cycles() {
        let root =
            std::env::temp_dir().join(format!("vetto-policy-inheritance-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("policy.toml");
        std::fs::write(
            &path,
            "[metadata]\nextends = \"does-not-exist\"\n[filesystem]\nallow_write = [\"$PROJECT\"]\n",
        )
        .unwrap();
        let unknown = load_with_options(
            "custom",
            Some(&path),
            &root,
            &root,
            Tier::Full,
            &PolicyLoadOptions {
                include_project_policy: false,
                ..PolicyLoadOptions::default()
            },
        )
        .expect_err("unknown inherited profiles must fail closed");
        assert!(unknown.to_string().contains("unknown inherited profile"));

        std::fs::write(
            &path,
            "[metadata]\nextends = \"../strict\"\n[filesystem]\nallow_write = [\"$PROJECT\"]\n",
        )
        .unwrap();
        let traversal = load_with_options(
            "custom",
            Some(&path),
            &root,
            &root,
            Tier::Full,
            &PolicyLoadOptions {
                include_project_policy: false,
                ..PolicyLoadOptions::default()
            },
        )
        .expect_err("inherited profile names must not become paths");
        assert!(traversal
            .to_string()
            .contains("invalid inherited profile name"));
        let _ = std::fs::remove_dir_all(root);
    }
}
