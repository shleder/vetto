//! Extended condition evaluator for policy layers.
//!
//! Predicates in the `[conditions]` table guard when a policy layer applies.
//! All specified conditions must hold (logical AND) for the layer to be merged.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

/// String or array form for convenient TOML condition definitions.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum RawStringOrList {
    One(String),
    Many(Vec<String>),
}

impl RawStringOrList {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }

    pub fn as_slice(&self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value.clone()],
            Self::Many(values) => values.clone(),
        }
    }
}

/// Raw condition predicates parsed from TOML `[conditions]`.
#[derive(Deserialize, Serialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RawConditions {
    #[serde(default)]
    pub branch: Option<RawStringOrList>,
    #[serde(default)]
    pub git_tag: Option<RawStringOrList>,
    #[serde(default)]
    pub env_set: Option<RawStringOrList>,
    #[serde(default)]
    pub env_matches: Option<HashMap<String, String>>,
    #[serde(default)]
    pub agent_is: Option<RawStringOrList>,
    #[serde(default)]
    pub os: Option<RawStringOrList>,
    #[serde(default)]
    pub ci_mode: Option<bool>,
    #[serde(default)]
    pub file_exists: Option<RawStringOrList>,
    #[serde(default)]
    pub project_contains: Option<RawStringOrList>,
}

/// Evaluation context supplied by the loader and runtime environment.
#[derive(Debug, Clone)]
pub struct ConditionContext<'a> {
    pub project: &'a Path,
    pub branch: Option<&'a str>,
    pub git_tag: Option<&'a str>,
    pub agent: Option<&'a str>,
    pub os: Option<&'a str>,
    pub env: Option<&'a HashMap<String, String>>,
}

impl<'a> ConditionContext<'a> {
    pub fn new(project: &'a Path) -> Self {
        Self {
            project,
            branch: None,
            git_tag: None,
            agent: None,
            os: None,
            env: None,
        }
    }
}

/// Evaluate all predicates in `conditions` against `context`.
pub fn conditions_match(conditions: &RawConditions, context: &ConditionContext<'_>) -> bool {
    // 1. Branch predicate
    if let Some(branches) = &conditions.branch {
        let branch_patterns = branches.as_slice();
        let Some(active_branch) = context.branch else {
            return false;
        };
        if !branch_patterns
            .iter()
            .any(|pattern| glob_match(pattern, active_branch))
        {
            return false;
        }
    }

    // 2. Git Tag predicate
    if let Some(tags) = &conditions.git_tag {
        let tag_patterns = tags.as_slice();
        let Some(active_tag) = context.git_tag else {
            return false;
        };
        if !tag_patterns
            .iter()
            .any(|pattern| glob_match(pattern, active_tag))
        {
            return false;
        }
    }

    // 3. Environment Variable Set predicate (`env_set`)
    if let Some(env_vars) = &conditions.env_set {
        for var in env_vars.as_slice() {
            if !is_env_set(var.as_str(), context.env) {
                return false;
            }
        }
    }

    // 4. Environment Variable Exact Matches predicate (`env_matches`)
    if let Some(matches) = &conditions.env_matches {
        for (key, expected_val) in matches {
            let actual_val = get_env_val(key, context.env);
            match actual_val {
                Some(val) if glob_match(expected_val, &val) => {}
                _ => return false,
            }
        }
    }

    // 5. Agent predicate (`agent_is`)
    if let Some(agents) = &conditions.agent_is {
        let agent_list = agents.as_slice();
        let Some(active_agent) = context.agent else {
            return false;
        };
        if !agent_list.iter().any(|candidate| candidate.eq_ignore_ascii_case(active_agent)) {
            return false;
        }
    }

    // 6. Host OS predicate (`os`)
    if let Some(os_list) = &conditions.os {
        let candidates = os_list.as_slice();
        let current_os = context.os.unwrap_or(std::env::consts::OS);
        let matches_os = candidates.iter().any(|candidate| {
            candidate.eq_ignore_ascii_case(current_os)
                || (candidate.eq_ignore_ascii_case("unix") && (current_os == "linux" || current_os == "macos"))
        });
        if !matches_os {
            return false;
        }
    }

    // 7. CI Mode predicate (`ci_mode`)
    if let Some(expected_ci) = conditions.ci_mode {
        let is_ci = is_ci_detected(context.env);
        if is_ci != expected_ci {
            return false;
        }
    }

    // 8. File Exists predicate (`file_exists`)
    if let Some(paths) = &conditions.file_exists {
        if !paths
            .as_slice()
            .iter()
            .all(|path| safe_project_file_exists(context.project, path))
        {
            return false;
        }
    }

    // 9. Project Contains predicate (`project_contains`)
    if let Some(needles) = &conditions.project_contains {
        if !needles
            .as_slice()
            .iter()
            .all(|needle| project_contains(context.project, needle))
        {
            return false;
        }
    }

    true
}

fn is_env_set(key: &str, custom_env: Option<&HashMap<String, String>>) -> bool {
    if let Some(env_map) = custom_env {
        return env_map.contains_key(key);
    }
    std::env::var_os(key).is_some()
}

fn get_env_val(key: &str, custom_env: Option<&HashMap<String, String>>) -> Option<String> {
    if let Some(env_map) = custom_env {
        return env_map.get(key).cloned();
    }
    std::env::var(key).ok()
}

fn is_ci_detected(custom_env: Option<&HashMap<String, String>>) -> bool {
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "TRAVIS", "CIRCLECI", "JENKINS_URL"] {
        if let Some(val) = get_env_val(var, custom_env) {
            let v = val.trim().to_ascii_lowercase();
            if v == "1" || v == "true" || !v.is_empty() {
                return true;
            }
        }
    }
    false
}

/// Simple glob matching for branches and tags (supporting '*' and exact matches).
pub fn glob_match(pattern: &str, candidate: &str) -> bool {
    if pattern == candidate || pattern == "*" {
        return true;
    }
    if let Ok(glob_pat) = glob::Pattern::new(pattern) {
        if glob_pat.matches(candidate) {
            return true;
        }
    }
    // Fallback prefix / suffix matching
    if let Some(prefix) = pattern.strip_suffix('*') {
        if candidate.starts_with(prefix) {
            return true;
        }
    }
    if let Some(suffix) = pattern.strip_prefix('*') {
        if candidate.ends_with(suffix) {
            return true;
        }
    }
    false
}

/// Detect active git branch from `.git/HEAD`.
pub fn detect_git_branch(project: &Path) -> Option<String> {
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

/// Detect active git tag from `.git` refs or HEAD.
pub fn detect_git_tag(project: &Path) -> Option<String> {
    let head_path = project.join(".git/HEAD");
    let head_content = std::fs::read_to_string(&head_path).ok()?.trim().to_string();

    let tag_ref_prefix = "ref: refs/tags/";
    if let Some(tag) = head_content.strip_prefix(tag_ref_prefix) {
        return Some(tag.to_string());
    }

    // Check if HEAD sha matches any tag in .git/refs/tags/
    let head_sha = if head_content.starts_with("ref: ") {
        let ref_rel = head_content.strip_prefix("ref: ")?.trim();
        let ref_path = project.join(".git").join(ref_rel);
        std::fs::read_to_string(ref_path).ok()?.trim().to_string()
    } else {
        head_content
    };

    let tags_dir = project.join(".git/refs/tags");
    if let Ok(entries) = std::fs::read_dir(tags_dir) {
        for entry in entries.flatten() {
            if let Ok(content) = std::fs::read_to_string(entry.path()) {
                if content.trim() == head_sha {
                    return Some(entry.file_name().to_string_lossy().to_string());
                }
            }
        }
    }

    // Check .git/packed-refs if present
    let packed_refs = project.join(".git/packed-refs");
    if let Ok(content) = std::fs::read_to_string(packed_refs) {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            let mut parts = line.split_whitespace();
            if let (Some(sha), Some(ref_name)) = (parts.next(), parts.next()) {
                if sha == head_sha {
                    if let Some(tag_name) = ref_name.strip_prefix("refs/tags/") {
                        return Some(tag_name.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Verify that `raw` path exists securely within `project` bounds without symlink traversal out.
pub fn safe_project_file_exists(project: &Path, raw: &str) -> bool {
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

pub fn project_contains(project: &Path, needle: &str) -> bool {
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
    let needle_bytes = needle.as_bytes();
    let mut files = 0usize;
    let mut bytes = 0usize;
    project_contains_in_dir(&project_absolute, needle_bytes, &mut files, &mut bytes)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_branch_matching() {
        let project = Path::new("/test");
        let mut ctx = ConditionContext::new(project);
        ctx.branch = Some("feature/security-hardened");

        let cond = RawConditions {
            branch: Some(RawStringOrList::One("feature/*".to_string())),
            ..Default::default()
        };
        assert!(conditions_match(&cond, &ctx));

        let cond_neg = RawConditions {
            branch: Some(RawStringOrList::One("main".to_string())),
            ..Default::default()
        };
        assert!(!conditions_match(&cond_neg, &ctx));
    }

    #[test]
    fn test_env_and_agent_matching() {
        let project = Path::new("/test");
        let mut env_map = HashMap::new();
        env_map.insert("CI".to_string(), "true".to_string());
        env_map.insert("BUILD_ENV".to_string(), "production".to_string());

        let mut ctx = ConditionContext::new(project);
        ctx.agent = Some("codex");
        ctx.env = Some(&env_map);
        ctx.os = Some("linux");

        let mut matches = HashMap::new();
        matches.insert("BUILD_ENV".to_string(), "prod*".to_string());

        let cond = RawConditions {
            agent_is: Some(RawStringOrList::Many(vec!["claude".into(), "codex".into()])),
            env_set: Some(RawStringOrList::One("CI".into())),
            env_matches: Some(matches),
            os: Some(RawStringOrList::One("linux".into())),
            ci_mode: Some(true),
            ..Default::default()
        };
        assert!(conditions_match(&cond, &ctx));

        let cond_wrong_agent = RawConditions {
            agent_is: Some(RawStringOrList::One("aider".into())),
            ..Default::default()
        };
        assert!(!conditions_match(&cond_wrong_agent, &ctx));

        let cond_not_ci = RawConditions {
            ci_mode: Some(false),
            ..Default::default()
        };
        assert!(!conditions_match(&cond_not_ci, &ctx));
    }
}
