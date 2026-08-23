//! Load-time resolution of `$PROJECT`/`$HOME`/`$AGENT` variables and glob patterns
//! into a finite set of concrete paths.
//!
//! Globs DO NOT exist at the enforcement layer: Landlock only understands
//! concrete paths, so every pattern is expanded here against the real
//! filesystem before any sandbox is built.

use std::path::{Path, PathBuf};

const GLOB_CHARS: [char; 3] = ['*', '?', '['];

pub struct Vars<'a> {
    pub project: &'a Path,
    pub home: &'a Path,
}

pub fn substitute(entry: &str, vars: &Vars) -> PathBuf {
    substitute_with_agent(entry, vars, None)
}

/// Substitute the built-in path variables, including an optional per-agent
/// compatibility root.  `$AGENT` is deliberately left untouched when no
/// agent is selected; the policy loader treats that as a hard error instead
/// of silently turning it into a literal path.
pub fn substitute_with_agent(entry: &str, vars: &Vars, agent: Option<&Path>) -> PathBuf {
    let s = entry
        .replace("$PROJECT", &vars.project.to_string_lossy())
        .replace("$HOME", &vars.home.to_string_lossy());
    let s = match agent {
        Some(agent) => s.replace("$AGENT", &agent.to_string_lossy()),
        None => s,
    };
    // Also tolerate a leading ~/ for user comfort.
    let s = if let Some(rest) = s.strip_prefix("~/") {
        format!("{}/{}", vars.home.display(), rest)
    } else {
        s
    };
    PathBuf::from(s)
}

fn has_glob(p: &Path) -> bool {
    p.to_string_lossy().chars().any(|c| GLOB_CHARS.contains(&c))
}

/// Resolve one profile entry into zero or more existing concrete paths.
/// Glob entries that match nothing resolve to an empty set (not an error).
pub fn resolve_entry(entry: &str, vars: &Vars) -> Vec<PathBuf> {
    resolve_entry_with_agent(entry, vars, None)
}

/// Resolve one entry with an optional agent compatibility root.
pub fn resolve_entry_with_agent(entry: &str, vars: &Vars, agent: Option<&Path>) -> Vec<PathBuf> {
    let substituted = substitute_with_agent(entry, vars, agent);
    if !has_glob(&substituted) {
        return vec![substituted];
    }

    let mut opts = glob::MatchOptions::new();
    opts.require_literal_leading_dot = false;
    opts.case_sensitive = true;

    let pattern = substituted.to_string_lossy().to_string();
    let mut out = Vec::new();
    if let Ok(paths) = glob::glob_with(&pattern, opts) {
        for p in paths.flatten() {
            out.push(p);
            // Guard against pathological patterns materializing huge sets.
            if out.len() >= 50_000 {
                break;
            }
        }
    }
    out
}

/// True when a concrete path matches the *shape* of secret files we always
/// refuse to expose from inside $PROJECT (used by FS-ONLY enumeration mode).
pub fn is_secret_shaped(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    if lower == ".env" || lower.starts_with(".env.") {
        return true;
    }
    lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".kdbx")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_shapes_are_case_insensitive() {
        for path in [
            ".ENV",
            ".Env.production",
            "PRIVATE.PEM",
            "CLIENT.Key",
            "IDENTITY.P12",
            "CERT.PfX",
            "PASSWORDS.KDBX",
        ] {
            assert!(is_secret_shaped(Path::new(path)), "missed {path}");
        }
    }

    #[test]
    fn agent_variable_substitutes_only_with_explicit_context() {
        let vars = Vars {
            project: Path::new("/project"),
            home: Path::new("/home/user"),
        };
        assert_eq!(
            substitute_with_agent("$AGENT/cache", &vars, Some(Path::new("/home/user/.codex"))),
            PathBuf::from("/home/user/.codex/cache")
        );
        assert_eq!(
            substitute("$AGENT/cache", &vars),
            PathBuf::from("$AGENT/cache")
        );
    }
}
