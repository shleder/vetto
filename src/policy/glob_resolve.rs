//! Load-time resolution of `$PROJECT`/`$HOME` variables and glob patterns
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
    let s = entry
        .replace("$PROJECT", &vars.project.to_string_lossy())
        .replace("$HOME", &vars.home.to_string_lossy());
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
    let substituted = substitute(entry, vars);
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
    if name == ".env" || name.starts_with(".env.") {
        return true;
    }
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".pem")
        || lower.ends_with(".key")
        || lower.ends_with(".p12")
        || lower.ends_with(".pfx")
        || lower.ends_with(".kdbx")
}
