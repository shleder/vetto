//! Shared environment boundary filter: PATH sanitizing + secret-name deny.
//!
//! Used by every sandbox backend before `exec`. Matching is case-insensitive
//! on Windows (env names collide regardless of spelling, W1) and
//! case-sensitive elsewhere. Values containing NUL are always dropped: no
//! backend can pass them to `execve` / `CreateProcess` anyway (M1).

/// Secret-shaped env name prefixes (upper-cased compare). Anything matching
/// is never inherited from the parent, on any platform.
pub const HARD_DENY_PREFIXES: &[&str] = &[
    "AWS_",
    "GCP_",
    "GOOGLE_",
    "AZURE_",
    "OPENAI_",
    "ANTHROPIC_",
    "CLAUDE_",
    "CODEX_",
    "GH_",
    "GITHUB_",
    "GITLAB_",
    "NPM_",
    "PYPI_",
    "DOCKER_",
    "KUBE",
    "VAULT_",
    "SECRET",
    "TOKEN",
    "PRIVATE",
    "CREDENTIAL",
    "LDAP_",
    "DB_",
    "DATABASE_",
    "STRIPE_",
    "SENDGRID_",
    "SLACK_",
    "DISCORD_",
    "TELEGRAM_",
    "TWILIO_",
    "API_KEY",
    "AUTH_",
    "SESSION_",
    "COOKIE_",
    "BEARER",
    "BASIC_",
    "OAUTH",
];

/// Mandatory redacted wildcard patterns fulfilling INV-27 (NEXT_GEN §23).
/// Any environment variable matching any of these patterns is scrubbed.
pub const DEFAULT_REDACTED_PATTERNS: &[&str] = &[
    "*_KEY",
    "*_TOKEN",
    "*_SECRET",
    "AWS_*",
    "GITHUB_*",
    "GH_*",
    "ANTHROPIC_*",
    "OPENAI_*",
    "CODEX_*",
    "CLAUDE_*",
    "AZURE_*",
    "GCP_*",
    "GOOGLE_*",
    "*_PASSWORD",
    "*_CREDENTIAL",
    "*_CREDENTIALS",
    "*_AUTH",
    "*_PRIVATE_KEY",
];

/// Matches a string against a glob/wildcard pattern containing `*` and `?`.
/// Matching is case-insensitive for environment variable protection.
pub fn matches_wildcard_pattern(pattern: &str, text: &str) -> bool {
    let p_bytes: Vec<u8> = pattern
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect();
    let t_bytes: Vec<u8> = text
        .as_bytes()
        .iter()
        .map(|b| b.to_ascii_uppercase())
        .collect();

    let mut p_idx = 0;
    let mut t_idx = 0;
    let mut star_idx = None;
    let mut match_idx = 0;

    while t_idx < t_bytes.len() {
        if p_idx < p_bytes.len() && (p_bytes[p_idx] == b'?' || p_bytes[p_idx] == t_bytes[t_idx]) {
            p_idx += 1;
            t_idx += 1;
        } else if p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
            star_idx = Some(p_idx);
            match_idx = t_idx;
            p_idx += 1;
        } else if let Some(s_idx) = star_idx {
            p_idx = s_idx + 1;
            match_idx += 1;
            t_idx = match_idx;
        } else {
            return false;
        }
    }

    while p_idx < p_bytes.len() && p_bytes[p_idx] == b'*' {
        p_idx += 1;
    }

    p_idx == p_bytes.len()
}

/// True if `name` looks secret-shaped or matches any redacted wildcard pattern (INV-27).
pub fn is_hard_denied(name: &str) -> bool {
    let upper = name.to_uppercase();
    HARD_DENY_PREFIXES.iter().any(|p| upper.starts_with(p))
        || DEFAULT_REDACTED_PATTERNS
            .iter()
            .any(|pat| matches_wildcard_pattern(pat, &upper))
        || upper.contains("SECRET")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("CREDENTIALS")
        || upper.ends_with("_KEY")
        || upper.ends_with("_TOKEN")
        || upper.ends_with("_SECRET")
}

/// Checks whether `name` is hard-denied or matches any caller-provided redacted patterns.
pub fn is_redacted(name: &str, patterns: &[String]) -> bool {
    if is_hard_denied(name) {
        return true;
    }
    patterns
        .iter()
        .any(|pat| matches_wildcard_pattern(pat, name))
}

/// Sanitize a PATH-like value: drop empty components, `.`, and `~`-relative
/// entries, dedup preserving order. Empty result falls back to a minimal
/// system PATH so the child can still exec.
pub fn sanitize_path(path: &str) -> String {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for comp in path.split(':') {
        if comp.is_empty() || comp == "." || comp.starts_with('~') {
            continue;
        }
        if seen.insert(comp.to_string()) {
            out.push(comp);
        }
    }
    if out.is_empty() {
        return "/usr/bin:/bin".to_string();
    }
    out.join(":")
}

/// Filter `(name, value)` pairs: drop hard-denied names, names with `=` or
/// NUL, and pairs whose value contains NUL. With `strict_path`, PATH values
/// (case-insensitive name) go through [`sanitize_path`].
pub fn filter_env(
    vars: impl Iterator<Item = (String, String)>,
    strict_path: bool,
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in vars {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            continue;
        }
        if value.contains('\0') {
            continue;
        }
        if is_hard_denied(&name) {
            continue;
        }
        if strict_path && name.eq_ignore_ascii_case("PATH") {
            out.push((name, sanitize_path(&value)));
        } else {
            out.push((name, value));
        }
    }
    out
}

/// Filter `(name, value)` pairs using caller-provided redacted wildcard patterns alongside
/// hard-denied names (INV-27).
pub fn filter_env_with_patterns(
    vars: impl Iterator<Item = (String, String)>,
    strict_path: bool,
    redacted_patterns: &[String],
) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (name, value) in vars {
        if name.is_empty() || name.contains('=') || name.contains('\0') {
            continue;
        }
        if value.contains('\0') {
            continue;
        }
        if is_redacted(&name, redacted_patterns) {
            continue;
        }
        if strict_path && name.eq_ignore_ascii_case("PATH") {
            out.push((name, sanitize_path(&value)));
        } else {
            out.push((name, value));
        }
    }
    out
}

/// Sanitizes the environment by filtering out variables matching redacted wildcard patterns
/// (such as `*_KEY`, `*_TOKEN`, `*_SECRET`, `AWS_*`, `GITHUB_*`). Fulfills INV-27.
pub fn sanitize_environment(
    vars: impl Iterator<Item = (String, String)>,
    redacted_patterns: &[String],
) -> Vec<(String, String)> {
    filter_env_with_patterns(vars, true, redacted_patterns)
}

#[cfg(test)]
mod envfilter_tests {
    use super::*;

    #[test]
    fn hard_deny_catches_lowercase_aws() {
        assert!(is_hard_denied("aws_secret_access_key"));
        assert!(is_hard_denied("GH_TOKEN"));
        assert!(!is_hard_denied("PATH"));
        assert!(!is_hard_denied("HOME"));
    }

    #[test]
    fn wildcard_matching_patterns() {
        assert!(matches_wildcard_pattern("*_KEY", "OPENAI_API_KEY"));
        assert!(matches_wildcard_pattern("*_KEY", "CUSTOM_KEY"));
        assert!(matches_wildcard_pattern("*_KEY", "api_key"));
        assert!(matches_wildcard_pattern("*_TOKEN", "GITHUB_TOKEN"));
        assert!(matches_wildcard_pattern("*_TOKEN", "USER_TOKEN"));
        assert!(matches_wildcard_pattern("*_SECRET", "CLIENT_SECRET"));
        assert!(matches_wildcard_pattern("AWS_*", "AWS_ACCESS_KEY_ID"));
        assert!(matches_wildcard_pattern("AWS_*", "aws_default_region"));
        assert!(matches_wildcard_pattern("GITHUB_*", "GITHUB_SHA"));

        assert!(!matches_wildcard_pattern("*_KEY", "KEYBOARD"));
        assert!(!matches_wildcard_pattern("*_KEY", "key"));
        assert!(!matches_wildcard_pattern("*_KEY", "PATH"));
        assert!(!matches_wildcard_pattern("AWS_*", "NOT_AWS"));
    }

    #[test]
    fn is_hard_denied_catches_wildcard_suffixes() {
        assert!(is_hard_denied("CUSTOM_KEY"));
        assert!(is_hard_denied("APP_TOKEN"));
        assert!(is_hard_denied("CLIENT_SECRET"));
        assert!(is_hard_denied("AWS_DEFAULT_REGION"));
        assert!(is_hard_denied("GITHUB_ACTIONS"));
        assert!(!is_hard_denied("USER"));
        assert!(!is_hard_denied("EDITOR"));
    }

    #[test]
    fn sanitize_environment_scrubs_wildcards() {
        let vars = vec![
            ("CUSTOM_KEY".to_string(), "secret123".to_string()),
            ("APP_TOKEN".to_string(), "tok456".to_string()),
            ("USER".to_string(), "alice".to_string()),
            ("PATH".to_string(), "/bin:/usr/bin".to_string()),
            ("MY_CUSTOM_SECRET".to_string(), "val".to_string()),
        ];
        let cleaned = sanitize_environment(vars.into_iter(), &[]);
        let names: Vec<String> = cleaned.into_iter().map(|(k, _)| k).collect();
        assert_eq!(names, vec!["USER".to_string(), "PATH".to_string()]);
    }

    #[test]
    fn path_sanitizer_cleans() {
        assert_eq!(sanitize_path("/a::.:~/x:/a"), "/a");
        assert_eq!(sanitize_path(""), "/usr/bin:/bin");
        assert_eq!(sanitize_path("/b:/a:/b"), "/b:/a");
    }

    #[test]
    fn filter_env_drops_secrets_and_nul() {
        let vars = vec![
            ("SECRET_FOO".to_string(), "x".to_string()),
            ("PATH".to_string(), "/a::/b".to_string()),
            ("BAD\0NAME".to_string(), "x".to_string()),
            ("OK".to_string(), "a\0b".to_string()),
            ("HOME".to_string(), "/h".to_string()),
        ];
        let got = filter_env(vars.into_iter(), true);
        assert_eq!(
            got,
            vec![
                ("PATH".to_string(), "/a:/b".to_string()),
                ("HOME".to_string(), "/h".to_string()),
            ]
        );
    }
}
