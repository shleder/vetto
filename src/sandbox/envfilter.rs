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

/// True if `name` looks secret-shaped (upper-cased compare).
pub fn is_hard_denied(name: &str) -> bool {
    let upper = name.to_uppercase();
    HARD_DENY_PREFIXES.iter().any(|p| upper.starts_with(p))
        || upper.contains("SECRET")
        || upper.contains("PRIVATE_KEY")
        || upper.contains("CREDENTIALS")
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
    fn path_sanitizer_cleans() {
        assert_eq!(sanitize_path("/a::./~/a"), "/a");
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
