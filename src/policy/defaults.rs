//! Built-in profiles, embedded at compile time from /profiles.

pub const DEFAULT_TOML: &str = include_str!("../../profiles/default.toml");
pub const STRICT_TOML: &str = include_str!("../../profiles/strict.toml");
pub const AUDIT_TOML: &str = include_str!("../../profiles/audit.toml");
pub const PERMISSIVE_TOML: &str = include_str!("../../profiles/permissive.toml");

pub const PROFILE_NAMES: [&str; 4] = ["default", "strict", "audit", "permissive"];

pub const CODEX_AGENT_TOML: &str = include_str!("../../profiles/agents/codex.toml");
pub const CLAUDE_AGENT_TOML: &str = include_str!("../../profiles/agents/claude.toml");
pub const GEMINI_AGENT_TOML: &str = include_str!("../../profiles/agents/gemini.toml");
pub const AIDER_AGENT_TOML: &str = include_str!("../../profiles/agents/aider.toml");
pub const CURSOR_AGENT_TOML: &str = include_str!("../../profiles/agents/cursor.toml");
pub const CLINE_AGENT_TOML: &str = include_str!("../../profiles/agents/cline.toml");
pub const OPENCODE_AGENT_TOML: &str = include_str!("../../profiles/agents/opencode.toml");
pub const COPILOT_AGENT_TOML: &str = include_str!("../../profiles/agents/copilot.toml");
pub const CUSTOM_AGENT_TOML: &str = include_str!("../../profiles/agents/custom.toml");

pub const AGENT_PROFILE_NAMES: [&str; 9] = [
    "codex", "claude", "gemini", "aider", "cursor", "cline", "opencode", "copilot", "custom",
];

/// Environment variables that are safe and useful for an agent session.
///
/// The list is deliberately small: the parent environment is never inherited
/// wholesale. A trailing `*` is treated as a prefix pattern by
/// `EnvironmentPolicy::allows` (used for locale variables only).
pub const DEFAULT_ENV_PASSTHROUGH: &[&str] = &[
    "HOME",
    "PATH",
    "SHELL",
    "USER",
    "LOGNAME",
    "TERM",
    "COLORTERM",
    "LANG",
    "LC_*",
    "EDITOR",
    "GIT_AUTHOR_NAME",
    "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL",
    "CARGO_HOME",
    "RUSTUP_HOME",
    "NVM_DIR",
    "NODE_PATH",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "TMPDIR",
    "PWD",
    "OLDPWD",
    "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME",
    "NO_COLOR",
    "CI",
    "TERM_PROGRAM",
    "VETTO_SANDBOXED",
    "VETTO_SHIM_ACTIVE",
    "VETTO_WRAPPED",
    "VETTO_GIT_GUARD",
];

pub fn default_env_passthrough() -> Vec<String> {
    DEFAULT_ENV_PASSTHROUGH
        .iter()
        .map(|name| (*name).to_string())
        .collect()
}

pub fn builtin(name: &str) -> Option<&'static str> {
    match name {
        "default" => Some(DEFAULT_TOML),
        "strict" => Some(STRICT_TOML),
        "audit" => Some(AUDIT_TOML),
        "permissive" => Some(PERMISSIVE_TOML),
        _ => None,
    }
}

pub fn canonical_agent_name(name: &str) -> Option<&'static str> {
    match name.trim().to_ascii_lowercase().as_str() {
        "codex" | "codex-cli" => Some("codex"),
        "claude" | "claude-code" => Some("claude"),
        "aider" | "aider-chat" => Some("aider"),
        "cursor" | "cursor-server" => Some("cursor"),
        "cline" => Some("cline"),
        "opencode" => Some("opencode"),
        "copilot" | "github-copilot-cli" => Some("copilot"),
        "gemini" | "gemini-cli" => Some("gemini"),
        "antigravity" | "antigravity-cli" | "agy" => Some("antigravity"),
        "custom" => Some("custom"),
        _ => None,
    }
}

pub fn agent_builtin(name: &str) -> Option<&'static str> {
    match canonical_agent_name(name)? {
        "codex" => Some(CODEX_AGENT_TOML),
        "claude" => Some(CLAUDE_AGENT_TOML),
        "gemini" | "antigravity" => Some(GEMINI_AGENT_TOML),
        "aider" => Some(AIDER_AGENT_TOML),
        "cursor" => Some(CURSOR_AGENT_TOML),
        "cline" => Some(CLINE_AGENT_TOML),
        "opencode" => Some(OPENCODE_AGENT_TOML),
        "copilot" => Some(COPILOT_AGENT_TOML),
        "custom" => Some(CUSTOM_AGENT_TOML),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string_array<'a>(profile: &'a toml::Value, section: &str, key: &str) -> Vec<&'a str> {
        profile[section][key]
            .as_array()
            .expect("profile field must be an array")
            .iter()
            .map(|value| value.as_str().expect("profile entry must be a string"))
            .collect()
    }

    #[test]
    fn every_builtin_masks_all_project_secret_shapes() {
        let required = [
            "$PROJECT/.env",
            "$PROJECT/.env.*",
            "$PROJECT/**/.env",
            "$PROJECT/**/.env.*",
            "$PROJECT/*.pem",
            "$PROJECT/**/*.pem",
            "$PROJECT/*.key",
            "$PROJECT/**/*.key",
            "$PROJECT/*.p12",
            "$PROJECT/**/*.p12",
            "$PROJECT/*.pfx",
            "$PROJECT/**/*.pfx",
            "$PROJECT/*.kdbx",
            "$PROJECT/**/*.kdbx",
            "$PROJECT/.[eE][nN][vV]",
            "$PROJECT/.[eE][nN][vV].*",
            "$PROJECT/**/.[eE][nN][vV]",
            "$PROJECT/**/.[eE][nN][vV].*",
            "$PROJECT/*.[pP][eE][mM]",
            "$PROJECT/**/*.[pP][eE][mM]",
            "$PROJECT/*.[kK][eE][yY]",
            "$PROJECT/**/*.[kK][eE][yY]",
            "$PROJECT/*.[pP]12",
            "$PROJECT/**/*.[pP]12",
            "$PROJECT/*.[pP][fF][xX]",
            "$PROJECT/**/*.[pP][fF][xX]",
            "$PROJECT/*.[kK][dD][bB][xX]",
            "$PROJECT/**/*.[kK][dD][bB][xX]",
        ];

        for name in PROFILE_NAMES {
            let parsed: toml::Value = toml::from_str(builtin(name).unwrap()).unwrap();
            let denied = string_array(&parsed, "display_only_deny", "paths");
            for pattern in required {
                assert!(
                    denied.contains(&pattern),
                    "profile {name} does not mask {pattern}"
                );
            }
        }
    }

    #[test]
    fn permissive_profile_does_not_blanket_read_credential_homes() {
        let parsed: toml::Value = toml::from_str(PERMISSIVE_TOML).unwrap();
        let readable = string_array(&parsed, "filesystem", "allow_read");
        for path in [
            "$HOME/.cargo",
            "$HOME/.npm",
            "$HOME/.cache",
            "$HOME/go",
            "$HOME/.config/github-copilot",
            "$HOME/.claude",
            "$HOME/.codex",
        ] {
            assert!(
                !readable.contains(&path),
                "permissive profile blanket-reads credential path {path}"
            );
        }
    }

    #[test]
    fn every_agent_preset_is_known_and_schema_strict() {
        for name in AGENT_PROFILE_NAMES {
            let text = agent_builtin(name).expect("agent preset must be embedded");
            let value: toml::Value = toml::from_str(text).expect("agent preset must be TOML");
            assert!(
                value.get("metadata").is_some(),
                "agent {name} lacks metadata"
            );
        }
    }
}
