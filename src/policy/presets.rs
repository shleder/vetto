//! Predefined deny path sets for common cloud credentials, SSH keys, container configurations, etc.

/// Resolve a preset name to a slice of path patterns.
pub fn resolve_preset(name: &str) -> Option<&'static [&'static str]> {
    match name.to_ascii_lowercase().as_str() {
        "ssh" => Some(&["$HOME/.ssh"]),
        "aws" => Some(&["$HOME/.aws"]),
        "gcp" | "gcloud" => Some(&["$HOME/.config/gcloud"]),
        "kube" | "kubernetes" => Some(&["$HOME/.kube"]),
        "docker" => Some(&["$HOME/.docker", "$HOME/.docker/config.json"]),
        "gnupg" | "gpg" => Some(&["$HOME/.gnupg"]),
        "git" => Some(&["$HOME/.git-credentials", "$HOME/.netrc"]),
        "npm" => Some(&["$HOME/.npmrc"]),
        "cargo" => Some(&["$HOME/.cargo/credentials", "$HOME/.cargo/credentials.toml"]),
        "claude" => Some(&["$HOME/.claude"]),
        "codex" => Some(&["$HOME/.codex"]),
        _ => None,
    }
}

/// Known preset names for validation and diagnostics.
pub const KNOWN_PRESETS: &[&str] = &[
    "ssh",
    "aws",
    "gcp",
    "gcloud",
    "kube",
    "kubernetes",
    "docker",
    "gnupg",
    "gpg",
    "git",
    "npm",
    "cargo",
    "claude",
    "codex",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_known_presets_resolve() {
        for preset in KNOWN_PRESETS {
            let resolved = resolve_preset(preset);
            assert!(resolved.is_some(), "preset '{preset}' failed to resolve");
            assert!(
                !resolved.unwrap().is_empty(),
                "preset '{preset}' resolved to empty list"
            );
        }
    }

    #[test]
    fn ssh_and_aws_expand_to_home_directories() {
        assert_eq!(resolve_preset("ssh"), Some(&["$HOME/.ssh"][..]));
        assert_eq!(resolve_preset("aws"), Some(&["$HOME/.aws"][..]));
        assert_eq!(resolve_preset("kube"), Some(&["$HOME/.kube"][..]));
        assert_eq!(
            resolve_preset("docker"),
            Some(&["$HOME/.docker", "$HOME/.docker/config.json"][..])
        );
    }
}
