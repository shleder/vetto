//! Security presets, agent auto-allowlist definitions, and predefined deny presets.
//!
//! Security Presets (Tier 1):
//! - `paranoid`: everything closed (write only $PROJECT and /tmp, network off, strict secret denies)
//! - `balanced`: default base (write $PROJECT and /tmp, standard toolchain read, secrets denied, network allowlist by agent)
//! - `yolo`: wide read/write roots, but secrets STILL denied + network allowlist by agent
//!
//! Deny Presets (Tier 3):
//! - `ssh`, `aws`, `gcp`, `kube`, `docker`, `gnupg`, `git`, `npm`, `cargo`, `claude`, `codex`

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use super::loader::{RawDeny, RawFilesystem, RawLayer, RawMetadata, RawNetwork, RawStringList};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Paranoid,
    Balanced,
    Yolo,
}

impl Preset {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "paranoid" => Ok(Preset::Paranoid),
            "balanced" => Ok(Preset::Balanced),
            "yolo" => Ok(Preset::Yolo),
            other => bail!("unknown preset '{other}' (expected 'paranoid', 'balanced', or 'yolo')"),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Preset::Paranoid => "paranoid",
            Preset::Balanced => "balanced",
            Preset::Yolo => "yolo",
        }
    }
}

impl std::str::FromStr for Preset {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl std::fmt::Display for Preset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Auto-allowlist domains by agent name.
pub fn agent_network_allowlist(agent: &str) -> Vec<String> {
    let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
    match canon {
        "claude" => vec!["api.anthropic.com".into()],
        "codex" => vec!["api.openai.com".into(), "chatgpt.com".into()],
        "gemini" => vec!["generativelanguage.googleapis.com".into()],
        "aider" => vec!["api.openai.com".into(), "api.anthropic.com".into()],
        "opencode" => vec!["api.openai.com".into(), "api.anthropic.com".into()],
        "cursor" => vec!["api.cursor.com".into(), "api2.cursor.sh".into()],
        "copilot" => vec![
            "api.github.com".into(),
            "copilot-proxy.githubusercontent.com".into(),
        ],
        "cline" => vec!["api.anthropic.com".into(), "api.openai.com".into()],
        _ => Vec::new(),
    }
}

/// Standard secret paths that MUST be denied across all presets (including yolo).
pub fn standard_secret_deny_paths() -> Vec<String> {
    vec![
        "$PROJECT/.env".into(),
        "$PROJECT/.env.*".into(),
        "$PROJECT/**/.env".into(),
        "$PROJECT/**/.env.*".into(),
        "$PROJECT/*.pem".into(),
        "$PROJECT/**/*.pem".into(),
        "$PROJECT/*.key".into(),
        "$PROJECT/**/*.key".into(),
        "$PROJECT/*.p12".into(),
        "$PROJECT/**/*.p12".into(),
        "$PROJECT/*.pfx".into(),
        "$PROJECT/**/*.pfx".into(),
        "$PROJECT/*.kdbx".into(),
        "$PROJECT/**/*.kdbx".into(),
        "$PROJECT/.[eE][nN][vV]".into(),
        "$PROJECT/.[eE][nN][vV].*".into(),
        "$PROJECT/**/.[eE][nN][vV]".into(),
        "$PROJECT/**/.[eE][nN][vV].*".into(),
        "$PROJECT/*.[pP][eE][mM]".into(),
        "$PROJECT/**/*.[pP][eE][mM]".into(),
        "$PROJECT/*.[kK][eE][yY]".into(),
        "$PROJECT/**/*.[kK][eE][yY]".into(),
        "$PROJECT/*.[pP]12".into(),
        "$PROJECT/**/*.[pP]12".into(),
        "$PROJECT/*.[pP][fF][xX]".into(),
        "$PROJECT/**/*.[pP][fF][xX]".into(),
        "$PROJECT/*.[kK][dD][bB][xX]".into(),
        "$PROJECT/**/*.[kK][dD][bB][xX]".into(),
    ]
}

/// Generate a RawLayer representing the preset configuration.
pub fn preset_layer(preset: Preset, agent: Option<&str>) -> RawLayer {
    let network_domains = agent.map(agent_network_allowlist).unwrap_or_default();
    let deny_paths = standard_secret_deny_paths();

    match preset {
        Preset::Paranoid => RawLayer {
            metadata: Some(RawMetadata {
                name: Some("preset:paranoid".into()),
                description: Some("Paranoid preset: everything closed, network off".into()),
                ..Default::default()
            }),
            filesystem: Some(RawFilesystem {
                allow_write: Some(RawStringList::Many(vec![
                    "$PROJECT".into(),
                    "/tmp".into(),
                    "/dev/null".into(),
                ])),
                allow_read: Some(RawStringList::Many(vec!["$PROJECT".into()])),
                deny_write: Some(RawStringList::Many(vec!["$PROJECT/.git".into()])),
                ..Default::default()
            }),
            display_only_deny: Some(RawDeny {
                paths: Some(RawStringList::Many(deny_paths)),
            }),
            network: Some(RawNetwork {
                mode: Some("off".into()),
                ..Default::default()
            }),
            ..Default::default()
        },
        Preset::Balanced => {
            let net = if !network_domains.is_empty() {
                RawNetwork {
                    mode: Some(format!("allowlist:{}", network_domains.join(","))),
                    allow: Some(RawStringList::Many(network_domains)),
                    ..Default::default()
                }
            } else {
                RawNetwork {
                    mode: Some("off".into()),
                    ..Default::default()
                }
            };

            RawLayer {
                metadata: Some(RawMetadata {
                    name: Some("preset:balanced".into()),
                    description: Some("Balanced preset: standard development access".into()),
                    ..Default::default()
                }),
                filesystem: Some(RawFilesystem {
                    allow_write: Some(RawStringList::Many(vec![
                        "$PROJECT".into(),
                        "/tmp".into(),
                        "/dev/null".into(),
                    ])),
                    allow_read: Some(RawStringList::Many(vec![
                        "$PROJECT".into(),
                        "$HOME/.cargo".into(),
                        "$HOME/.rustup".into(),
                        "$HOME/.npm".into(),
                        "$HOME/.cache".into(),
                        "$HOME/.local/share".into(),
                    ])),
                    deny_write: Some(RawStringList::Many(vec!["$PROJECT/.git".into()])),
                    ..Default::default()
                }),
                display_only_deny: Some(RawDeny {
                    paths: Some(RawStringList::Many(deny_paths)),
                }),
                network: Some(net),
                ..Default::default()
            }
        }
        Preset::Yolo => {
            let net = if !network_domains.is_empty() {
                Some(RawNetwork {
                    mode: Some(format!("allowlist:{}", network_domains.join(","))),
                    allow: Some(RawStringList::Many(network_domains)),
                    ..Default::default()
                })
            } else {
                None
            };

            RawLayer {
                metadata: Some(RawMetadata {
                    name: Some("preset:yolo".into()),
                    description: Some(
                        "Yolo preset: permissive write/read with secret masking".into(),
                    ),
                    ..Default::default()
                }),
                filesystem: Some(RawFilesystem {
                    allow_write: Some(RawStringList::Many(vec![
                        "$PROJECT".into(),
                        "/tmp".into(),
                        "/dev/null".into(),
                        "$HOME".into(),
                    ])),
                    allow_read: Some(RawStringList::Many(vec!["/".into()])),
                    deny_write: Some(RawStringList::Many(vec!["$PROJECT/.git".into()])),
                    ..Default::default()
                }),
                display_only_deny: Some(RawDeny {
                    paths: Some(RawStringList::Many(deny_paths)),
                }),
                network: net,
                ..Default::default()
            }
        }
    }
}

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
    fn parses_all_presets() {
        assert_eq!(Preset::parse("paranoid").unwrap(), Preset::Paranoid);
        assert_eq!(Preset::parse("balanced").unwrap(), Preset::Balanced);
        assert_eq!(Preset::parse("yolo").unwrap(), Preset::Yolo);
        assert_eq!(Preset::parse("PARANOID").unwrap(), Preset::Paranoid);
        assert!(Preset::parse("invalid").is_err());
    }

    #[test]
    fn auto_allowlist_matches_known_agents() {
        assert_eq!(agent_network_allowlist("claude"), vec!["api.anthropic.com"]);
        assert_eq!(
            agent_network_allowlist("claude-code"),
            vec!["api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("codex"),
            vec!["api.openai.com", "chatgpt.com"]
        );
        assert_eq!(
            agent_network_allowlist("codex-cli"),
            vec!["api.openai.com", "chatgpt.com"]
        );
        assert_eq!(
            agent_network_allowlist("gemini"),
            vec!["generativelanguage.googleapis.com"]
        );
        assert_eq!(
            agent_network_allowlist("gemini-cli"),
            vec!["generativelanguage.googleapis.com"]
        );
        assert_eq!(
            agent_network_allowlist("aider"),
            vec!["api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("aider-chat"),
            vec!["api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("opencode"),
            vec!["api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("cursor"),
            vec!["api.cursor.com", "api2.cursor.sh"]
        );
        assert_eq!(
            agent_network_allowlist("cursor-server"),
            vec!["api.cursor.com", "api2.cursor.sh"]
        );
        assert_eq!(
            agent_network_allowlist("cline"),
            vec!["api.anthropic.com", "api.openai.com"]
        );
        assert_eq!(
            agent_network_allowlist("copilot"),
            vec!["api.github.com", "copilot-proxy.githubusercontent.com"]
        );
        assert_eq!(
            agent_network_allowlist("github-copilot-cli"),
            vec!["api.github.com", "copilot-proxy.githubusercontent.com"]
        );
        assert!(agent_network_allowlist("unknown").is_empty());
    }

    #[test]
    fn yolo_preset_still_denies_secrets() {
        let layer = preset_layer(Preset::Yolo, Some("claude"));
        let deny = layer.display_only_deny.expect("yolo must mask secrets");
        let paths = deny.paths.expect("must have paths").into_vec();
        assert!(paths.iter().any(|p| p.contains(".env")));
        assert!(paths.iter().any(|p| p.contains(".key")));
    }

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
