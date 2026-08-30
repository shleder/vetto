//! Security presets and agent auto-allowlist definitions.
//!
//! Presets:
//! - `paranoid`: everything closed (write only $PROJECT and /tmp, network off, strict secret denies)
//! - `balanced`: default base (write $PROJECT and /tmp, standard toolchain read, secrets denied, network allowlist by agent)
//! - `yolo`: wide read/write roots, but secrets STILL denied + network allowlist by agent
//!
//! Agent network auto-allowlist:
//! - claude -> api.anthropic.com
//! - codex -> api.openai.com, chatgpt.com
//! - gemini -> generativelanguage.googleapis.com
//! - aider -> api.openai.com, api.anthropic.com
//! - opencode -> api.openai.com, api.anthropic.com
//! - cursor -> api.cursor.com, api2.cursor.sh

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
    match agent.trim().to_ascii_lowercase().as_str() {
        "claude" | "claude-code" => vec!["api.anthropic.com".into()],
        "codex" | "codex-cli" => vec!["api.openai.com".into(), "chatgpt.com".into()],
        "gemini" => vec!["generativelanguage.googleapis.com".into()],
        "aider" | "aider-chat" => vec!["api.openai.com".into(), "api.anthropic.com".into()],
        "opencode" => vec!["api.openai.com".into(), "api.anthropic.com".into()],
        "cursor" | "cursor-server" => vec!["api.cursor.com".into(), "api2.cursor.sh".into()],
        "copilot" | "github-copilot-cli" => vec![
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
                extends: None,
            }),
            security: None,
            filesystem: Some(RawFilesystem {
                allow_write: Some(RawStringList::Many(vec![
                    "$PROJECT".into(),
                    "/tmp".into(),
                    "/dev/null".into(),
                ])),
                allow_read: Some(RawStringList::Many(vec!["$PROJECT".into()])),
                deny_write: Some(RawStringList::Many(vec!["$PROJECT/.git".into()])),
                deny_read: None,
            }),
            display_only_deny: Some(RawDeny {
                paths: Some(RawStringList::Many(deny_paths)),
            }),
            environment: None,
            network: Some(RawNetwork {
                mode: Some("off".into()),
                allow: None,
                deny: None,
                deny_network: None,
            }),
            conditions: None,
            limits: None,
        },
        Preset::Balanced => {
            let net = if !network_domains.is_empty() {
                RawNetwork {
                    mode: Some(format!("allowlist:{}", network_domains.join(","))),
                    allow: Some(RawStringList::Many(network_domains)),
                    deny: None,
                    deny_network: None,
                }
            } else {
                RawNetwork {
                    mode: Some("off".into()),
                    allow: None,
                    deny: None,
                    deny_network: None,
                }
            };

            RawLayer {
                metadata: Some(RawMetadata {
                    name: Some("preset:balanced".into()),
                    description: Some("Balanced preset: standard development access".into()),
                    extends: None,
                }),
                security: None,
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
                    deny_read: None,
                }),
                display_only_deny: Some(RawDeny {
                    paths: Some(RawStringList::Many(deny_paths)),
                }),
                environment: None,
                network: Some(net),
                conditions: None,
                limits: None,
            }
        }
        Preset::Yolo => {
            let net = if !network_domains.is_empty() {
                Some(RawNetwork {
                    mode: Some(format!("allowlist:{}", network_domains.join(","))),
                    allow: Some(RawStringList::Many(network_domains)),
                    deny: None,
                    deny_network: None,
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
                    extends: None,
                }),
                security: None,
                filesystem: Some(RawFilesystem {
                    allow_write: Some(RawStringList::Many(vec![
                        "$PROJECT".into(),
                        "/tmp".into(),
                        "/dev/null".into(),
                        "$HOME".into(),
                    ])),
                    allow_read: Some(RawStringList::Many(vec!["/".into()])),
                    deny_write: Some(RawStringList::Many(vec!["$PROJECT/.git".into()])),
                    deny_read: None,
                }),
                display_only_deny: Some(RawDeny {
                    paths: Some(RawStringList::Many(deny_paths)),
                }),
                environment: None,
                network: net,
                conditions: None,
                limits: None,
            }
        }
    }
}

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
            agent_network_allowlist("codex"),
            vec!["api.openai.com", "chatgpt.com"]
        );
        assert_eq!(
            agent_network_allowlist("gemini"),
            vec!["generativelanguage.googleapis.com"]
        );
        assert_eq!(
            agent_network_allowlist("aider"),
            vec!["api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("opencode"),
            vec!["api.openai.com", "api.anthropic.com"]
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
}
