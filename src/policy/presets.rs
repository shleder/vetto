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

use super::loader::{
    RawDeny, RawFilesystem, RawLayer, RawLimits, RawMetadata, RawNetwork, RawStringList,
};

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
        "claude" => vec![
            "api.anthropic.com".into(),
            "auth.anthropic.com".into(),
            "claude.ai".into(),
            "statsig.anthropic.com".into(),
            "platform.anthropic.com".into(),
        ],
        "codex" => vec![
            "api.openai.com".into(),
            "chatgpt.com".into(),
            "auth.openai.com".into(),
            "cdn.oaistatic.com".into(),
            "chat.openai.com".into(),
            "platform.openai.com".into(),
        ],
        "gemini" => vec![
            "generativelanguage.googleapis.com".into(),
            "oauth2.googleapis.com".into(),
            "accounts.google.com".into(),
        ],
        "antigravity" | "agy" => vec![
            "accounts.google.com".into(),
            "oauth2.googleapis.com".into(),
            "antigravity.google".into(),
            "www.googleapis.com".into(),
            "cloudcode-pa.googleapis.com".into(),
            "daily-cloudcode-pa.googleapis.com".into(),
            "antigravity-unleash.goog".into(),
            "alkalimodelplatform-pa.googleapis.com".into(),
            "generativelanguage.googleapis.com".into(),
            "aicode.googleapis.com".into(),
            "businessaicode.googleapis.com".into(),
            "aiplatform.googleapis.com".into(),
            "play.googleapis.com".into(),
            "googleusercontent.com".into(),
        ],
        "aider" => vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "openrouter.ai".into(),
            "api.deepseek.com".into(),
            "api.groq.com".into(),
            "generativelanguage.googleapis.com".into(),
        ],
        "opencode" => {
            let mut domains = vec![
                "api.openai.com".into(),
                "api.anthropic.com".into(),
                "openrouter.ai".into(),
                "opencode.ai".into(),
                "integrate.api.nvidia.com".into(),
                "agentrouter.org".into(),
                "aihubmix.com".into(),
                "api.github.com".into(),
                "github.com".into(),
                "localhost".into(),
                "127.0.0.1".into(),
            ];
            for d in crate::policy::opencode::discover_opencode_providers() {
                if !domains.contains(&d) {
                    domains.push(d);
                }
            }
            domains
        }
        "cursor" => vec![
            "api2.cursor.sh".into(),
            "api.cursor.sh".into(),
            "auth.cursor.sh".into(),
            "repo.cursor.sh".into(),
        ],
        "copilot" => vec![
            "api.github.com".into(),
            "copilot-proxy.githubusercontent.com".into(),
        ],
        "cline" => vec![
            "api.anthropic.com".into(),
            "api.openai.com".into(),
            "openrouter.ai".into(),
            "otel.cline.bot".into(),
            "api.cline.bot".into(),
            "data.cline.bot".into(),
            "registry.npmjs.org".into(),
        ],
        "windsurf" => vec!["api.codeium.com".into(), "windsurf.codeium.com".into()],
        "continue" => vec![
            "api.continue.dev".into(),
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        "goose" => vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "openrouter.ai".into(),
        ],
        "openhands" => vec![
            "api.all-hands.dev".into(),
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        "swe_agent" => vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "openrouter.ai".into(),
        ],
        "plandex" => vec![
            "api.plandex.ai".into(),
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        "mentat" => vec![
            "api.mentat.ai".into(),
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        "gpt_engineer" => vec![
            "api.openai.com".into(),
            "api.anthropic.com".into(),
            "openrouter.ai".into(),
        ],
        "devin" => vec![
            "api.devin.ai".into(),
            "cognition.ai".into(),
            "api.openai.com".into(),
        ],
        "crust" => vec!["api.crustdata.com".into(), "api.openai.com".into()],
        "amp" => vec![
            "api.amp.dev".into(),
            "api.openai.com".into(),
            "api.anthropic.com".into(),
        ],
        _ => Vec::new(),
    }
}

/// Default resource limits for specific agents (e.g. OpenCode SQLite file size limit).
pub fn agent_default_limits(agent: &str) -> Option<RawLimits> {
    let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
    match canon {
        "opencode" => Some(RawLimits {
            file_size_bytes: Some(2147483648), // 2 GiB ceiling to allow local SQLite opencode.db without SIGXFSZ
            ..Default::default()
        }),
        _ => None,
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
                limits: agent.and_then(agent_default_limits),
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
                limits: agent.and_then(agent_default_limits),
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
        "antigravity" | "agy" => Some(&["$HOME/.gemini", "$HOME/.config/Antigravity"]),
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
    "antigravity",
    "agy",
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
        assert_eq!(
            agent_network_allowlist("claude"),
            vec![
                "api.anthropic.com",
                "auth.anthropic.com",
                "claude.ai",
                "statsig.anthropic.com",
                "platform.anthropic.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("claude-code"),
            vec![
                "api.anthropic.com",
                "auth.anthropic.com",
                "claude.ai",
                "statsig.anthropic.com",
                "platform.anthropic.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("codex"),
            vec![
                "api.openai.com",
                "chatgpt.com",
                "auth.openai.com",
                "cdn.oaistatic.com",
                "chat.openai.com",
                "platform.openai.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("codex-cli"),
            vec![
                "api.openai.com",
                "chatgpt.com",
                "auth.openai.com",
                "cdn.oaistatic.com",
                "chat.openai.com",
                "platform.openai.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("gemini"),
            vec![
                "generativelanguage.googleapis.com",
                "oauth2.googleapis.com",
                "accounts.google.com"
            ]
        );
        assert_eq!(
            agent_network_allowlist("gemini-cli"),
            vec![
                "generativelanguage.googleapis.com",
                "oauth2.googleapis.com",
                "accounts.google.com"
            ]
        );
        assert_eq!(
            agent_network_allowlist("antigravity"),
            vec![
                "accounts.google.com",
                "oauth2.googleapis.com",
                "antigravity.google",
                "www.googleapis.com",
                "cloudcode-pa.googleapis.com",
                "daily-cloudcode-pa.googleapis.com",
                "antigravity-unleash.goog",
                "alkalimodelplatform-pa.googleapis.com",
                "generativelanguage.googleapis.com",
                "aicode.googleapis.com",
                "businessaicode.googleapis.com",
                "aiplatform.googleapis.com",
                "play.googleapis.com",
                "googleusercontent.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("agy"),
            vec![
                "accounts.google.com",
                "oauth2.googleapis.com",
                "antigravity.google",
                "www.googleapis.com",
                "cloudcode-pa.googleapis.com",
                "daily-cloudcode-pa.googleapis.com",
                "antigravity-unleash.goog",
                "alkalimodelplatform-pa.googleapis.com",
                "generativelanguage.googleapis.com",
                "aicode.googleapis.com",
                "businessaicode.googleapis.com",
                "aiplatform.googleapis.com",
                "play.googleapis.com",
                "googleusercontent.com",
            ]
        );
        assert_eq!(
            agent_network_allowlist("aider"),
            vec![
                "api.openai.com",
                "api.anthropic.com",
                "openrouter.ai",
                "api.deepseek.com",
                "api.groq.com",
                "generativelanguage.googleapis.com"
            ]
        );
        assert_eq!(
            agent_network_allowlist("aider-chat"),
            vec![
                "api.openai.com",
                "api.anthropic.com",
                "openrouter.ai",
                "api.deepseek.com",
                "api.groq.com",
                "generativelanguage.googleapis.com"
            ]
        );
        let opencode_list = agent_network_allowlist("opencode");
        for expected in [
            "api.openai.com",
            "api.anthropic.com",
            "openrouter.ai",
            "opencode.ai",
            "api.github.com",
            "github.com",
        ] {
            assert!(
                opencode_list.iter().any(|d| d == expected),
                "opencode network allowlist must contain {expected}"
            );
        }
        assert_eq!(
            agent_network_allowlist("cursor"),
            vec![
                "api2.cursor.sh",
                "api.cursor.sh",
                "auth.cursor.sh",
                "repo.cursor.sh",
            ]
        );
        assert_eq!(
            agent_network_allowlist("cursor-server"),
            vec![
                "api2.cursor.sh",
                "api.cursor.sh",
                "auth.cursor.sh",
                "repo.cursor.sh",
            ]
        );
        assert_eq!(
            agent_network_allowlist("cline"),
            vec![
                "api.anthropic.com",
                "api.openai.com",
                "openrouter.ai",
                "otel.cline.bot",
                "api.cline.bot",
                "data.cline.bot",
                "registry.npmjs.org",
            ]
        );
        assert_eq!(
            agent_network_allowlist("copilot"),
            vec!["api.github.com", "copilot-proxy.githubusercontent.com"]
        );
        assert_eq!(
            agent_network_allowlist("github-copilot-cli"),
            vec!["api.github.com", "copilot-proxy.githubusercontent.com"]
        );
        assert_eq!(
            agent_network_allowlist("windsurf"),
            vec!["api.codeium.com", "windsurf.codeium.com"]
        );
        assert_eq!(
            agent_network_allowlist("continue"),
            vec!["api.continue.dev", "api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("goose"),
            vec!["api.openai.com", "api.anthropic.com", "openrouter.ai"]
        );
        assert_eq!(
            agent_network_allowlist("openhands"),
            vec!["api.all-hands.dev", "api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("swe_agent"),
            vec!["api.openai.com", "api.anthropic.com", "openrouter.ai"]
        );
        assert_eq!(
            agent_network_allowlist("plandex"),
            vec!["api.plandex.ai", "api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("mentat"),
            vec!["api.mentat.ai", "api.openai.com", "api.anthropic.com"]
        );
        assert_eq!(
            agent_network_allowlist("gpt_engineer"),
            vec!["api.openai.com", "api.anthropic.com", "openrouter.ai"]
        );
        assert_eq!(
            agent_network_allowlist("devin"),
            vec!["api.devin.ai", "cognition.ai", "api.openai.com"]
        );
        assert_eq!(
            agent_network_allowlist("crust"),
            vec!["api.crustdata.com", "api.openai.com"]
        );
        assert_eq!(
            agent_network_allowlist("amp"),
            vec!["api.amp.dev", "api.openai.com", "api.anthropic.com"]
        );
        assert!(agent_network_allowlist("custom").is_empty());
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
        assert_eq!(
            resolve_preset("antigravity"),
            Some(&["$HOME/.gemini", "$HOME/.config/Antigravity"][..])
        );
        assert_eq!(
            resolve_preset("agy"),
            Some(&["$HOME/.gemini", "$HOME/.config/Antigravity"][..])
        );
    }

    #[test]
    fn opencode_has_2gib_default_file_size_limit() {
        let limits = agent_default_limits("opencode").expect("opencode default limits");
        assert_eq!(limits.file_size_bytes, Some(2147483648));
        assert!(agent_default_limits("claude").is_none());
    }
}
