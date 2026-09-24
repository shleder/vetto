//! Zero-config AI agent onboarding and automatic detection.
//!
//! When `vetto` is invoked without arguments:
//! 1. Scans project markers (.claude, .codex, .gemini, .aider, .opencode, .cursor, AGENTS.md)
//! 2. Resolves binary presence in PATH
//! 3. Launches the detected agent in a secure-base profile with agent-specific network allowlists.
//!
//! If no agent is found, returns an honest error listing all supported agents.

use std::path::Path;

use anyhow::{bail, Result};

use crate::policy::loader::RawLayer;
use crate::policy::presets::{agent_network_allowlist, preset_layer, Preset};

pub const SUPPORTED_AGENTS: [&str; 21] = [
    "claude",
    "codex",
    "opencode",
    "gemini",
    "antigravity",
    "agy",
    "cursor",
    "aider",
    "cline",
    "copilot",
    "windsurf",
    "continue",
    "goose",
    "openhands",
    "swe_agent",
    "plandex",
    "mentat",
    "gpt_engineer",
    "devin",
    "crust",
    "amp",
];

struct AgentSpec {
    name: &'static str,
    binaries: &'static [&'static str],
    markers: &'static [&'static str],
}

const AGENT_SPECS: &[AgentSpec] = &[
    AgentSpec {
        name: "claude",
        binaries: &["claude", "claude-code"],
        markers: &[".claude", ".claude.json", "CLAUDE.md"],
    },
    AgentSpec {
        name: "codex",
        binaries: &["codex", "codex-cli"],
        markers: &[".codex", "codex.toml", "codex.json"],
    },
    AgentSpec {
        name: "opencode",
        binaries: &["opencode", "opencode-ai"],
        markers: &[".opencode", "opencode.json"],
    },
    AgentSpec {
        name: "gemini",
        binaries: &["gemini", "gemini-cli"],
        markers: &[".gemini", "GEMINI.md", "gemini.json"],
    },
    AgentSpec {
        name: "antigravity",
        binaries: &["antigravity", "agy", "antigravity-cli"],
        markers: &[".antigravity", "AGENTS.md"],
    },
    AgentSpec {
        name: "cursor",
        binaries: &["cursor", "cursor-agent", "cursor-server"],
        markers: &[".cursor", ".cursorrules"],
    },
    AgentSpec {
        name: "aider",
        binaries: &["aider", "aider-chat"],
        markers: &[".aider", ".aider.conf.yml", ".aider.chat.history.md"],
    },
    AgentSpec {
        name: "cline",
        binaries: &["cline", "cline-cli"],
        markers: &[".cline", ".roomodes"],
    },
    AgentSpec {
        name: "copilot",
        binaries: &["copilot", "gh-copilot", "github-copilot-cli"],
        markers: &[".copilot", "copilot-instructions.md"],
    },
    AgentSpec {
        name: "windsurf",
        binaries: &["windsurf", "windsurf-cli"],
        markers: &[".windsurf", ".codeium"],
    },
    AgentSpec {
        name: "continue",
        binaries: &["continue", "continue-cli"],
        markers: &[".continue"],
    },
    AgentSpec {
        name: "goose",
        binaries: &["goose", "goose-ai"],
        markers: &[".goosehints", "goose.yaml"],
    },
    AgentSpec {
        name: "openhands",
        binaries: &["openhands", "all-hands"],
        markers: &[".openhands", ".all-hands"],
    },
    AgentSpec {
        name: "swe_agent",
        binaries: &["swe-agent", "sweagent"],
        markers: &["swe-agent.yaml", ".swe-agent"],
    },
    AgentSpec {
        name: "plandex",
        binaries: &["plandex", "plandex-cli"],
        markers: &[".plandex", "plandex.yaml"],
    },
    AgentSpec {
        name: "mentat",
        binaries: &["mentat", "mentat-cli"],
        markers: &[".mentat", ".mentatconfig"],
    },
    AgentSpec {
        name: "gpt_engineer",
        binaries: &["gpt-engineer", "gpte"],
        markers: &[".gpteng", "gpt-engineer.toml"],
    },
    AgentSpec {
        name: "devin",
        binaries: &["devin", "devin-cli"],
        markers: &[".devin", "devin.json"],
    },
    AgentSpec {
        name: "crust",
        binaries: &["crust", "crust-cli"],
        markers: &[".crust", "crust.yaml"],
    },
    AgentSpec {
        name: "amp",
        binaries: &["amp", "amp-cli"],
        markers: &[".amp", "amp.yaml"],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedAgent {
    pub name: &'static str,
    pub binary: String,
    pub command: Vec<String>,
    pub network_domains: Vec<String>,
    pub reason: String,
}

/// Auto-detect AI coding agent from project markers and environment PATH.
pub fn detect_agent(project: &Path) -> Result<DetectedAgent> {
    // 1. Check specific project markers
    for spec in AGENT_SPECS {
        for marker in spec.markers {
            if project.join(marker).exists() {
                if let Some(binary) = find_any_binary(spec.binaries) {
                    return Ok(DetectedAgent {
                        name: spec.name,
                        binary: binary.clone(),
                        command: vec![binary],
                        network_domains: agent_network_allowlist(spec.name),
                        reason: format!("project marker '{marker}' and binary in PATH"),
                    });
                }
            }
        }
    }

    // 2. Check generic agent markers like AGENTS.md
    if project.join("AGENTS.md").exists() {
        for spec in AGENT_SPECS {
            if let Some(binary) = find_any_binary(spec.binaries) {
                return Ok(DetectedAgent {
                    name: spec.name,
                    binary: binary.clone(),
                    command: vec![binary],
                    network_domains: agent_network_allowlist(spec.name),
                    reason: "AGENTS.md marker and binary in PATH".to_string(),
                });
            }
        }
    }

    // 3. Fallback: check if any supported agent binary exists in PATH
    for spec in AGENT_SPECS {
        if let Some(binary) = find_any_binary(spec.binaries) {
            return Ok(DetectedAgent {
                name: spec.name,
                binary: binary.clone(),
                command: vec![binary],
                network_domains: agent_network_allowlist(spec.name),
                reason: "binary found in PATH".to_string(),
            });
        }
    }

    // 4. Honest error with list of supported agents
    bail!(
        "could not auto-detect AI agent from project markers or PATH.\n\
         Supported agents: {}\n\
         To enable transparent sandboxing: vetto enable <agent>\n\
         To run an agent manually: vetto [OPTIONS] -- <command> [args...]\n\
         To configure policy: vetto init --wizard",
        SUPPORTED_AGENTS.join(", ")
    )
}

/// Construct secure-base policy layer for the detected agent.
pub fn secure_base_policy(agent: &DetectedAgent) -> RawLayer {
    preset_layer(Preset::Balanced, Some(agent.name))
}

/// Returns known candidate binary names for an agent or alias.
pub fn agent_candidate_binaries(agent: &str) -> &'static [&'static str] {
    let canon = crate::policy::defaults::canonical_agent_name(agent).unwrap_or(agent);
    for spec in AGENT_SPECS {
        if spec.name == canon {
            return spec.binaries;
        }
    }
    &[]
}

/// Resolves real host binary for an agent, checking the provided name
/// and any known alternative binary names (aliases) outside Vetto shims.
pub fn find_real_agent_binary(agent: &str) -> Result<(String, std::path::PathBuf)> {
    // 1. Direct check: exact name outside shims
    if let Ok(real) = crate::shim::find_real_binary(agent) {
        return Ok((agent.to_string(), real));
    }

    // 2. Candidate binaries for this agent / alias
    let candidates = agent_candidate_binaries(agent);
    for &candidate in candidates {
        if candidate == agent {
            continue;
        }
        if let Ok(real) = crate::shim::find_real_binary(candidate) {
            return Ok((candidate.to_string(), real));
        }
    }

    bail!(
        "agent binary for '{agent}' was not found in PATH outside Vetto shims.\n\
         Please install '{agent}' first or verify that it is present in your PATH.\n\
         Supported agents: {}",
        SUPPORTED_AGENTS.join(", ")
    )
}

fn find_any_binary(names: &[&str]) -> Option<String> {
    for name in names {
        if crate::shim::find_real_binary(name).is_ok() {
            return Some((*name).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-onboard-test-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn fails_when_no_agent_found_with_informative_error() {
        let dir = temp_test_dir("no-agent");
        // Clear PATH or test non-existent agent
        let res = detect_agent(&dir);
        if let Err(err) = res {
            let msg = err.to_string();
            assert!(msg.contains("Supported agents:"));
            assert!(msg.contains("claude"));
            assert!(msg.contains("opencode"));
            assert!(msg.contains("windsurf"));
            assert!(msg.contains("vetto init"));
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn secure_base_policy_produces_balanced_profile() {
        let agent = DetectedAgent {
            name: "claude",
            binary: "claude".into(),
            command: vec!["claude".into()],
            network_domains: vec!["api.anthropic.com".into()],
            reason: "test".into(),
        };
        let layer = secure_base_policy(&agent);
        let fs = layer.filesystem.unwrap();
        assert!(fs
            .allow_write
            .unwrap()
            .into_vec()
            .contains(&"$PROJECT".to_string()));
        let net = layer.network.unwrap();
        assert_eq!(
            net.mode.unwrap(),
            "allowlist:api.anthropic.com,auth.anthropic.com,claude.ai,statsig.anthropic.com,platform.anthropic.com,registry.npmjs.org,pypi.org,files.pythonhosted.org"
        );
    }

    #[test]
    fn agent_candidate_binaries_resolves_known_agents() {
        let claude_bins = agent_candidate_binaries("claude");
        assert!(claude_bins.contains(&"claude"));
        assert!(claude_bins.contains(&"claude-code"));

        let aider_bins = agent_candidate_binaries("aider-chat");
        assert!(aider_bins.contains(&"aider"));
        assert!(aider_bins.contains(&"aider-chat"));

        let swe_bins = agent_candidate_binaries("swe-agent");
        assert!(swe_bins.contains(&"swe-agent"));
        assert!(swe_bins.contains(&"sweagent"));

        assert!(agent_candidate_binaries("unknown-agent").is_empty());
    }
}
