//! Project ecosystem detection, interactive wizard, and tailored policy generation for `vetto init`.

use anyhow::{bail, Context, Result};
use std::io::{BufRead, Write};
use std::path::Path;

use crate::policy::presets::agent_network_allowlist;
use crate::shim::registry::ShimRegistry;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectAnalysis {
    pub project_name: String,
    pub detected_ecosystems: Vec<&'static str>,
    pub detected_agents: Vec<&'static str>,
    pub recommended_allow_read: Vec<String>,
    pub recommended_network_domains: Vec<String>,
    pub detected_shims: Vec<String>,
}

pub fn analyze_project(root: &Path) -> ProjectAnalysis {
    let mut analysis = ProjectAnalysis::default();

    let name = root
        .canonicalize()
        .ok()
        .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        .unwrap_or_else(|| "project".to_string());
    analysis.project_name = name;

    // Detect binary shims for project
    analysis.detected_shims = ShimRegistry::detect_for_project(root);

    // Rust
    if root.join("Cargo.toml").exists() {
        analysis.detected_ecosystems.push("Rust");
        analysis
            .recommended_allow_read
            .push("$HOME/.cargo/registry".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.cargo/git".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.rustup".to_string());
        analysis
            .recommended_network_domains
            .push("crates.io:443".to_string());
        analysis
            .recommended_network_domains
            .push("static.crates.io:443".to_string());
    }

    // Node.js / TypeScript
    let is_node = root.join("package.json").exists()
        || root.join("pnpm-lock.yaml").exists()
        || root.join("yarn.lock").exists()
        || root.join("bun.lockb").exists();
    if is_node {
        if root.join("tsconfig.json").exists() {
            analysis.detected_ecosystems.push("Node.js (TypeScript)");
        } else {
            analysis.detected_ecosystems.push("Node.js");
        }
        analysis
            .recommended_allow_read
            .push("$HOME/.npm".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.local/share/pnpm/store".to_string());
        analysis
            .recommended_network_domains
            .push("registry.npmjs.org:443".to_string());
    }

    // Python
    let is_python = root.join("pyproject.toml").exists()
        || root.join("requirements.txt").exists()
        || root.join("Pipfile").exists()
        || root.join("poetry.lock").exists()
        || root.join("setup.py").exists();
    if is_python {
        analysis.detected_ecosystems.push("Python");
        analysis
            .recommended_allow_read
            .push("$HOME/.cache/pip".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.cache/uv".to_string());
        analysis
            .recommended_network_domains
            .push("pypi.org:443".to_string());
        analysis
            .recommended_network_domains
            .push("files.pythonhosted.org:443".to_string());
    }

    // Go
    if root.join("go.mod").exists() {
        analysis.detected_ecosystems.push("Go");
        analysis
            .recommended_allow_read
            .push("$HOME/go/pkg/mod".to_string());
        analysis
            .recommended_network_domains
            .push("proxy.golang.org:443".to_string());
        analysis
            .recommended_network_domains
            .push("sum.golang.org:443".to_string());
    }

    // AI Agents in Repo
    if root.join(".cursor").exists() || root.join(".cursorrules").exists() {
        analysis.detected_agents.push("Cursor");
    }
    if root.join(".claude").exists() || root.join("CLAUDE.md").exists() {
        analysis.detected_agents.push("Claude Code");
    }
    if root.join("codex.toml").exists() || root.join(".codex").exists() {
        analysis.detected_agents.push("OpenAI Codex");
    }
    if root.join(".aider.conf.yml").exists() || root.join(".aider.tags.cache.v3").exists() {
        analysis.detected_agents.push("Aider");
    }

    // Always recommend GitHub domain if git is present
    if root.join(".git").exists() {
        analysis
            .recommended_network_domains
            .push("github.com:443".to_string());
        analysis
            .recommended_network_domains
            .push("api.github.com:443".to_string());
    }

    analysis.recommended_allow_read.sort();
    analysis.recommended_allow_read.dedup();
    analysis.recommended_network_domains.sort();
    analysis.recommended_network_domains.dedup();

    analysis
}

/// Generate a fully-commented policy.toml template covering all sections.
pub fn generate_policy_toml(analysis: &ProjectAnalysis) -> String {
    let eco_str = if analysis.detected_ecosystems.is_empty() {
        "Generic".to_string()
    } else {
        analysis.detected_ecosystems.join(", ")
    };

    let agents_str = if analysis.detected_agents.is_empty() {
        "Auto-detected".to_string()
    } else {
        analysis.detected_agents.join(", ")
    };

    let mut out = format!(
        r#"# policy.toml - Project Security Policy
# Generated by `vetto init` for {eco_str} ({agents_str})
#
# Documentation: https://github.com/shleder/vetto

[metadata]
name = "{}"
description = "Vetto security policy tailored for {}"
extends = ["default"]

[security]
# When immutable = true, lower configuration layers cannot override or relax rules.
# immutable = false

[filesystem]
# Project directory and scratch space are writable:
allow_write = [
  "$PROJECT",
  "$PROJECT/target/",
  "/tmp",
  "/dev/null",
]

# Sensitive directories denied from write access:
# deny_write = [
#   "$PROJECT/.git",
# ]

# System toolchain caches and package registries allowed for reading:
allow_read = [
"#,
        analysis.project_name, eco_str
    );

    if analysis.recommended_allow_read.is_empty() {
        out.push_str("  \"$PROJECT\",\n");
    } else {
        for path in &analysis.recommended_allow_read {
            out.push_str(&format!("  \"{path}\",\n"));
        }
    }

    out.push_str(
        r#"]

# Explicitly denied read paths:
# deny_read = [
#   "$HOME/.ssh",
#   "$HOME/.gnupg",
# ]

[display_only_deny]
# Sensitive credential-shaped files masked and blocked inside the sandbox:
paths = [
  "$PROJECT/.env",
  "$PROJECT/.env.*",
  "$PROJECT/*.pem",
  "$PROJECT/*.key",
  "$PROJECT/*.pfx",
  "$PROJECT/*.kdbx",
]

[environment]
# Environment variables passed through to the sandboxed agent:
pass_through = [
  "HOME",
  "PATH",
  "USER",
  "LANG",
  "LC_*",
]

# Environment variables explicitly denied / stripped:
# deny = [
#   "AWS_SECRET_ACCESS_KEY",
#   "GITHUB_TOKEN",
# ]

[network]
# Network isolation mode: "off" | "allowlist"
mode = "allowlist"
allow = [
"#,
    );

    if analysis.recommended_network_domains.is_empty() {
        out.push_str("  \"github.com:443\",\n");
    } else {
        for domain in &analysis.recommended_network_domains {
            out.push_str(&format!("  \"{domain}\",\n"));
        }
    }

    out.push_str(
        r#"]

[limits]
# Optional resource ceilings for sandboxed processes:
# cpu_seconds = 3600
# address_space_bytes = 8589934592  # 8 GiB
# processes = 512
# open_files = 4096
# file_size_bytes = 1073741824      # 1 GiB
"#,
    );

    out
}

/// Run the 3-question interactive setup wizard.
pub fn run_wizard(
    root: &Path,
    reader: &mut impl BufRead,
    writer: &mut impl Write,
) -> Result<String> {
    writer.write_all(b"vetto first-run wizard:\n")?;
    writer.write_all(b"1. Which AI coding agent do you use? [claude / codex / gemini / aider / opencode / cursor / none]: ")?;
    writer.flush()?;

    let mut agent_line = String::new();
    reader.read_line(&mut agent_line)?;
    let agent_choice = agent_line.trim().to_ascii_lowercase();
    let agent = if agent_choice.is_empty() || agent_choice == "none" {
        None
    } else {
        Some(agent_choice)
    };

    writer.write_all(b"2. Does the agent need internet / network access? [y/N / agent-only]: ")?;
    writer.flush()?;

    let mut net_line = String::new();
    reader.read_line(&mut net_line)?;
    let net_choice = net_line.trim().to_ascii_lowercase();
    let allow_net = net_choice == "y" || net_choice == "yes" || net_choice == "agent-only";

    writer.write_all(b"3. What should be considered the project workspace root? [default: .]: ")?;
    writer.flush()?;

    let mut root_line = String::new();
    reader.read_line(&mut root_line)?;
    let root_choice = root_line.trim();
    let workspace_root = if root_choice.is_empty() {
        "$PROJECT"
    } else {
        root_choice
    };

    let mut analysis = analyze_project(root);
    if let Some(ref a) = agent {
        analysis.detected_agents = vec![match a.as_str() {
            "claude" => "Claude Code",
            "codex" => "OpenAI Codex",
            "gemini" => "Google Gemini",
            "aider" => "Aider",
            "opencode" => "OpenCode",
            "cursor" => "Cursor",
            _ => "Custom Agent",
        }];
        if allow_net {
            let domains = agent_network_allowlist(a);
            analysis.recommended_network_domains.extend(domains);
            analysis.recommended_network_domains.sort();
            analysis.recommended_network_domains.dedup();
        }
    }

    if !allow_net {
        analysis.recommended_network_domains.clear();
    }

    let mut toml = generate_policy_toml(&analysis);
    if workspace_root != "$PROJECT" {
        toml = toml.replace("\"$PROJECT\"", &format!("\"{workspace_root}\""));
    }

    Ok(toml)
}

pub fn run_init(root: &Path, force: bool, wizard: bool) -> Result<()> {
    let policy_path = root.join("policy.toml");
    let legacy_path = root.join("vetto.toml");

    if (policy_path.exists() || legacy_path.exists()) && !force {
        bail!("policy file already exists in this directory (use --force to overwrite)");
    }

    let toml_content = if wizard {
        let mut stdin = std::io::stdin().lock();
        let mut stdout = std::io::stdout();
        run_wizard(root, &mut stdin, &mut stdout)?
    } else {
        let analysis = analyze_project(root);
        generate_policy_toml(&analysis)
    };

    std::fs::write(&policy_path, toml_content)
        .with_context(|| format!("failed to write {}", policy_path.display()))?;

    println!(
        "vetto: initialized security policy at {}",
        policy_path.display()
    );
    println!();
    println!("Next steps:");
    println!("  # Run your AI coding agent inside the sandbox:");
    println!("  vetto -- <agent_command>");
    println!();
    println!("  # Or run with zero-config auto-detection:");
    println!("  vetto");
    println!();
    println!("  # Inspect effective policy:");
    println!("  vetto policy explain");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Cursor;
    use std::path::PathBuf;

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-init-test-{name}-{}",
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
    fn detects_rust_node_and_claude_project() {
        let dir = temp_test_dir("rust-node");
        let path = dir.as_path();

        fs::write(path.join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        fs::write(path.join("package.json"), "{}").unwrap();
        fs::write(path.join("tsconfig.json"), "{}").unwrap();
        fs::write(path.join("CLAUDE.md"), "# Claude instructions").unwrap();

        let analysis = analyze_project(path);
        assert!(analysis.detected_ecosystems.contains(&"Rust"));
        assert!(analysis
            .detected_ecosystems
            .contains(&"Node.js (TypeScript)"));
        assert!(analysis.detected_agents.contains(&"Claude Code"));
        assert!(analysis
            .recommended_allow_read
            .contains(&"$HOME/.cargo/registry".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"crates.io:443".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"registry.npmjs.org:443".to_string()));
        assert!(analysis.detected_shims.contains(&"cargo".to_string()));
        assert!(analysis.detected_shims.contains(&"node".to_string()));

        let toml = generate_policy_toml(&analysis);
        assert!(toml.contains("Rust, Node.js (TypeScript)"));
        assert!(toml.contains("$HOME/.cargo/registry"));
        assert!(toml.contains("$PROJECT/.env"));
        assert!(toml.contains("[metadata]"));
        assert!(toml.contains("[security]"));
        assert!(toml.contains("[filesystem]"));
        assert!(toml.contains("[display_only_deny]"));
        assert!(toml.contains("[environment]"));
        assert!(toml.contains("[network]"));
        assert!(toml.contains("[limits]"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn wizard_answers_tailor_generated_policy() {
        let dir = temp_test_dir("wizard");
        let input = "claude\nyes\n/workspace\n";
        let mut reader = Cursor::new(input);
        let mut writer = Vec::new();

        let toml = run_wizard(&dir, &mut reader, &mut writer).unwrap();
        assert!(toml.contains("Claude Code"));
        assert!(toml.contains("api.anthropic.com"));
        assert!(toml.contains("/workspace"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_creates_policy_file_and_respects_force() {
        let dir = temp_test_dir("init-force");
        let path = dir.as_path();

        assert!(run_init(path, false, false).is_ok());
        assert!(path.join("policy.toml").exists());

        // Second run without force should fail
        assert!(run_init(path, false, false).is_err());

        // Run with force should succeed
        assert!(run_init(path, true, false).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }
}
