//! Project ecosystem detection and tailored policy generation for `vetto init`.

use anyhow::{bail, Context, Result};
use std::path::Path;

use crate::policy::presets::agent_network_allowlist;
use crate::shim::registry::ShimRegistry;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectAnalysis {
    pub project_name: String,
    pub detected_ecosystems: Vec<&'static str>,
    pub detected_agents: Vec<&'static str>,
    pub recommended_allow_read: Vec<String>,
    pub recommended_allow_write: Vec<String>,
    pub recommended_network_domains: Vec<String>,
    pub detected_shims: Vec<String>,
    pub recommended_file_size_bytes: Option<u64>,
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

    // Base writable roots
    analysis.recommended_allow_write.extend([
        "$PROJECT".to_string(),
        "/tmp".to_string(),
        "/dev/null".to_string(),
    ]);

    // Rust
    if root.join("Cargo.toml").exists() {
        analysis.detected_ecosystems.push("Rust");
        analysis
            .recommended_allow_write
            .push("$PROJECT/target/".to_string());
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
            .push("crates.io".to_string());
        analysis
            .recommended_network_domains
            .push("static.crates.io".to_string());
    }

    // Node.js / TypeScript
    let is_node = root.join("package.json").exists()
        || root.join("pnpm-lock.yaml").exists()
        || root.join("yarn.lock").exists()
        || root.join("bun.lock").exists()
        || root.join("bun.lockb").exists();
    if is_node {
        if root.join("tsconfig.json").exists() {
            analysis.detected_ecosystems.push("Node.js (TypeScript)");
        } else {
            analysis.detected_ecosystems.push("Node.js");
        }
        analysis
            .recommended_allow_write
            .push("$PROJECT/node_modules/.cache".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.npm".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.local/share/pnpm/store".to_string());
        if root.join("bun.lock").exists() || root.join("bun.lockb").exists() {
            analysis
                .recommended_allow_read
                .push("$HOME/.bun".to_string());
        }
        analysis
            .recommended_network_domains
            .push("registry.npmjs.org".to_string());
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
            .recommended_allow_write
            .push("$PROJECT/.pytest_cache".to_string());
        analysis
            .recommended_allow_write
            .push("$PROJECT/.mypy_cache".to_string());
        analysis
            .recommended_allow_write
            .push("$PROJECT/.ruff_cache".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.cache/pip".to_string());
        analysis
            .recommended_allow_read
            .push("$HOME/.cache/uv".to_string());
        analysis
            .recommended_network_domains
            .push("pypi.org".to_string());
        analysis
            .recommended_network_domains
            .push("files.pythonhosted.org".to_string());
    }

    // Go
    if root.join("go.mod").exists() {
        analysis.detected_ecosystems.push("Go");
        analysis
            .recommended_allow_read
            .push("$HOME/go/pkg/mod".to_string());
        analysis
            .recommended_network_domains
            .push("proxy.golang.org".to_string());
        analysis
            .recommended_network_domains
            .push("sum.golang.org".to_string());
    }

    // AI Agents in Repo
    if root.join(".cursor").exists() || root.join(".cursorrules").exists() {
        analysis.detected_agents.push("Cursor");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("cursor"));
    }
    if root.join(".claude").exists() || root.join("CLAUDE.md").exists() {
        analysis.detected_agents.push("Claude Code");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("claude"));
    }
    if root.join("codex.toml").exists() || root.join(".codex").exists() {
        analysis.detected_agents.push("OpenAI Codex");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("codex"));
    }
    if root.join(".aider.conf.yml").exists() || root.join(".aider.tags.cache.v3").exists() {
        analysis.detected_agents.push("Aider");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("aider"));
    }
    if root.join(".opencode").exists() || root.join("opencode.json").exists() {
        analysis.detected_agents.push("OpenCode");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("opencode"));
        analysis.recommended_file_size_bytes = Some(2147483648);
    }
    if root.join(".cline").exists() || root.join(".clinerules").exists() {
        analysis.detected_agents.push("Cline");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("cline"));
    }
    if root.join(".windsurf").exists() || root.join(".windsurfrules").exists() {
        analysis.detected_agents.push("Windsurf");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("windsurf"));
    }
    if root.join(".goose").exists() || root.join(".goosehints").exists() {
        analysis.detected_agents.push("Goose");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("goose"));
    }
    if root.join(".antigravity").exists() {
        analysis.detected_agents.push("Antigravity");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("antigravity"));
    }
    if root.join(".copilot").exists() || root.join("copilot-instructions.md").exists() {
        analysis.detected_agents.push("GitHub Copilot");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("copilot"));
    }
    if root.join(".smolagents").exists() {
        analysis.detected_agents.push("Smolagents");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("smolagents"));
    }
    if root.join(".omp").exists() || root.join("omp.toml").exists() {
        analysis.detected_agents.push("OMP");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("omp"));
    }
    if root.join(".zcode").exists() || root.join("zcode.json").exists() {
        analysis.detected_agents.push("ZCode");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("zcode"));
    }
    if root.join(".kimi").exists() || root.join("kimi.json").exists() {
        analysis.detected_agents.push("Kimi Code");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("kimi"));
    }
    if root.join(".grok").exists() || root.join("grok.json").exists() {
        analysis.detected_agents.push("Grok Build");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("grok"));
    }
    if root.join(".crewai").exists()
        || root.join("crewai.json").exists()
        || root.join("crew.py").exists()
    {
        analysis.detected_agents.push("CrewAI");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("crewai"));
    }
    if root.join(".autogen").exists()
        || root.join("autogen.json").exists()
        || root.join(".autogenstudio").exists()
    {
        analysis.detected_agents.push("AutoGen");
        analysis
            .recommended_network_domains
            .extend(agent_network_allowlist("autogen"));
    }
    if root.join("AGENTS.md").exists() {
        analysis.detected_agents.push("AGENTS.md");
    }

    // Always recommend GitHub domain if git is present
    if root.join(".git").exists() {
        analysis
            .recommended_network_domains
            .push("github.com".to_string());
        analysis
            .recommended_network_domains
            .push("api.github.com".to_string());
    }

    analysis.recommended_allow_read.sort();
    analysis.recommended_allow_read.dedup();
    analysis.recommended_allow_write.sort();
    analysis.recommended_allow_write.dedup();
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
"#,
        analysis.project_name, eco_str
    );

    if analysis.recommended_allow_write.is_empty() {
        out.push_str("  \"$PROJECT\",\n  \"/tmp\",\n  \"/dev/null\",\n");
    } else {
        for path in &analysis.recommended_allow_write {
            out.push_str(&format!("  \"{path}\",\n"));
        }
    }
    out.push_str("]\n\n");

    out.push_str(
        r#"# Sensitive directories denied from write access:
# deny_write = [
#   "$PROJECT/.git",
# ]

# System toolchain caches and package registries allowed for reading:
allow_read = [
"#,
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
        out.push_str("  \"github.com\",\n");
    } else {
        for domain in &analysis.recommended_network_domains {
            out.push_str(&format!("  \"{domain}\",\n"));
        }
    }

    out.push_str("]\n\n");

    if analysis.detected_agents.contains(&"OpenCode")
        || analysis.recommended_file_size_bytes.is_some()
    {
        let limit = analysis.recommended_file_size_bytes.unwrap_or(2147483648);
        out.push_str(&format!(
            r#"[limits]
# Resource ceilings for sandboxed processes (2 GiB for OpenCode SQLite opencode.db):
file_size_bytes = {limit}
"#
        ));
    } else {
        out.push_str(
            r#"[limits]
# Optional resource ceilings for sandboxed processes:
# cpu_seconds = 3600
# address_space_bytes = 8589934592  # 8 GiB
# processes = 512
# open_files = 4096
# file_size_bytes = 1073741824      # 1 GiB
"#,
        );
    }

    out
}

pub fn run_init(root: &Path, force: bool) -> Result<()> {
    let policy_path = root.join("policy.toml");
    let legacy_path = root.join("vetto.toml");

    if (policy_path.exists() || legacy_path.exists()) && !force {
        bail!("policy file already exists in this directory (use --force to overwrite)");
    }

    let analysis = analyze_project(root);
    let toml_content = generate_policy_toml(&analysis);

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
            .contains(&"crates.io".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"registry.npmjs.org".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"api.anthropic.com".to_string()));
        assert!(analysis
            .recommended_allow_write
            .contains(&"$PROJECT/target/".to_string()));
        assert!(analysis
            .recommended_allow_write
            .contains(&"$PROJECT/node_modules/.cache".to_string()));
        assert!(analysis
            .recommended_allow_write
            .contains(&"/tmp".to_string()));

        let toml = generate_policy_toml(&analysis);
        assert!(toml.contains("Rust, Node.js (TypeScript)"));
        assert!(toml.contains("api.anthropic.com"));
        assert!(toml.contains("$HOME/.cargo/registry"));
        assert!(toml.contains("$PROJECT/target/"));
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
    fn detects_python_test_scratch_dirs() {
        let dir = temp_test_dir("python-scratch");
        let path = dir.as_path();

        fs::write(path.join("pyproject.toml"), "[tool.pytest]").unwrap();

        let analysis = analyze_project(path);
        assert!(analysis.detected_ecosystems.contains(&"Python"));
        assert!(analysis
            .recommended_allow_write
            .contains(&"$PROJECT/.pytest_cache".to_string()));
        assert!(analysis
            .recommended_allow_write
            .contains(&"$PROJECT/.mypy_cache".to_string()));
        assert!(analysis
            .recommended_allow_write
            .contains(&"$PROJECT/.ruff_cache".to_string()));

        let toml = generate_policy_toml(&analysis);
        assert!(toml.contains(".pytest_cache"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn detects_opencode_cline_bun_project() {
        let dir = temp_test_dir("opencode-bun");
        let path = dir.as_path();

        fs::write(path.join("bun.lock"), "").unwrap();
        fs::write(path.join("package.json"), "{}").unwrap();
        fs::write(path.join("opencode.json"), "{}").unwrap();
        fs::write(path.join(".clinerules"), "rules").unwrap();

        let analysis = analyze_project(path);
        assert!(analysis.detected_ecosystems.contains(&"Node.js"));
        assert!(analysis.detected_agents.contains(&"OpenCode"));
        assert!(analysis.detected_agents.contains(&"Cline"));
        assert!(analysis
            .recommended_allow_read
            .contains(&"$HOME/.bun".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"opencode.ai".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"otel.cline.bot".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"api.cline.bot".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"data.cline.bot".to_string()));
        assert_eq!(analysis.recommended_file_size_bytes, Some(2147483648));

        let toml = generate_policy_toml(&analysis);
        assert!(toml.contains("opencode.ai"));
        assert!(toml.contains("otel.cline.bot"));
        assert!(toml.contains("api.cline.bot"));
        assert!(toml.contains("data.cline.bot"));
        assert!(toml.contains("2147483648"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_init_creates_policy_file_and_respects_force() {
        let dir = temp_test_dir("init-force");
        let path = dir.as_path();

        assert!(run_init(path, false).is_ok());
        assert!(path.join("policy.toml").exists());

        // Second run without force should fail
        assert!(run_init(path, false).is_err());

        // Run with force should succeed
        assert!(run_init(path, true).is_ok());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn analyze_project_detects_crewai_and_autogen() {
        let dir = temp_test_dir("crewai-autogen");
        let path = dir.as_path();
        fs::write(path.join("crew.py"), "#!/usr/bin/env python3\n").unwrap();
        fs::write(path.join("autogen.json"), "{}").unwrap();

        let analysis = analyze_project(path);
        assert!(analysis.detected_agents.contains(&"CrewAI"));
        assert!(analysis.detected_agents.contains(&"AutoGen"));
        assert!(analysis
            .recommended_network_domains
            .contains(&"app.crewai.com".to_string()));
        assert!(analysis
            .recommended_network_domains
            .contains(&"api.mistral.ai".to_string()));

        let _ = fs::remove_dir_all(&dir);
    }
}
