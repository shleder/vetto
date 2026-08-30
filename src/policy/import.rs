//! Policy import from other AI agent configurations (Claude Code, OpenAI Codex).
//!
//! Imports permissions (allow/deny paths, network domains) into a valid
//! `policy.toml` format. Unknown fields are ignored with diagnostics on stderr.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value as JsonValue;
use toml::Value as TomlValue;

/// Import policy from an external agent config and write to `output_path`.
pub fn import_policy(
    from: &str,
    input_path: Option<&Path>,
    output_path: &Path,
    home: &Path,
) -> Result<String> {
    let toml_content = match from.trim().to_ascii_lowercase().as_str() {
        "claude" | "claude-code" => import_claude(input_path, home)?,
        "codex" | "codex-cli" => import_codex(input_path, home)?,
        other => bail!("unknown import source '{other}' (expected 'claude' or 'codex')"),
    };

    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
    }

    std::fs::write(output_path, &toml_content).with_context(|| {
        format!(
            "failed to write imported policy to {}",
            output_path.display()
        )
    })?;

    Ok(toml_content)
}

/// Import permissions from Claude Code settings (`~/.claude/settings.json` or `~/.claude.json`).
pub fn import_claude(input_path: Option<&Path>, home: &Path) -> Result<String> {
    let resolved_path = match input_path {
        Some(p) => p.to_path_buf(),
        None => {
            let primary = home.join(".claude/settings.json");
            let secondary = home.join(".claude.json");
            if primary.exists() {
                primary
            } else if secondary.exists() {
                secondary
            } else {
                primary
            }
        }
    };

    if !resolved_path.exists() {
        bail!(
            "Claude configuration file '{}' was not found (use --path to specify location)",
            resolved_path.display()
        );
    }

    let text = std::fs::read_to_string(&resolved_path)
        .with_context(|| format!("failed to read Claude config {}", resolved_path.display()))?;

    let root: JsonValue = serde_json::from_str(&text).with_context(|| {
        format!(
            "failed to parse JSON from Claude config {}",
            resolved_path.display()
        )
    })?;

    let mut allow_write = vec!["$PROJECT".to_string(), "/tmp".to_string()];
    let mut allow_read = vec!["$PROJECT".to_string()];
    let mut deny_read = Vec::new();
    let mut deny_paths = Vec::new();
    let mut allow_network = vec!["api.anthropic.com".to_string()];

    if let JsonValue::Object(map) = root {
        for (key, val) in map {
            match key.as_str() {
                "permissions" => {
                    if let JsonValue::Object(perms) = val {
                        for (pkey, pval) in perms {
                            match pkey.as_str() {
                                "allow" | "allowed_paths" | "allow_read" => {
                                    extract_json_strings(&pval, &mut allow_read);
                                }
                                "allow_write" | "allowed_write_paths" => {
                                    extract_json_strings(&pval, &mut allow_write);
                                }
                                "deny" | "denied_paths" | "deny_read" => {
                                    extract_json_strings(&pval, &mut deny_read);
                                }
                                "network" | "allowed_domains" | "api_domains" => {
                                    extract_json_strings(&pval, &mut allow_network);
                                }
                                other => {
                                    eprintln!(
                                        "vetto: import: ignoring unknown permissions field '{other}'"
                                    );
                                }
                            }
                        }
                    }
                }
                "allowedTools" | "tools" => {
                    // Tool permissions: if filesystem tools allowed, keep defaults
                }
                "blockedPaths" | "deniedPaths" => {
                    extract_json_strings(&val, &mut deny_paths);
                }
                "network" => {
                    if let JsonValue::Object(net_map) = val {
                        for (nkey, nval) in net_map {
                            if matches!(
                                nkey.as_str(),
                                "allowed_hosts"
                                    | "allowed_domains"
                                    | "allowedDomains"
                                    | "allowedHosts"
                                    | "allow"
                                    | "domains"
                            ) {
                                extract_json_strings(&nval, &mut allow_network);
                            }
                        }
                    } else {
                        extract_json_strings(&val, &mut allow_network);
                    }
                }
                "allowedDomains" | "allowedHosts" => {
                    extract_json_strings(&val, &mut allow_network);
                }
                other => {
                    eprintln!("vetto: import: ignoring unknown field '{other}' in Claude config");
                }
            }
        }
    }

    allow_write.sort();
    allow_write.dedup();
    allow_read.sort();
    allow_read.dedup();
    deny_read.sort();
    deny_read.dedup();
    deny_paths.sort();
    deny_paths.dedup();
    allow_network.sort();
    allow_network.dedup();

    render_policy_toml(
        "imported-claude",
        "Imported from Claude settings",
        &allow_write,
        &allow_read,
        &deny_read,
        &deny_paths,
        &allow_network,
    )
}

/// Import permissions from OpenAI Codex config (`~/.codex/config.toml` or `./codex.toml`).
pub fn import_codex(input_path: Option<&Path>, home: &Path) -> Result<String> {
    let resolved_path = match input_path {
        Some(p) => p.to_path_buf(),
        None => {
            let user_cfg = home.join(".codex/config.toml");
            let project_cfg = PathBuf::from("codex.toml");
            if project_cfg.exists() {
                project_cfg
            } else if user_cfg.exists() {
                user_cfg
            } else {
                home.join(".codex/config.toml")
            }
        }
    };

    if !resolved_path.exists() {
        bail!(
            "Codex configuration file '{}' was not found (use --path to specify location)",
            resolved_path.display()
        );
    }

    let text = std::fs::read_to_string(&resolved_path)
        .with_context(|| format!("failed to read Codex config {}", resolved_path.display()))?;

    let root: TomlValue = toml::from_str(&text).with_context(|| {
        format!(
            "failed to parse TOML from Codex config {}",
            resolved_path.display()
        )
    })?;

    let mut allow_write = vec!["$PROJECT".to_string(), "/tmp".to_string()];
    let mut allow_read = vec!["$PROJECT".to_string()];
    let mut deny_read = Vec::new();
    let mut deny_paths = Vec::new();
    let mut allow_network = vec!["api.openai.com".to_string(), "chatgpt.com".to_string()];

    if let TomlValue::Table(map) = root {
        for (key, val) in map {
            match key.as_str() {
                "sandbox" => {
                    if let TomlValue::Table(sandbox) = val {
                        for (skey, sval) in sandbox {
                            match skey.as_str() {
                                "allowed_paths" | "allow_read" | "readable" => {
                                    extract_toml_strings(&sval, &mut allow_read);
                                }
                                "writable_paths" | "allow_write" | "writable" => {
                                    extract_toml_strings(&sval, &mut allow_write);
                                }
                                "denied_paths" | "deny_read" => {
                                    extract_toml_strings(&sval, &mut deny_read);
                                }
                                "mask_paths" | "display_only_deny" => {
                                    extract_toml_strings(&sval, &mut deny_paths);
                                }
                                "network" | "allowed_domains" => {
                                    extract_toml_strings(&sval, &mut allow_network);
                                }
                                other => {
                                    eprintln!(
                                        "vetto: import: ignoring unknown sandbox field '{other}'"
                                    );
                                }
                            }
                        }
                    }
                }
                "permissions" => {
                    if let TomlValue::Table(perms) = val {
                        for (pkey, pval) in perms {
                            match pkey.as_str() {
                                "allow_read" | "read" => {
                                    extract_toml_strings(&pval, &mut allow_read);
                                }
                                "allow_write" | "write" => {
                                    extract_toml_strings(&pval, &mut allow_write);
                                }
                                "deny" | "deny_read" => {
                                    extract_toml_strings(&pval, &mut deny_read);
                                }
                                "network" => {
                                    extract_toml_strings(&pval, &mut allow_network);
                                }
                                other => {
                                    eprintln!(
                                        "vetto: import: ignoring unknown permissions field '{other}'"
                                    );
                                }
                            }
                        }
                    }
                }
                "network" => {
                    if let TomlValue::Table(net) = val {
                        for (nkey, nval) in net {
                            if matches!(
                                nkey.as_str(),
                                "allow"
                                    | "allowed_domains"
                                    | "allowed_hosts"
                                    | "allowedDomains"
                                    | "allowedHosts"
                                    | "domains"
                            ) {
                                extract_toml_strings(&nval, &mut allow_network);
                            }
                        }
                    } else {
                        extract_toml_strings(&val, &mut allow_network);
                    }
                }
                "allowed_domains" | "allowedDomains" | "allowed_hosts" | "allowedHosts" => {
                    extract_toml_strings(&val, &mut allow_network);
                }
                "sandbox_write_roots"
                | "write_roots"
                | "writable_roots"
                | "allow_write"
                | "writable_paths" => {
                    extract_toml_strings(&val, &mut allow_write);
                }
                "sandbox_read_roots" | "read_roots" | "readable_roots" | "allow_read"
                | "readable_paths" => {
                    extract_toml_strings(&val, &mut allow_read);
                }
                other => {
                    eprintln!("vetto: import: ignoring unknown field '{other}' in Codex config");
                }
            }
        }
    }

    allow_write.sort();
    allow_write.dedup();
    allow_read.sort();
    allow_read.dedup();
    deny_read.sort();
    deny_read.dedup();
    deny_paths.sort();
    deny_paths.dedup();
    allow_network.sort();
    allow_network.dedup();

    render_policy_toml(
        "imported-codex",
        "Imported from Codex configuration",
        &allow_write,
        &allow_read,
        &deny_read,
        &deny_paths,
        &allow_network,
    )
}

fn extract_json_strings(val: &JsonValue, out: &mut Vec<String>) {
    match val {
        JsonValue::String(s) => {
            if !s.trim().is_empty() {
                out.push(s.clone());
            }
        }
        JsonValue::Array(arr) => {
            for item in arr {
                if let JsonValue::String(s) = item {
                    if !s.trim().is_empty() {
                        out.push(s.clone());
                    }
                }
            }
        }
        _ => {}
    }
}

fn extract_toml_strings(val: &TomlValue, out: &mut Vec<String>) {
    match val {
        TomlValue::String(s) => {
            if !s.trim().is_empty() {
                out.push(s.clone());
            }
        }
        TomlValue::Array(arr) => {
            for item in arr {
                if let TomlValue::String(s) = item {
                    if !s.trim().is_empty() {
                        out.push(s.clone());
                    }
                }
            }
        }
        _ => {}
    }
}

fn render_policy_toml(
    name: &str,
    description: &str,
    allow_write: &[String],
    allow_read: &[String],
    deny_read: &[String],
    deny_paths: &[String],
    allow_network: &[String],
) -> Result<String> {
    let mut out = String::new();

    out.push_str(&format!(
        "# policy.toml - Generated by `vetto policy import`\n\
         [metadata]\n\
         name = \"{name}\"\n\
         description = \"{description}\"\n\
         extends = [\"default\"]\n\n"
    ));

    out.push_str("[filesystem]\n");
    out.push_str("allow_write = [\n");
    for path in allow_write {
        out.push_str(&format!("  \"{path}\",\n"));
    }
    out.push_str("]\n\n");

    out.push_str("allow_read = [\n");
    for path in allow_read {
        out.push_str(&format!("  \"{path}\",\n"));
    }
    out.push_str("]\n\n");

    if !deny_read.is_empty() {
        out.push_str("deny_read = [\n");
        for path in deny_read {
            out.push_str(&format!("  \"{path}\",\n"));
        }
        out.push_str("]\n\n");
    }

    out.push_str("[display_only_deny]\npaths = [\n");
    if deny_paths.is_empty() {
        out.push_str("  \"$PROJECT/.env\",\n");
        out.push_str("  \"$PROJECT/.env.*\",\n");
        out.push_str("  \"$PROJECT/*.pem\",\n");
        out.push_str("  \"$PROJECT/*.key\",\n");
    } else {
        for path in deny_paths {
            out.push_str(&format!("  \"{path}\",\n"));
        }
    }
    out.push_str("]\n\n");

    if !allow_network.is_empty() {
        out.push_str("[network]\nmode = \"allowlist\"\nallow = [\n");
        for domain in allow_network {
            out.push_str(&format!("  \"{domain}\",\n"));
        }
        out.push_str("]\n");
    } else {
        out.push_str("[network]\nmode = \"off\"\n");
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-import-test-{name}-{}",
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
    fn imports_claude_settings_json() {
        let dir = temp_test_dir("claude");
        let claude_path = dir.join("settings.json");
        let json = r#"{
            "unknownField": 123,
            "permissions": {
                "allow": ["/var/data", "$PROJECT/src"],
                "allow_write": ["$PROJECT/build"],
                "network": ["api.anthropic.com", "cdn.anthropic.com"]
            }
        }"#;
        fs::write(&claude_path, json).unwrap();

        let out_path = dir.join("policy.toml");
        let content = import_policy("claude", Some(&claude_path), &out_path, &dir).unwrap();
        assert!(content.contains("name = \"imported-claude\""));
        assert!(content.contains("/var/data"));
        assert!(content.contains("$PROJECT/build"));
        assert!(content.contains("api.anthropic.com"));
        assert!(out_path.exists());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn imports_codex_config_toml() {
        let dir = temp_test_dir("codex");
        let codex_path = dir.join("config.toml");
        let toml = r#"
            random_key = "ignore_me"
            [sandbox]
            allowed_paths = ["/opt/sdk", "$PROJECT"]
            writable_paths = ["$PROJECT/dist"]
            allowed_domains = ["api.openai.com", "custom.endpoint.com"]
        "#;
        fs::write(&codex_path, toml).unwrap();

        let out_path = dir.join("policy.toml");
        let content = import_policy("codex", Some(&codex_path), &out_path, &dir).unwrap();
        assert!(content.contains("name = \"imported-codex\""));
        assert!(content.contains("/opt/sdk"));
        assert!(content.contains("$PROJECT/dist"));
        assert!(content.contains("custom.endpoint.com"));
        assert!(out_path.exists());

        let _ = fs::remove_dir_all(dir);
    }
}
