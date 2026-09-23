//! OpenCode Agent Configuration Parser & Dynamic Provider Discovery.
//!
//! Provides zero-dependency JSONC comment stripping, URL host extraction,
//! and automatic extraction of custom provider domains from `~/.config/opencode/opencode.jsonc`
//! and related environment variables.

use std::path::{Path, PathBuf};

/// Strips single-line (`//`) and multi-line (`/* */`) comments as well as trailing
/// commas from JSONC input, producing valid JSON for `serde_json`.
///
/// Comments inside string literals (e.g. `"http://localhost"`) are preserved.
pub fn strip_jsonc_comments(input: &str) -> String {
    // Phase 1: Strip comments outside string literals
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut without_comments = String::with_capacity(len);
    let mut i = 0;
    let mut in_string = false;
    let mut escape = false;

    while i < len {
        let c = chars[i];
        if in_string {
            without_comments.push(c);
            if escape {
                escape = false;
            } else if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
        } else if c == '"' {
            in_string = true;
            without_comments.push(c);
            i += 1;
        } else if c == '/' && i + 1 < len && chars[i + 1] == '/' {
            // Single-line comment: skip until newline or EOF
            i += 2;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            if i < len && chars[i] == '\n' {
                without_comments.push('\n');
                i += 1;
            }
        } else if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            // Multi-line comment: skip until "*/" or EOF
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                if chars[i] == '\n' {
                    without_comments.push('\n');
                }
                i += 1;
            }
            if i + 1 < len {
                i += 2; // skip */
            } else {
                i = len;
            }
        } else {
            without_comments.push(c);
            i += 1;
        }
    }

    // Phase 2: Strip trailing commas before '}' or ']' outside string literals
    let chars2: Vec<char> = without_comments.chars().collect();
    let len2 = chars2.len();
    let mut result = String::with_capacity(len2);
    let mut i2 = 0;
    let mut in_str2 = false;
    let mut esc2 = false;

    while i2 < len2 {
        let c = chars2[i2];
        if in_str2 {
            result.push(c);
            if esc2 {
                esc2 = false;
            } else if c == '\\' {
                esc2 = true;
            } else if c == '"' {
                in_str2 = false;
            }
            i2 += 1;
        } else if c == '"' {
            in_str2 = true;
            result.push(c);
            i2 += 1;
        } else if c == ',' {
            // Look ahead for next non-whitespace char
            let mut j = i2 + 1;
            while j < len2 && chars2[j].is_whitespace() {
                j += 1;
            }
            if j < len2 && (chars2[j] == '}' || chars2[j] == ']') {
                // Drop trailing comma
                i2 += 1;
            } else {
                result.push(c);
                i2 += 1;
            }
        } else {
            result.push(c);
            i2 += 1;
        }
    }

    result
}

/// Extracts canonical domain/host from a raw URL or host string.
///
/// Handles scheme prefixes (`http://`, `https://`), userinfo (`user:pass@`),
/// ports (`:8080`), and trailing path/query/fragment.
pub fn extract_host_from_url(raw: &str) -> Option<String> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // Strip scheme if present
    let without_scheme = if let Some(idx) = s.find("://") {
        &s[idx + 3..]
    } else {
        s
    };

    // Strip path, query, fragment
    let host_and_port = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);

    // Strip userinfo
    let host_and_port = if let Some(idx) = host_and_port.rfind('@') {
        &host_and_port[idx + 1..]
    } else {
        host_and_port
    };

    // Strip port
    let host = if host_and_port.starts_with('[') {
        // IPv6 bracketed host
        if let Some(end_bracket) = host_and_port.find(']') {
            &host_and_port[1..end_bracket]
        } else {
            host_and_port
        }
    } else if let Some((h, p)) = host_and_port.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.contains(':') {
            h
        } else {
            host_and_port
        }
    } else {
        host_and_port
    };

    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// Recursively scans a serde_json Value for endpoint/URL strings.
fn collect_urls_from_value(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                let k_lower = k.to_ascii_lowercase();
                if (k_lower == "baseurl" || k_lower == "url" || k_lower == "endpoint")
                    && v.is_string()
                {
                    if let Some(s) = v.as_str() {
                        out.push(s.to_string());
                    }
                } else {
                    collect_urls_from_value(v, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for item in arr {
                collect_urls_from_value(item, out);
            }
        }
        _ => {}
    }
}

/// Extracts custom provider domains from OpenCode JSONC configuration content.
///
/// Detects URLs in `provider.*.options.baseURL`, `url`, `endpoint`, etc.
/// If `localhost` or `127.0.0.1` is discovered, both are included to ensure
/// compatibility with heterogeneous client connections.
pub fn extract_domains_from_opencode_jsonc(content: &str) -> Vec<String> {
    let stripped = strip_jsonc_comments(content);
    let mut raw_urls = Vec::new();

    if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&stripped) {
        // Check "provider" and "providers" sections specifically first
        for key in ["provider", "providers"] {
            if let Some(serde_json::Value::Object(providers)) = parsed.get(key) {
                for (_name, pval) in providers {
                    if let Some(serde_json::Value::Object(opts)) = pval.get("options") {
                        for opt_key in ["baseURL", "baseUrl", "url", "endpoint"] {
                            if let Some(serde_json::Value::String(u)) = opts.get(opt_key) {
                                raw_urls.push(u.clone());
                            }
                        }
                    }
                    for opt_key in ["baseURL", "baseUrl", "url", "endpoint"] {
                        if let Some(serde_json::Value::String(u)) = pval.get(opt_key) {
                            raw_urls.push(u.clone());
                        }
                    }
                }
            }
        }
        // Also recursively scan for any baseUrl/endpoint anywhere in the config
        collect_urls_from_value(&parsed, &mut raw_urls);
    }

    let mut domains = Vec::new();
    for u in raw_urls {
        if let Some(h) = extract_host_from_url(&u) {
            if h == "localhost" || h == "127.0.0.1" {
                domains.push("localhost".to_string());
                domains.push("127.0.0.1".to_string());
            } else {
                domains.push(h);
            }
        }
    }

    domains.sort();
    domains.dedup();
    domains
}

/// Discovers custom OpenCode provider domains from filesystem paths and environment variables.
pub fn discover_opencode_providers_from_paths(
    home: Option<&Path>,
    project: Option<&Path>,
) -> Vec<String> {
    let mut domains = Vec::new();

    // 1. Explicit config path via OPENCODE_CONFIG
    if let Ok(env_path) = std::env::var("OPENCODE_CONFIG") {
        let p = PathBuf::from(env_path);
        if p.is_file() {
            if let Ok(content) = std::fs::read_to_string(&p) {
                domains.extend(extract_domains_from_opencode_jsonc(&content));
            }
        }
    }

    // 2. Home configuration paths
    if let Some(h) = home {
        let candidate_paths = [
            h.join(".config/opencode/opencode.jsonc"),
            h.join(".config/opencode/opencode.json"),
            h.join(".opencode/opencode.jsonc"),
            h.join(".opencode/opencode.json"),
        ];
        for path in candidate_paths {
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    domains.extend(extract_domains_from_opencode_jsonc(&content));
                }
            }
        }
    }

    // 3. Project configuration paths
    if let Some(proj) = project {
        let candidate_paths = [
            proj.join(".opencode/opencode.jsonc"),
            proj.join(".opencode/opencode.json"),
            proj.join("opencode.jsonc"),
            proj.join("opencode.json"),
        ];
        for path in candidate_paths {
            if path.is_file() {
                if let Ok(content) = std::fs::read_to_string(&path) {
                    domains.extend(extract_domains_from_opencode_jsonc(&content));
                }
            }
        }
    }

    // 4. Base URL environment variables
    let env_vars = [
        "OPENAI_BASE_URL",
        "ANTHROPIC_BASE_URL",
        "OPENROUTER_BASE_URL",
        "OPENCODE_BASE_URL",
        "AIHUBMIX_BASE_URL",
    ];
    for var in env_vars {
        if let Ok(val) = std::env::var(var) {
            if let Some(h) = extract_host_from_url(&val) {
                if h == "localhost" || h == "127.0.0.1" {
                    domains.push("localhost".to_string());
                    domains.push("127.0.0.1".to_string());
                } else {
                    domains.push(h);
                }
            }
        }
    }

    domains.sort();
    domains.dedup();
    domains
}

/// Discovers OpenCode providers from default environment ($HOME and current directory).
pub fn discover_opencode_providers() -> Vec<String> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let project = std::env::current_dir().ok();
    discover_opencode_providers_from_paths(home.as_deref(), project.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_jsonc_comments() {
        let jsonc = r#"{
            // Single line comment
            "key": "value // not a comment",
            /* Multi
               line
               comment */
            "arr": [1, 2, 3,],
            "nested": {
                "inner": "escaped \" quotes",
            },
        }"#;

        let stripped = strip_jsonc_comments(jsonc);
        let parsed: serde_json::Value =
            serde_json::from_str(&stripped).expect("must parse cleanly as valid JSON");

        assert_eq!(parsed["key"], "value // not a comment");
        assert_eq!(parsed["arr"], serde_json::json!([1, 2, 3]));
        assert_eq!(parsed["nested"]["inner"], "escaped \" quotes");
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_url("https://aihubmix.com/v1"),
            Some("aihubmix.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://localhost:20128/v1"),
            Some("localhost".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://127.0.0.1:20128/v1"),
            Some("127.0.0.1".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://triklz27.ru/v1"),
            Some("triklz27.ru".to_string())
        );
        assert_eq!(
            extract_host_from_url("integrate.api.nvidia.com"),
            Some("integrate.api.nvidia.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("https://user:pass@custom-api.org:8443/chat/completions"),
            Some("custom-api.org".to_string())
        );
        assert_eq!(extract_host_from_url("   "), None);
        assert_eq!(extract_host_from_url(""), None);
    }

    #[test]
    fn test_extract_domains_from_opencode_jsonc() {
        let sample = r#"{
            "$schema": "https://opencode.ai/config.json",
            "model": "opeasi/gpt-6-astra",
            "provider": {
                "aihubmix": {
                    "name": "AIHubMix",
                    "options": {
                        "baseURL": "https://aihubmix.com/v1",
                        "apiKey": "sk-12345"
                    }
                },
                "omniroute": {
                    "options": {
                        "baseURL": "http://localhost:20128/v1"
                    }
                },
                "opeasi": {
                    "options": {
                        "baseURL": "https://triklz27.ru/v1"
                    }
                }
            }
        }"#;

        let domains = extract_domains_from_opencode_jsonc(sample);
        assert!(domains.contains(&"aihubmix.com".to_string()));
        assert!(domains.contains(&"triklz27.ru".to_string()));
        assert!(domains.contains(&"localhost".to_string()));
        assert!(domains.contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn test_discover_opencode_providers_from_temp_paths() {
        let temp_dir = std::env::temp_dir().join(format!("vetto-opencode-disc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&temp_dir);
        let config_dir = temp_dir.join(".config/opencode");
        std::fs::create_dir_all(&config_dir).unwrap();

        let jsonc_content = r#"{
            "provider": {
                "custom_provider": {
                    "options": {
                        "baseURL": "https://custom.provider.net/v1"
                    }
                }
            }
        }"#;
        std::fs::write(config_dir.join("opencode.jsonc"), jsonc_content).unwrap();

        let discovered = discover_opencode_providers_from_paths(Some(&temp_dir), None);
        assert!(discovered.contains(&"custom.provider.net".to_string()));

        let _ = std::fs::remove_dir_all(temp_dir);
    }
}
