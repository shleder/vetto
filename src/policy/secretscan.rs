//! Secret Auto-scanner (Feature 25).
//!
//! Scans a project tree for common credential shapes (AWS keys, PEM private keys,
//! GitHub/Slack/AI API tokens, .env files) within strict time and size limits.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Configuration options for secret scanning.
#[derive(Debug, Clone)]
pub struct SecretScanOptions {
    /// Maximum size of an individual file to scan in bytes (default: 1 MB).
    pub max_file_size_bytes: u64,
    /// Maximum number of files to inspect before stopping (default: 5,000).
    pub max_files: usize,
    /// Maximum duration allowed for the entire scan (default: 3 seconds).
    pub timeout: Duration,
}

impl Default for SecretScanOptions {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 1024 * 1024, // 1 MB
            max_files: 5_000,
            timeout: Duration::from_secs(3),
        }
    }
}

/// A secret finding identified during a scan.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SecretFinding {
    pub path: PathBuf,
    pub line: usize,
    pub rule: String,
    pub preview: String,
}

/// Summary of a completed secret scan.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SecretScanResult {
    pub findings: Vec<SecretFinding>,
    pub files_scanned: usize,
    pub bytes_scanned: u64,
    pub timed_out: bool,
}

impl SecretScanResult {
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    pub fn unique_paths(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = self.findings.iter().map(|f| f.path.clone()).collect();
        paths.sort();
        paths.dedup();
        paths
    }
}

/// Helper to mask secret tokens in previews.
pub fn mask_secret(raw: &str) -> String {
    let len = raw.len();
    if len <= 8 {
        "*".repeat(len)
    } else {
        let prefix = &raw[..4.min(len)];
        let suffix = &raw[len.saturating_sub(4)..];
        format!(
            "{prefix}{}{suffix}",
            "*".repeat(len.saturating_sub(8).max(4))
        )
    }
}

/// Determines if a directory name should be skipped during recursive traversal.
pub fn is_ignored_directory(name: &str) -> bool {
    matches!(
        name,
        ".git"
            | "node_modules"
            | "target"
            | "vendor"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".vetto"
            | ".vetto-reports"
            | ".cargo"
            | ".rustup"
    )
}

/// Determines if a file name itself indicates a secret file (e.g. .env, *.pem, *.key).
pub fn is_secret_filename(path: &Path) -> Option<&'static str> {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return None;
    };
    let lower = name.to_ascii_lowercase();

    if lower == ".env" || lower.starts_with(".env.") {
        return Some("Environment file (.env)");
    }
    if lower.ends_with(".pem") {
        return Some("PEM Certificate/Key file");
    }
    if lower.ends_with(".key") || lower.ends_with(".pkcs8") {
        return Some("Private Key file");
    }
    if lower.ends_with(".p12") || lower.ends_with(".pfx") {
        return Some("PKCS#12 Certificate bundle");
    }
    if lower.ends_with(".kdbx") {
        return Some("KeePass Password Database");
    }
    if lower == "id_rsa" || lower == "id_ed25519" || lower == "id_ecdsa" || lower == "id_dsa" {
        return Some("SSH Private Key");
    }

    None
}

/// Scan a single line for well-known secret patterns.
pub fn scan_line(line: &str) -> Option<(&'static str, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        // Still check .env assignments if they have values
    }

    // 1. Private Key Header
    if trimmed.contains("-----BEGIN") && trimmed.contains("PRIVATE KEY-----") {
        return Some(("Private Key Header", mask_secret(trimmed)));
    }

    // 2. AWS Access Key (AKIA...)
    if let Some(idx) = trimmed.find("AKIA") {
        let candidate = &trimmed[idx..];
        if candidate.len() >= 20 {
            let key = &candidate[..20];
            if key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() && !c.is_ascii_lowercase())
            {
                return Some(("AWS Access Key ID", mask_secret(key)));
            }
        }
    }

    // 3. GitHub Tokens (ghp_..., gho_..., github_pat_...)
    if let Some(idx) = trimmed.find("ghp_").or_else(|| trimmed.find("gho_")) {
        let candidate = &trimmed[idx..];
        if candidate.len() >= 40 {
            let token = &candidate[..40];
            if token[4..].chars().all(|c| c.is_ascii_alphanumeric()) {
                return Some(("GitHub Personal Access Token", mask_secret(token)));
            }
        }
    }
    if let Some(idx) = trimmed.find("github_pat_") {
        let candidate = &trimmed[idx..];
        if candidate.len() >= 82 {
            let token = &candidate[..82];
            return Some(("GitHub Fine-Grained PAT", mask_secret(token)));
        }
    }

    // 4. Slack Tokens (xox[baprs]-...)
    if let Some(idx) = trimmed
        .find("xoxb-")
        .or_else(|| trimmed.find("xoxp-"))
        .or_else(|| trimmed.find("xoxa-"))
    {
        let candidate = &trimmed[idx..];
        let token: String = candidate
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();
        if token.len() >= 20 {
            return Some(("Slack Token", mask_secret(&token)));
        }
    }

    // 5. Anthropic / OpenAI API Keys
    if let Some(idx) = trimmed.find("sk-ant-") {
        let candidate = &trimmed[idx..];
        let token: String = candidate
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if token.len() >= 25 {
            return Some(("Anthropic API Key", mask_secret(&token)));
        }
    }
    if let Some(idx) = trimmed.find("sk-") {
        let candidate = &trimmed[idx..];
        let token: String = candidate
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if token.len() >= 30 {
            return Some(("OpenAI API Key", mask_secret(&token)));
        }
    }

    // 6. Generic high-entropy assignments like API_KEY = "..."
    if let Some(finding) = check_generic_secret_assignment(trimmed) {
        return Some(finding);
    }

    None
}

fn check_generic_secret_assignment(line: &str) -> Option<(&'static str, String)> {
    let lower = line.to_ascii_lowercase();
    let keywords = [
        "api_key",
        "apikey",
        "api_secret",
        "secret_key",
        "access_token",
        "auth_token",
        "private_key",
        "password",
    ];

    for kw in keywords {
        if let Some(kw_pos) = lower.find(kw) {
            let after_kw = &line[kw_pos + kw.len()..];
            let after_eq = if let Some(eq_pos) = after_kw.find('=') {
                &after_kw[eq_pos + 1..]
            } else if let Some(colon_pos) = after_kw.find(':') {
                &after_kw[colon_pos + 1..]
            } else {
                continue;
            };

            let val = after_eq
                .trim()
                .trim_matches(|c| c == '"' || c == '\'' || c == '`' || c == ';');
            if val.len() >= 20
                && !val.contains(' ')
                && val.chars().any(|c| c.is_ascii_digit())
                && val.chars().any(|c| c.is_ascii_alphabetic())
            {
                // Ignore placeholders
                let val_lower = val.to_ascii_lowercase();
                if val_lower.contains("your_")
                    || val_lower.contains("example")
                    || val_lower.contains("changeme")
                    || val_lower.contains("placeholder")
                    || val_lower.contains("dummy")
                {
                    continue;
                }
                return Some(("Generic API Key / Secret Assignment", mask_secret(val)));
            }
        }
    }

    None
}

/// Scan a single file for secret content.
pub fn scan_file(path: &Path, max_bytes: u64) -> Vec<SecretFinding> {
    let mut findings = Vec::new();

    // Check filename first
    if let Some(rule) = is_secret_filename(path) {
        findings.push(SecretFinding {
            path: path.to_path_buf(),
            line: 1,
            rule: rule.to_string(),
            preview: format!(
                "[Filename match: {}]",
                path.file_name().unwrap_or_default().to_string_lossy()
            ),
        });
    }

    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return findings;
    };
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > max_bytes {
        return findings;
    }

    let Ok(content) = std::fs::read_to_string(path) else {
        return findings; // binary or invalid UTF-8
    };

    for (idx, line) in content.lines().enumerate() {
        if let Some((rule, preview)) = scan_line(line) {
            findings.push(SecretFinding {
                path: path.to_path_buf(),
                line: idx + 1,
                rule: rule.to_string(),
                preview,
            });
        }
    }

    findings
}

/// Recursively scans a directory for secret patterns.
pub fn scan_directory(root: &Path, options: &SecretScanOptions) -> SecretScanResult {
    let start = Instant::now();
    let mut result = SecretScanResult::default();
    let mut queue = vec![root.to_path_buf()];

    while let Some(current) = queue.pop() {
        if start.elapsed() >= options.timeout {
            result.timed_out = true;
            break;
        }
        if result.files_scanned >= options.max_files {
            result.timed_out = true;
            break;
        }

        if current.is_file() {
            let file_findings = scan_file(&current, options.max_file_size_bytes);
            if let Ok(meta) = std::fs::metadata(&current) {
                result.bytes_scanned += meta.len();
            }
            result.files_scanned += 1;
            result.findings.extend(file_findings);
            continue;
        }

        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() {
                if !is_ignored_directory(&name) {
                    queue.push(path);
                }
            } else if path.is_file() {
                if start.elapsed() >= options.timeout || result.files_scanned >= options.max_files {
                    result.timed_out = true;
                    break;
                }
                let file_findings = scan_file(&path, options.max_file_size_bytes);
                if let Ok(meta) = entry.metadata() {
                    result.bytes_scanned += meta.len();
                }
                result.files_scanned += 1;
                result.findings.extend(file_findings);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "vetto-secretscan-{tag}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn scans_and_detects_aws_key() {
        let line = "AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF";
        let finding = scan_line(line);
        assert!(finding.is_some());
        let (rule, preview) = finding.unwrap();
        assert_eq!(rule, "AWS Access Key ID");
        assert!(preview.contains("AKIA"));
        assert!(preview.contains("****"));
    }

    #[test]
    fn scans_and_detects_pem_header() {
        let line = "-----BEGIN RSA PRIVATE KEY-----";
        let finding = scan_line(line);
        assert!(finding.is_some());
        let (rule, _) = finding.unwrap();
        assert_eq!(rule, "Private Key Header");
    }

    #[test]
    fn scans_and_detects_github_pat() {
        let line = "GITHUB_TOKEN=ghp_123456789012345678901234567890123456";
        let finding = scan_line(line);
        assert!(finding.is_some());
        let (rule, _) = finding.unwrap();
        assert_eq!(rule, "GitHub Personal Access Token");
    }

    #[test]
    fn scans_directory_and_respects_limits() {
        let dir = temp_test_dir("scan-dir");
        fs::write(dir.join(".env"), "DB_PASS=secretpassword123456\n").unwrap();
        fs::write(dir.join("clean.txt"), "hello world\n").unwrap();

        let res = scan_directory(&dir, &SecretScanOptions::default());
        assert!(!res.is_clean());
        assert_eq!(res.unique_paths().len(), 1);
        assert_eq!(res.unique_paths()[0], dir.join(".env"));

        let _ = fs::remove_dir_all(&dir);
    }
}
