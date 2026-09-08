//! Redaction layer for reports (FM-07).
//!
//! Evidence is attacker-influenced: payloads may print secrets, control
//! bytes, or megabytes of garbage. Before anything lands in a report or CI
//! artifact the text passes through [`redact_text`]: secret-shaped tokens
//! are replaced, control bytes stripped, output truncated to [`MAX_DETAIL`].

/// Maximum stored characters per detail string.
pub const MAX_DETAIL: usize = 2000;

/// Literal secret-shape needles (no regex dependency): each entry is
/// (case-insensitive key fragment, minimum value run to redact).
const KEY_FRAGMENTS: &[&str] = &[
    "aws_secret",
    "secret",
    "token",
    "api_key",
    "apikey",
    "api-key",
    "private_key",
    "private-key",
    "privatekey",
    "password",
    "passwd",
];

/// Redact secrets, strip control bytes, enforce the size cap.
pub fn redact_text(input: &str) -> String {
    let mut out = redact_assignments(input);
    out = redact_pem(&out);
    out = redact_fake_markers(&out);
    out = out
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    if out.len() > MAX_DETAIL {
        out.truncate(MAX_DETAIL);
        out.push_str("…[TRUNCATED]");
    }
    out
}

/// Mask the local HOME prefix so reports do not leak account paths.
pub fn mask_home(input: &str, home: &str) -> String {
    if home.is_empty() {
        return input.to_string();
    }
    input.replace(home, "$HOME")
}

/// Redact `key = value` / `key: value` assignments for known key fragments.
/// Keeps the key name, replaces the value with `[REDACTED]`.
fn redact_assignments(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for line in input.split_inclusive('\n') {
        out.push_str(&redact_assignment_line(line));
    }
    out
}

fn redact_assignment_line(line: &str) -> String {
    let lower = line.to_lowercase();
    for frag in KEY_FRAGMENTS {
        if lower.contains(frag) {
            if let Some(pos) = line.find('=').or_else(|| line.find(':')) {
                let (head, _) = line.split_at(pos + 1);
                return format!("{head}[REDACTED]");
            }
            return "[REDACTED]".to_string();
        }
    }
    line.to_string()
}

fn redact_pem(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    loop {
        let Some(begin) = rest.find("-----BEGIN") else {
            out.push_str(rest);
            break;
        };
        let Some(key_end) = rest[begin..].find("-----").map(|i| begin + i + 5) else {
            out.push_str(rest);
            break;
        };
        if !rest[begin..key_end].contains("PRIVATE KEY") {
            out.push_str(&rest[..key_end]);
            rest = &rest[key_end..];
            continue;
        }
        let Some(end) = rest[key_end..].find("-----END").map(|i| key_end + i) else {
            out.push_str(&rest[..key_end]);
            out.push_str("[REDACTED]");
            break;
        };
        let Some(end_close) = rest[end..].find("-----").map(|i| end + i + 5) else {
            out.push_str(&rest[..key_end]);
            out.push_str("[REDACTED]");
            break;
        };
        out.push_str(&rest[..begin]);
        out.push_str("[REDACTED]");
        rest = &rest[end_close..];
    }
    out
}

fn redact_fake_markers(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("FAKE-TEST-") {
        out.push_str(&rest[..pos]);
        out.push_str("[REDACTED]");
        let tail = &rest[pos + "FAKE-TEST-".len()..];
        let skip = tail
            .find(|c: char| !(c.is_ascii_uppercase() || c == '-'))
            .unwrap_or(tail.len());
        rest = &tail[skip..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod redact_tests {
    use super::*;

    /// FM-07: secrets and bulk output must not reach the report.
    #[test]
    fn evidence_redact_001() {
        let evil = "leak: AWS_SECRET_ACCESS_KEY=supersecretvalue123\n".to_string()
            + &"x".repeat(100_000);
        let redacted = redact_text(&evil);
        assert!(!redacted.contains("supersecretvalue123"));
        assert!(redacted.len() <= MAX_DETAIL + 32);
    }

    #[test]
    fn pem_is_redacted() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nABCDEF\n-----END RSA PRIVATE KEY-----";
        assert!(!redact_text(pem).contains("ABCDEF"));
    }

    #[test]
    fn control_bytes_stripped_newlines_kept() {
        let out = redact_text("a\x1bb\nc\x07d");
        assert!(!out.contains('\x1b'));
        assert!(out.contains('\n'));
    }
}
