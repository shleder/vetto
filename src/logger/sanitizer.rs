//! BEST-EFFORT secret redaction for logs and reports.
//!
//! Honesty first: this scanner has BOTH false positives and false negatives.
//! It is a courtesy layer that keeps obvious credentials out of artifacts a
//! user might share — it is NOT a security boundary. Enforcement lives in
//! Landlock/Seatbelt, never here.

/// Redact obvious secret shapes from a single line. Keeps everything else
/// byte-identical. ASCII-safe boundaries only, so multibyte UTF-8 content
/// outside redacted ranges is preserved.
pub fn sanitize_line(line: &str) -> String {
    let line = redact_pem(line);
    let line = redact_prefixed_tokens(&line);
    redact_key_values(&line)
}

// --- PEM blocks -----------------------------------------------------------

fn redact_pem(s: &str) -> String {
    let Some(begin) = s.find("-----BEGIN") else {
        return s.to_string();
    };
    let Some(rel) = s[begin..].find("-----END") else {
        return s.to_string();
    };
    let end_marker = begin + rel;
    let after = end_marker + "-----END".len();
    let block_end = s[after..]
        .find("-----")
        .map(|i| after + i + 5)
        .unwrap_or(s.len());

    let mut out = String::with_capacity(s.len());
    // Keep the type-bearing header line; redact the key body.
    let header_line_end = s[begin..block_end]
        .find('\n')
        .map(|i| begin + i + 1)
        .unwrap_or(begin);
    out.push_str(&s[..header_line_end]);
    out.push_str("[REDACTED PEM BODY]\n");
    out.push_str(&redact_pem(&s[block_end..]));
    out
}

// --- Prefixed tokens (AWS keys, GitHub/Slack/OpenAI-style tokens) ---------

fn redact_prefixed_tokens(s: &str) -> String {
    let mut out = s.to_string();
    for (prefix, min_run) in [
        ("AKIA", 16usize),       // AWS access key id
        ("ASIA", 16),            // AWS temporary access key id
        ("ghp_", 20),            // GitHub PAT
        ("gho_", 20),            // GitHub OAuth
        ("ghu_", 20),            // GitHub user token
        ("ghs_", 20),            // GitHub server token
        ("ghr_", 20),            // GitHub refresh token
        ("sk-", 24),             // generic API secret / OpenAI-style
        ("xoxb-", 20),           // Slack bot token
        ("xoxp-", 20),           // Slack user token
        ("xoxa-", 20),           // Slack app token
        ("xoxs-", 20),           // Slack secret
    ] {
        out = redact_run(&out, prefix, min_run);
    }
    out
}

fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

/// Find `prefix` occurrences followed by >= min_run token chars and replace
/// the whole run with the prefix + [REDACTED].
fn redact_run(s: &str, prefix: &str, min_run: usize) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if s[i..].starts_with(prefix) {
            let mut j = i + prefix.len();
            while j < bytes.len() && is_token_char(bytes[j]) {
                j += 1;
            }
            if j - (i + prefix.len()) >= min_run {
                out.push_str(prefix);
                out.push_str("[REDACTED]");
                i = j;
                continue;
            }
        }
        // Advance one char (UTF-8 safe: copy until next boundary).
        let step = utf8_step(&s[i..]);
        out.push_str(&s[i..i + step]);
        i += step;
    }
    out
}

fn utf8_step(s: &str) -> usize {
    let b = s.as_bytes()[0];
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1 // invalid byte; advance carefully
    }
}

// --- key=value / key: value pairs ------------------------------------------

const SECRET_KEYS: [&str; 7] = [
    "password", "passwd", "secret", "token", "api_key", "apikey", "authorization",
];

fn redact_key_values(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let mut matched = false;
        if i == 0 || !is_word_byte(bytes[i - 1]) {
            for key in SECRET_KEYS {
                if lower[i..].starts_with(key) {
                    let after = i + key.len();
                    let mut k = after;
                    while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\t') {
                        k += 1;
                    }
                    let sep = bytes.get(k).copied();
                    if k < bytes.len() && (sep == Some(b'=') || sep == Some(b':')) {
                        let mut v = k + 1;
                        while v < bytes.len() && (bytes[v] == b' ' || bytes[v] == b'\t') {
                            v += 1;
                        }
                        let quote = bytes.get(v).copied();
                        let (value_end, total_end) = if quote == Some(b'"') || quote == Some(b'\'')
                        {
                            let mut e = v + 1;
                            while e < bytes.len() && bytes[e] != quote.unwrap() {
                                e += 1;
                            }
                            let te = (e + 1).min(bytes.len());
                            (e, te)
                        } else {
                            let mut e = v;
                            while e < bytes.len()
                                && bytes[e] != b' '
                                && bytes[e] != b'\t'
                                && bytes[e] != b'"'
                                && bytes[e] != b'\''
                                && bytes[e] != b','
                                && bytes[e] != b'}'
                            {
                                e += 1;
                            }
                            (e, e)
                        };
                        if value_end - v >= 4 {
                            out.push_str(&s[i..k + 1]);
                            out.push_str("[REDACTED]");
                            i = total_end;
                            matched = true;
                        }
                    }
                    break;
                }
            }
        }
        if !matched {
            let step = utf8_step(&s[i..]);
            out.push_str(&s[i..i + step]);
            i += step;
        }
    }
    out
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

#[cfg(test)]
mod tests {
    use super::sanitize_line;

    #[test]
    fn redacts_aws_key() {
        let out = sanitize_line(r#"{"key":"AKIAIOSFODNN7EXAMPLE"}"#);
        assert!(out.contains("AKIA[REDACTED]"), "{out}");
        assert!(!out.contains("EXAMPLE"));
    }

    #[test]
    fn redacts_github_token() {
        let out = sanitize_line("token=ghp_0123456789abcdefghijklmnopqrstuvwxyz");
        assert!(out.contains("[REDACTED]"), "{out}");
    }

    #[test]
    fn keeps_ordinary_lines() {
        let line = r#"{"path":"/home/user/project/src/main.rs"}"#;
        assert_eq!(sanitize_line(line), line);
    }

    #[test]
    fn redacts_password_pair() {
        let out = sanitize_line("password=\"hunter2hunter2\"");
        assert!(out.starts_with("password=[REDACTED]"), "{out}");
    }
}
