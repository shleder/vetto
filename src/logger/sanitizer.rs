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
    let line = redact_key_values(&line);
    let line = redact_bearer_tokens(&line);
    let line = redact_env_assignments(&line);
    redact_high_entropy_runs(&line)
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
        ("AKIA", 16usize), // AWS access key id
        ("ASIA", 16),      // AWS temporary access key id
        ("ghp_", 20),      // GitHub PAT
        ("gho_", 20),      // GitHub OAuth
        ("ghu_", 20),      // GitHub user token
        ("ghs_", 20),      // GitHub server token
        ("ghr_", 20),      // GitHub refresh token
        ("sk-", 24),       // generic API secret / OpenAI-style
        ("xoxb-", 20),     // Slack bot token
        ("xoxp-", 20),     // Slack user token
        ("xoxa-", 20),     // Slack app token
        ("xoxs-", 20),     // Slack secret
    ] {
        out = redact_run(&out, prefix, min_run);
    }
    out
}

fn redact_bearer_tokens(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if lower[i..].starts_with("bearer ") {
            let value_start = i + "bearer ".len();
            let mut end = value_start;
            while end < bytes.len()
                && !bytes[end].is_ascii_whitespace()
                && !matches!(bytes[end], b'"' | b'\'' | b',' | b'{' | b'}' | b'[' | b']')
            {
                end += 1;
            }
            if end.saturating_sub(value_start) >= 8 {
                out.push_str(&s[i..value_start]);
                out.push_str("[REDACTED]");
                i = end;
                continue;
            }
        }
        let step = utf8_step(&s[i..]);
        out.push_str(&s[i..i + step]);
        i += step;
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
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
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
                        if key == "authorization" && lower[v..].starts_with("bearer ") {
                            let token_start = v + "bearer ".len();
                            let mut token_end = token_start;
                            while token_end < bytes.len()
                                && !bytes[token_end].is_ascii_whitespace()
                                && !matches!(
                                    bytes[token_end],
                                    b'"' | b'\'' | b',' | b'{' | b'}' | b'[' | b']'
                                )
                            {
                                token_end += 1;
                            }
                            if token_end.saturating_sub(token_start) >= 8 {
                                out.push_str(&s[i..token_start]);
                                out.push_str("[REDACTED]");
                                i = token_end;
                                matched = true;
                                break;
                            }
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

/// Redact shell/.env-style uppercase assignments. Without source-file
/// context this necessarily has false positives, hence the module-wide
/// BEST-EFFORT label.
fn redact_env_assignments(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        let boundary =
            i == 0 || bytes[i - 1].is_ascii_whitespace() || matches!(bytes[i - 1], b'"' | b'\'');
        if boundary && (bytes[i].is_ascii_uppercase() || bytes[i] == b'_') {
            let mut key_end = i;
            while key_end < bytes.len()
                && (bytes[key_end].is_ascii_uppercase()
                    || bytes[key_end].is_ascii_digit()
                    || bytes[key_end] == b'_')
            {
                key_end += 1;
            }
            let mut separator = key_end;
            while separator < bytes.len() && (bytes[separator] == b' ' || bytes[separator] == b'\t')
            {
                separator += 1;
            }
            if key_end.saturating_sub(i) >= 2 && bytes.get(separator) == Some(&b'=') {
                let mut value_start = separator + 1;
                while value_start < bytes.len()
                    && (bytes[value_start] == b' ' || bytes[value_start] == b'\t')
                {
                    value_start += 1;
                }
                let quote = bytes
                    .get(value_start)
                    .copied()
                    .filter(|b| matches!(b, b'"' | b'\''));
                let content_start = value_start + usize::from(quote.is_some());
                let mut end = content_start;
                while end < bytes.len()
                    && match quote {
                        Some(q) => bytes[end] != q,
                        None => {
                            !bytes[end].is_ascii_whitespace() && !matches!(bytes[end], b',' | b'}')
                        }
                    }
                {
                    end += 1;
                }
                if end.saturating_sub(content_start) >= 4 {
                    out.push_str(&s[i..=separator]);
                    out.push_str("[REDACTED]");
                    i = if quote.is_some() && end < bytes.len() {
                        end + 1
                    } else {
                        end
                    };
                    continue;
                }
            }
        }
        let step = utf8_step(&s[i..]);
        out.push_str(&s[i..i + step]);
        i += step;
    }
    out
}

fn redact_high_entropy_runs(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if is_entropy_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_entropy_char(bytes[i]) {
                i += 1;
            }
            let candidate = &bytes[start..i];
            if candidate.len() >= 20
                && !is_whitelisted_hash_or_pattern(candidate)
                && shannon_entropy(candidate) > 4.5
            {
                out.push_str("[REDACTED_HIGH_ENTROPY]");
            } else {
                out.push_str(&s[start..i]);
            }
            continue;
        }
        let step = utf8_step(&s[i..]);
        out.push_str(&s[i..i + step]);
        i += step;
    }
    out
}

fn is_whitelisted_hash_or_pattern(token: &[u8]) -> bool {
    let is_pure_hex = token.iter().all(|&b| b.is_ascii_hexdigit());
    if is_pure_hex && matches!(token.len(), 32 | 40 | 64 | 128) {
        return true;
    }
    if token.len() == 36 && is_uuid_format(token) {
        return true;
    }
    let is_pure_digits = token.iter().all(|&b| b.is_ascii_digit());
    if is_pure_digits {
        return true;
    }
    let is_pure_lowercase = token.iter().all(|&b| b.is_ascii_lowercase());
    if is_pure_lowercase && shannon_entropy(token) < 4.6 {
        return true;
    }
    false
}

fn is_uuid_format(token: &[u8]) -> bool {
    if token.len() != 36 {
        return false;
    }
    for (i, &b) in token.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn is_entropy_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'/' | b'=')
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let length = bytes.len() as f64;
    counts
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = f64::from(count) / length;
            -probability * probability.log2()
        })
        .sum()
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

    #[test]
    fn redacts_bearer_env_and_high_entropy_values() {
        let bearer = sanitize_line("Authorization: Bearer abcdefghijklmnop");
        assert_eq!(bearer, "Authorization: Bearer [REDACTED]");
        assert_eq!(
            sanitize_line("authorization:\tBEARER abcdefghijklmnop"),
            "authorization:\tBEARER [REDACTED]"
        );

        let env = sanitize_line("DATABASE_URL=postgres://user:pass@example.invalid/db");
        assert_eq!(env, "DATABASE_URL=[REDACTED]");
        assert_eq!(
            sanitize_line("OPENAI_API_KEY = abcdefghijklmnop"),
            "OPENAI_API_KEY =[REDACTED]"
        );

        let random = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";
        let entropy = sanitize_line(random);
        assert_eq!(entropy, "[REDACTED_HIGH_ENTROPY]");
    }
}
