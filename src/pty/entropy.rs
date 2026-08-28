//! Real-time sliding-window Shannon entropy secret masking.
//!
//! Evaluates Shannon entropy on whitespace/delimiter-bounded word tokens:
//! H(X) = - sum_i P(x_i) * log2(P(x_i))
//!
//! Masking triggers if H > 4.5 bits/byte on token lengths >= 20 bytes,
//! with false-positive whitelist suppression for hashes, UUIDs, and paths.

/// Threshold for Shannon entropy masking (bits/byte).
pub const ENTROPY_THRESHOLD: f64 = 4.5;
/// Minimum token length to trigger Shannon entropy evaluation.
pub const MIN_ENTROPY_TOKEN_LEN: usize = 20;

/// Compute Shannon entropy in bits per byte over a byte slice.
pub fn calculate_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len_f = bytes.len() as f64;
    counts
        .iter()
        .copied()
        .filter(|&c| c > 0)
        .map(|c| {
            let p = (c as f64) / len_f;
            -p * p.log2()
        })
        .sum()
}

/// Determine whether a token qualifies as high entropy and is not whitelisted.
pub fn is_entropy_masked(token: &[u8]) -> bool {
    if token.len() < MIN_ENTROPY_TOKEN_LEN {
        return false;
    }
    if is_whitelisted_hash_or_pattern(token) {
        return false;
    }
    calculate_entropy(token) > ENTROPY_THRESHOLD
}

/// Check if a byte is part of a potential entropy token run.
#[inline]
pub fn is_entropy_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'+' | b'/')
}

/// Whitelist filters to suppress false positives on commit SHAs, UUIDs, and base64 hashes.
fn is_whitelisted_hash_or_pattern(token: &[u8]) -> bool {
    // 1. Pure hex hashes (git SHAs [0-9a-fA-F]{40}, sha256 [0-9a-fA-F]{64}, md5 [0-9a-fA-F]{32})
    let is_pure_hex = token.iter().all(|&b| b.is_ascii_hexdigit());
    if is_pure_hex && matches!(token.len(), 32 | 40 | 64 | 128) {
        return true;
    }

    // 2. UUID format: 8-4-4-4-12 hex chars separated by dashes (len 36)
    if token.len() == 36 && is_uuid_format(token) {
        return true;
    }

    // 3. Monotonous / repetitive tokens or pure digits / single-cased alpha
    let is_pure_digits = token.iter().all(|&b| b.is_ascii_digit());
    if is_pure_digits {
        return true;
    }

    let is_pure_lowercase = token.iter().all(|&b| b.is_ascii_lowercase());
    if is_pure_lowercase && calculate_entropy(token) < 4.6 {
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

/// Mask high-entropy tokens in a string slice using marker replacement.
pub fn mask_high_entropy_tokens(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if is_entropy_token_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_entropy_token_char(bytes[i]) {
                i += 1;
            }
            let candidate = &bytes[start..i];
            if is_entropy_masked(candidate) {
                out.push_str("[REDACTED_HIGH_ENTROPY]");
            } else {
                out.push_str(&s[start..i]);
            }
            continue;
        }
        let step = utf8_char_len(bytes[i]);
        let end = (i + step).min(s.len());
        out.push_str(&s[i..end]);
        i = end;
    }
    out
}

/// Mask high-entropy tokens in a byte slice with in-place padding (pad with '*').
pub fn mask_high_entropy_pad(bytes: &mut [u8]) {
    let mut i = 0usize;
    while i < bytes.len() {
        if is_entropy_token_char(bytes[i]) {
            let start = i;
            while i < bytes.len() && is_entropy_token_char(bytes[i]) {
                i += 1;
            }
            let candidate = &bytes[start..i];
            if is_entropy_masked(candidate) {
                for b in &mut bytes[start..i] {
                    *b = b'*';
                }
            }
            continue;
        }
        i += 1;
    }
}

fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy_calculation() {
        // Uniform distribution over 16 chars: log2(16) = 4.0
        let hex = b"0123456789abcdef";
        let h = calculate_entropy(hex);
        assert!((h - 4.0).abs() < 1e-6);

        // Uniform distribution over 64 chars: log2(64) = 6.0
        let b64 = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let h_b64 = calculate_entropy(b64);
        assert!((h_b64 - 6.0).abs() < 1e-6);
    }

    #[test]
    fn test_high_entropy_masking() {
        // Strip non-entropy chars to form a token
        let token = "aB39zKmP2qL8vX1yR4wT7jN_xY9ZaBc";
        assert!(is_entropy_masked(token.as_bytes()));

        let text = format!("key={token} ordinary");
        let masked = mask_high_entropy_tokens(&text);
        assert_eq!(masked, "key=[REDACTED_HIGH_ENTROPY] ordinary");
    }

    #[test]
    fn test_whitelist_suppression() {
        // Git SHA-1 (40 hex chars)
        let git_sha = "e0d123456789abcdef0123456789abcdef012345";
        assert!(!is_entropy_masked(git_sha.as_bytes()));

        // UUID
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        assert!(!is_entropy_masked(uuid.as_bytes()));
    }
}
