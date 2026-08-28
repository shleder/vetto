//! Zero-overhead streaming PTY redactor utilizing Aho-Corasick multi-pattern automaton
//! and 256-byte carry-over lookback buffer across chunk reads.

use std::collections::VecDeque;
use super::entropy;

/// Redaction replacement style.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedactionStyle {
    /// In-place padding with '*' (preserves exact terminal column width for TUIs).
    PadMask,
    /// Marker string substitution (e.g., "[REDACTED]").
    Marker,
}

impl Default for RedactionStyle {
    fn default() -> Self {
        Self::PadMask
    }
}

/// Pattern descriptor for Aho-Corasick automaton.
#[derive(Debug, Clone)]
struct PatternInfo {
    prefix: Vec<u8>,
    min_run_len: usize,
    is_pem: bool,
    is_bearer: bool,
}

#[derive(Debug, Clone)]
struct AcNode {
    next: Vec<(u8, usize)>,
    fail: usize,
    pattern_matches: Vec<usize>,
}

impl AcNode {
    fn new() -> Self {
        Self {
            next: Vec::new(),
            fail: 0,
            pattern_matches: Vec::new(),
        }
    }

    fn get_next(&self, b: u8) -> Option<usize> {
        self.next.iter().find(|&&(byte, _)| byte == b).map(|&(_, idx)| idx)
    }

    fn set_next(&mut self, b: u8, idx: usize) {
        if let Some(pos) = self.next.iter().position(|&(byte, _)| byte == b) {
            self.next[pos] = (b, idx);
        } else {
            self.next.push((b, idx));
        }
    }
}

/// Fast multi-pattern Aho-Corasick automaton.
#[derive(Debug, Clone)]
struct AhoCorasick {
    nodes: Vec<AcNode>,
    patterns: Vec<PatternInfo>,
}

impl AhoCorasick {
    fn new(patterns: Vec<PatternInfo>) -> Self {
        let mut ac = Self {
            nodes: vec![AcNode::new()],
            patterns,
        };
        ac.build();
        ac
    }

    fn build(&mut self) {
        for (pattern_idx, pattern) in self.patterns.iter().enumerate() {
            let mut current = 0;
            for &byte in &pattern.prefix {
                let next_node = match self.nodes[current].get_next(byte) {
                    Some(next) => next,
                    None => {
                        let new_node_idx = self.nodes.len();
                        self.nodes.push(AcNode::new());
                        self.nodes[current].set_next(byte, new_node_idx);
                        new_node_idx
                    }
                };
                current = next_node;
            }
            self.nodes[current].pattern_matches.push(pattern_idx);
        }

        // BFS for failure links
        let mut queue = VecDeque::new();
        let root_next: Vec<(u8, usize)> = self.nodes[0].next.clone();
        for &(_, next_idx) in &root_next {
            self.nodes[next_idx].fail = 0;
            queue.push_back(next_idx);
        }

        while let Some(current) = queue.pop_front() {
            for i in 0..self.nodes[current].next.len() {
                let (byte, next_idx) = self.nodes[current].next[i];
                let mut fail_node = self.nodes[current].fail;
                while fail_node != 0 && self.nodes[fail_node].get_next(byte).is_none() {
                    fail_node = self.nodes[fail_node].fail;
                }
                let target_fail = match self.nodes[fail_node].get_next(byte) {
                    Some(idx) if idx != next_idx => idx,
                    _ => 0,
                };
                self.nodes[next_idx].fail = target_fail;
                let matches_to_add = self.nodes[target_fail].pattern_matches.clone();
                self.nodes[next_idx].pattern_matches.extend(matches_to_add);
                queue.push_back(next_idx);
            }
        }
    }

    fn step(&self, mut current_state: usize, byte: u8) -> (usize, &[usize]) {
        loop {
            if let Some(next) = self.nodes[current_state].get_next(byte) {
                return (next, &self.nodes[next].pattern_matches);
            }
            if current_state == 0 {
                return (0, &[]);
            }
            current_state = self.nodes[current_state].fail;
        }
    }
}

/// Zero-overhead streaming PTY redactor.
pub struct StreamingRedactor {
    automaton: AhoCorasick,
    carry_over: Vec<u8>,
    style: RedactionStyle,
}

impl StreamingRedactor {
    pub fn new() -> Self {
        Self::with_style(RedactionStyle::PadMask)
    }

    pub fn with_style(style: RedactionStyle) -> Self {
        let patterns = vec![
            PatternInfo { prefix: b"sk-proj-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"sk-ant-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"sk-".to_vec(), min_run_len: 24, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"ghp_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"gho_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"ghu_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"ghs_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"ghr_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"AKIA".to_vec(), min_run_len: 16, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"ASIA".to_vec(), min_run_len: 16, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"xoxb-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"xoxp-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"xoxa-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"xoxs-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"glpat-".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"hf_".to_vec(), min_run_len: 20, is_pem: false, is_bearer: false },
            PatternInfo { prefix: b"Bearer ".to_vec(), min_run_len: 8, is_pem: false, is_bearer: true },
            PatternInfo { prefix: b"bearer ".to_vec(), min_run_len: 8, is_pem: false, is_bearer: true },
            PatternInfo { prefix: b"-----BEGIN PRIVATE KEY-----".to_vec(), min_run_len: 0, is_pem: true, is_bearer: false },
            PatternInfo { prefix: b"-----BEGIN RSA PRIVATE KEY-----".to_vec(), min_run_len: 0, is_pem: true, is_bearer: false },
            PatternInfo { prefix: b"-----BEGIN EC PRIVATE KEY-----".to_vec(), min_run_len: 0, is_pem: true, is_bearer: false },
            PatternInfo { prefix: b"-----BEGIN OPENSSH PRIVATE KEY-----".to_vec(), min_run_len: 0, is_pem: true, is_bearer: false },
            PatternInfo { prefix: b"-----BEGIN CERTIFICATE-----".to_vec(), min_run_len: 0, is_pem: true, is_bearer: false },
        ];
        Self {
            automaton: AhoCorasick::new(patterns),
            carry_over: Vec::with_capacity(256),
            style,
        }
    }

    /// Process a streaming chunk of bytes, returning the redacted slice.
    pub fn redact_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        if chunk.is_empty() && self.carry_over.is_empty() {
            return Vec::new();
        }

        let mut buffer = Vec::with_capacity(self.carry_over.len() + chunk.len());
        buffer.extend_from_slice(&self.carry_over);
        buffer.extend_from_slice(chunk);
        self.carry_over.clear();

        let mut redacted_spans: Vec<(usize, usize, usize)> = Vec::new(); // (start, end, pattern_idx)
        let mut state = 0;

        let mut i = 0;
        while i < buffer.len() {
            let (next_state, matches) = self.automaton.step(state, buffer[i]);
            state = next_state;

            for &pattern_idx in matches {
                let pat = &self.automaton.patterns[pattern_idx];
                let match_start = (i + 1).saturating_sub(pat.prefix.len());

                if pat.is_pem {
                    // Find END marker
                    if let Some(rel_end) = find_subsequence(&buffer[i..], b"-----END") {
                        let pem_body_start = i;
                        let pem_end = (i + rel_end + 32).min(buffer.len());
                        redacted_spans.push((pem_body_start, pem_end, pattern_idx));
                    }
                } else if pat.is_bearer {
                    let token_start = match_start + pat.prefix.len();
                    let mut token_end = token_start;
                    while token_end < buffer.len() && is_token_char(buffer[token_end]) {
                        token_end += 1;
                    }
                    if token_end - token_start >= pat.min_run_len {
                        redacted_spans.push((token_start, token_end, pattern_idx));
                    }
                } else {
                    let mut token_end = match_start + pat.prefix.len();
                    while token_end < buffer.len() && is_token_char(buffer[token_end]) {
                        token_end += 1;
                    }
                    if token_end - match_start >= pat.min_run_len {
                        redacted_spans.push((match_start + pat.prefix.len(), token_end, pattern_idx));
                    }
                }
            }
            i += 1;
        }

        // Apply redactions
        let mut result = Vec::with_capacity(buffer.len());
        let mut cursor = 0;

        // Sort and deduplicate overlapping spans (prefer longest prefix / largest start)
        redacted_spans.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(&a.0)));
        redacted_spans.dedup_by(|a, b| a.1 == b.1);
        redacted_spans.sort_by_key(|&(s, _, _)| s);

        for (start, end, _) in redacted_spans {
            if start < cursor {
                continue;
            }
            result.extend_from_slice(&buffer[cursor..start]);
            let length = end - start;
            match self.style {
                RedactionStyle::PadMask => {
                    result.extend(std::iter::repeat(b'*').take(length));
                }
                RedactionStyle::Marker => {
                    result.extend_from_slice(b"[REDACTED]");
                }
            }
            cursor = end;
        }

        let tail = &buffer[cursor..];
        // Determine safe carry-over window at chunk boundary (up to 256 bytes)
        // Only carry over if we end mid-token
        if tail.len() > 256 {
            let safe_emit = tail.len() - 256;
            result.extend_from_slice(&tail[..safe_emit]);
            self.carry_over.extend_from_slice(&tail[safe_emit..]);
        } else if !tail.is_empty() && is_token_char(*tail.last().unwrap()) {
            self.carry_over.extend_from_slice(tail);
        } else {
            result.extend_from_slice(tail);
        }

        // Apply entropy masking on emitted slice
        if self.style == RedactionStyle::PadMask {
            entropy::mask_high_entropy_pad(&mut result);
        }

        result
    }

    /// Redact a string completely and flush any buffered state.
    pub fn redact_str(&mut self, input: &str) -> String {
        let chunk = input.as_bytes();
        let mut out = self.redact_chunk(chunk);
        out.extend(self.flush());
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Flush any remaining carry-over bytes.
    pub fn flush(&mut self) -> Vec<u8> {
        let mut remaining = std::mem::take(&mut self.carry_over);
        if self.style == RedactionStyle::PadMask {
            entropy::mask_high_entropy_pad(&mut remaining);
        }
        remaining
    }

    /// Reset internal buffer state.
    pub fn reset(&mut self) {
        self.carry_over.clear();
    }
}

impl Default for StreamingRedactor {
    fn default() -> Self {
        Self::new()
    }
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'+' | b'/' | b'=')
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prefixed_token_redaction_pad_mask() {
        let mut redactor = StreamingRedactor::with_style(RedactionStyle::PadMask);
        let secret = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz";
        let output = redactor.redact_str(secret);
        assert!(output.starts_with("sk-proj-"));
        assert!(!output.contains("0123456789abcdef"));
        assert_eq!(output.len(), secret.len(), "PadMask must preserve length");
    }

    #[test]
    fn test_prefixed_token_redaction_marker() {
        let mut redactor = StreamingRedactor::with_style(RedactionStyle::Marker);
        let secret = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        let output = redactor.redact_str(secret);
        assert!(output.contains("ghp_[REDACTED]"));
    }

    #[test]
    fn test_chunk_split_boundary_carry_over() {
        let mut redactor = StreamingRedactor::with_style(RedactionStyle::Marker);
        let chunk1 = b"export GITHUB_TOKEN=ghp_";
        let chunk2 = b"0123456789abcdefghijklmnopqrstuvwxyz\n";

        let mut out = redactor.redact_chunk(chunk1);
        out.extend(redactor.redact_chunk(chunk2));
        out.extend(redactor.flush());

        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("GITHUB_TOKEN=ghp_[REDACTED]"));
    }
}
