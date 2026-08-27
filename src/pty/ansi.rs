//! Zero-copy ANSI terminal escape code passthrough engine.
//!
//! Separates terminal control sequences (CSI, OSC, SGR, cursor movements)
//! from text payload before passing text to the streaming secret redactor,
//! then reassembles sanitized text with original terminal formatting intact.

use super::redact::{RedactionStyle, StreamingRedactor};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnsiState {
    Ground,
    Escape,
    Csi,
    Osc,
    OscEscape,
}

/// Token parsed from ANSI stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnsiToken<'a> {
    Text(&'a [u8]),
    Escape(&'a [u8]),
}

/// Zero-copy ANSI state machine parser.
pub struct AnsiParser {
    state: AnsiState,
    partial_escape: Vec<u8>,
}

impl AnsiParser {
    pub fn new() -> Self {
        Self {
            state: AnsiState::Ground,
            partial_escape: Vec::with_capacity(64),
        }
    }

    pub fn reset(&mut self) {
        self.state = AnsiState::Ground;
        self.partial_escape.clear();
    }
}

impl Default for AnsiParser {
    fn default() -> Self {
        Self::new()
    }
}

/// ANSI-aware streaming terminal redactor.
pub struct AnsiRedactor {
    parser: AnsiParser,
    redactor: StreamingRedactor,
}

impl AnsiRedactor {
    pub fn new() -> Self {
        Self::with_style(RedactionStyle::PadMask)
    }

    pub fn with_style(style: RedactionStyle) -> Self {
        Self {
            parser: AnsiParser::new(),
            redactor: StreamingRedactor::with_style(style),
        }
    }

    /// Redact a chunk of raw terminal bytes, preserving all ANSI escapes in place.
    pub fn redact_chunk(&mut self, chunk: &[u8]) -> Vec<u8> {
        let mut full_input = Vec::with_capacity(self.parser.partial_escape.len() + chunk.len());
        full_input.extend_from_slice(&self.parser.partial_escape);
        full_input.extend_from_slice(chunk);
        self.parser.partial_escape.clear();

        let mut output = Vec::with_capacity(full_input.len());
        let mut text_start = 0;
        let mut i = 0;
        let len = full_input.len();

        while i < len {
            let b = full_input[i];
            match self.parser.state {
                AnsiState::Ground => {
                    if b == 0x1b {
                        // Flush any preceding text to redactor
                        if i > text_start {
                            let text_chunk = &full_input[text_start..i];
                            output.extend(self.redactor.redact_chunk(text_chunk));
                        }
                        text_start = i;
                        self.parser.state = AnsiState::Escape;
                    }
                }
                AnsiState::Escape => match b {
                    b'[' => self.parser.state = AnsiState::Csi,
                    b']' => self.parser.state = AnsiState::Osc,
                    0x40..=0x5f => {
                        // 2-byte escape sequence (e.g. \x1b7, \x1b8, \x1bM)
                        output.extend_from_slice(&full_input[text_start..=i]);
                        text_start = i + 1;
                        self.parser.state = AnsiState::Ground;
                    }
                    _ => {
                        // Unknown or single ESC
                        output.extend_from_slice(&full_input[text_start..=i]);
                        text_start = i + 1;
                        self.parser.state = AnsiState::Ground;
                    }
                },
                AnsiState::Csi => {
                    // CSI parameter/intermediate bytes are 0x20..=0x3f; final byte is 0x40..=0x7e
                    if (0x40..=0x7e).contains(&b) {
                        output.extend_from_slice(&full_input[text_start..=i]);
                        text_start = i + 1;
                        self.parser.state = AnsiState::Ground;
                    }
                }
                AnsiState::Osc => {
                    // OSC terminated by BEL (\x07) or ST (\x1b\\)
                    if b == 0x07 {
                        output.extend_from_slice(&full_input[text_start..=i]);
                        text_start = i + 1;
                        self.parser.state = AnsiState::Ground;
                    } else if b == 0x1b {
                        self.parser.state = AnsiState::OscEscape;
                    }
                }
                AnsiState::OscEscape => {
                    if b == b'\\' {
                        output.extend_from_slice(&full_input[text_start..=i]);
                        text_start = i + 1;
                        self.parser.state = AnsiState::Ground;
                    } else {
                        self.parser.state = AnsiState::Osc;
                    }
                }
            }
            i += 1;
        }

        // Check if ending inside an unfinished ANSI sequence
        if self.parser.state != AnsiState::Ground {
            self.parser.partial_escape.extend_from_slice(&full_input[text_start..]);
        } else if text_start < len {
            let trailing_text = &full_input[text_start..];
            output.extend(self.redactor.redact_chunk(trailing_text));
        }

        output
    }

    /// Redact a string slice containing ANSI escapes.
    pub fn redact_str(&mut self, input: &str) -> String {
        let mut out = self.redact_chunk(input.as_bytes());
        out.extend(self.flush());
        String::from_utf8_lossy(&out).into_owned()
    }

    /// Flush any remaining buffered state.
    pub fn flush(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        if !self.parser.partial_escape.is_empty() {
            out.extend_from_slice(&self.parser.partial_escape);
            self.parser.partial_escape.clear();
        }
        out.extend(self.redactor.flush());
        out
    }

    /// Reset internal state.
    pub fn reset(&mut self) {
        self.parser.reset();
        self.redactor.reset();
    }
}

impl Default for AnsiRedactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ansi_passthrough_with_redaction() {
        let mut redactor = AnsiRedactor::with_style(RedactionStyle::Marker);
        let styled_text = "\x1b[31;1mToken: ghp_0123456789abcdefghijklmnopqrstuvwxyz\x1b[0m\r\n";
        let output = redactor.redact_str(styled_text);

        assert!(output.starts_with("\x1b[31;1mToken: ghp_[REDACTED]"));
        assert!(output.ends_with("\x1b[0m\r\n"));
    }

    #[test]
    fn test_ansi_split_across_chunks() {
        let mut redactor = AnsiRedactor::with_style(RedactionStyle::PadMask);
        let chunk1 = b"\x1b[32";
        let chunk2 = b"mOK\x1b[0m";

        let mut out = redactor.redact_chunk(chunk1);
        out.extend(redactor.redact_chunk(chunk2));
        out.extend(redactor.flush());

        assert_eq!(out, b"\x1b[32mOK\x1b[0m");
    }
}
