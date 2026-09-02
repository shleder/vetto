//! `vetto mask` CLI subcommand: real-time streaming secret redactor pipe.
//!
//! Reads standard input (or any reader) and writes redacted output to stdout (or any writer).
//! Example usage: `cat .env | vetto mask` or `env | vetto mask --style pad`.

use std::io::{self, Read, Write};

use anyhow::Result;
use clap::ValueEnum;

use crate::pty::redact::RedactionStyle;

/// CLI argument for secret redaction style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum MaskStyle {
    /// Substitute secrets with marker string "[REDACTED]"
    #[default]
    Marker,
    /// In-place padding with '*' (preserves exact character length)
    Pad,
}

impl From<MaskStyle> for RedactionStyle {
    fn from(s: MaskStyle) -> Self {
        match s {
            MaskStyle::Marker => RedactionStyle::Marker,
            MaskStyle::Pad => RedactionStyle::PadMask,
        }
    }
}

/// Arguments for `vetto mask`.
#[derive(clap::Args, Debug, Clone)]
pub struct MaskArgs {
    /// Redaction style: marker (default, [REDACTED]) or pad (in-place '*')
    #[arg(long, default_value = "marker", value_enum)]
    pub style: MaskStyle,
}

/// Run streaming redaction from an arbitrary reader to an arbitrary writer.
pub fn stream_mask<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    style: RedactionStyle,
) -> Result<()> {
    let mut redactor = crate::pty::AnsiRedactor::with_style(style);
    let mut buf = [0u8; 8192];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let redacted = redactor.redact_chunk(&buf[..n]);
                if !redacted.is_empty() {
                    writer.write_all(&redacted)?;
                    writer.flush()?;
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let flushed = redactor.flush();
    if !flushed.is_empty() {
        writer.write_all(&flushed)?;
        writer.flush()?;
    }
    Ok(())
}

/// Execute the `vetto mask` subcommand reading stdin and writing to stdout.
pub fn run_mask(args: &MaskArgs) -> Result<()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    stream_mask(stdin.lock(), stdout.lock(), args.style.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_stream_mask_marker_style() {
        let input = "export ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789\n\
                     export OPENAI_API_KEY=sk-proj-0123456789abcdefghijklmnopqrstuvwxyz\n\
                     export GEMINI_API_KEY=AIzaSyD-0123456789abcdefghijklmnopqrstuvwxyz\n\
                     export NPM_TOKEN=npm_0123456789abcdefghijklmnopqrstuvwxyz\n\
                     export PYPI_TOKEN=pypi-0123456789abcdefghijklmnopqrstuvwxyz\n\
                     export GITHUB_TOKEN=gho_0123456789abcdefghijklmnopqrstuvwxyz\n\
                     export MY_KEY=secret_key_val_12345678\n";
        let mut output = Vec::new();
        stream_mask(Cursor::new(input), &mut output, RedactionStyle::Marker).unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.contains("sk-ant-[REDACTED]"));
        assert!(result.contains("sk-proj-[REDACTED]"));
        assert!(result.contains("AIza[REDACTED]"));
        assert!(result.contains("npm_[REDACTED]"));
        assert!(result.contains("pypi-[REDACTED]"));
        assert!(result.contains("gho_[REDACTED]"));
        assert!(result.contains("MY_KEY=[REDACTED]"));
        assert!(!result.contains("0123456789abcdefghijklmnopqrstuvwxyz"));
        assert!(!result.contains("secret_key_val_12345678"));
    }

    #[test]
    fn test_stream_mask_pad_style() {
        let secret = "sk-proj-0123456789abcdefghijklmnopqrstuvwxyz";
        let input = format!("TOKEN={secret}\n");
        let mut output = Vec::new();
        stream_mask(Cursor::new(input.as_bytes()), &mut output, RedactionStyle::PadMask)
            .unwrap();
        let result = String::from_utf8(output).unwrap();

        assert!(result.starts_with("TOKEN=sk-proj-"));
        assert!(!result.contains("0123456789abcdef"));
        assert_eq!(result.trim(), format!("TOKEN=sk-proj-{}", "*".repeat(36)));
    }
}
