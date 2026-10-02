//! Unified memory and byte quantity parsing and formatting across Vetto.
//!
//! Enforces strict separation and mathematical correctness:
//! - IEC Binary standard: KiB (1024), MiB (1024^2), GiB (1024^3), TiB (1024^4)
//! - SI Decimal standard: KB (1000), MB (1000^2), GB (1000^3), TB (1000^4)
//! - Traditional single-letter suffixes: k, m, g, t (1024-based binary, matching Linux cgroups and ulimit)
//! - Byte suffix: b, B (1)
//! - Plain integers: raw byte count
//!
//! Provides overflow protection via `checked_mul` and fail-closed error handling.

use thiserror::Error;

/// Multiplier constants for byte unit calculations.
const KIB: u64 = 1024;
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * 1024 * 1024;
const TIB: u64 = 1024 * 1024 * 1024 * 1024;

const KB: u64 = 1000;
const MB: u64 = 1000 * 1000;
const GB: u64 = 1000 * 1000 * 1000;
const TB: u64 = 1000 * 1000 * 1000 * 1000;

/// Standard for formatting and interpreting byte quantity representations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStandard {
    /// IEC standard powers of 2 (1024-based): KiB, MiB, GiB, TiB.
    IecBinary,
    /// SI standard powers of 10 (1000-based): KB, MB, GB, TB.
    SiDecimal,
}

/// Errors occurring during byte quantity string parsing.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ParseBytesError {
    #[error("byte string is empty")]
    Empty,
    #[error("invalid numeric value: '{0}'")]
    InvalidNumber(String),
    #[error("unknown unit suffix: '{0}'")]
    UnknownUnit(String),
    #[error("arithmetic overflow calculating byte size")]
    Overflow,
}

/// Parse a human-readable byte quantity string into an exact byte count (`u64`).
///
/// Supported suffixes (case-insensitive):
/// - IEC Binary (1024-based): `kib`, `mib`, `gib`, `tib`
/// - SI Decimal (1000-based): `kb`, `mb`, `gb`, `tb`
/// - Traditional Unix / cgroup binary (1024-based): `k`, `m`, `g`, `t`
/// - Single byte: `b`
/// - Plain integer without suffix: interpreted as raw bytes
///
/// Fractional values (e.g. `1.5 GiB`, `0.5 mb`) are rounded to the nearest integer byte.
/// Overflow during multiplication or conversion is rejected with [`ParseBytesError::Overflow`].
pub fn parse_bytes(input: &str) -> Result<u64, ParseBytesError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(ParseBytesError::Empty);
    }

    // Direct plain integer check (e.g. "1024", "0")
    if let Ok(raw) = s.parse::<u64>() {
        return Ok(raw);
    }

    let lower = s.to_ascii_lowercase();

    // Suffix matching in strict order: 3-char suffixes, then 2-char, then 1-char
    let (number_str, mult) = if let Some(n) = lower.strip_suffix("tib") {
        (n, TIB)
    } else if let Some(n) = lower.strip_suffix("gib") {
        (n, GIB)
    } else if let Some(n) = lower.strip_suffix("mib") {
        (n, MIB)
    } else if let Some(n) = lower.strip_suffix("kib") {
        (n, KIB)
    } else if let Some(n) = lower.strip_suffix("tb") {
        (n, TB)
    } else if let Some(n) = lower.strip_suffix("gb") {
        (n, GB)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, MB)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, KB)
    } else if let Some(n) = lower.strip_suffix('t') {
        (n, TIB)
    } else if let Some(n) = lower.strip_suffix('g') {
        (n, GIB)
    } else if let Some(n) = lower.strip_suffix('m') {
        (n, MIB)
    } else if let Some(n) = lower.strip_suffix('k') {
        (n, KIB)
    } else if let Some(n) = lower.strip_suffix('b') {
        (n, 1u64)
    } else {
        // If it's a sequence of all digits that failed u64::parse, it's an overflow
        if s.chars().all(|c| c.is_ascii_digit()) {
            return Err(ParseBytesError::Overflow);
        }
        return Err(ParseBytesError::UnknownUnit(s.to_string()));
    };

    let trimmed = number_str.trim();
    if trimmed.is_empty() {
        return Err(ParseBytesError::InvalidNumber(trimmed.to_string()));
    }

    if trimmed.contains('.') {
        let val: f64 = trimmed
            .parse()
            .map_err(|_| ParseBytesError::InvalidNumber(trimmed.to_string()))?;

        if !val.is_finite() || val < 0.0 {
            return Err(ParseBytesError::InvalidNumber(trimmed.to_string()));
        }

        let bytes = (val * mult as f64).round();
        if bytes > u64::MAX as f64 {
            return Err(ParseBytesError::Overflow);
        }
        Ok(bytes as u64)
    } else {
        let val: u64 = trimmed.parse().map_err(|_| {
            if trimmed.starts_with('-') || !trimmed.chars().all(|c| c.is_ascii_digit()) {
                ParseBytesError::InvalidNumber(trimmed.to_string())
            } else {
                ParseBytesError::Overflow
            }
        })?;

        val.checked_mul(mult).ok_or(ParseBytesError::Overflow)
    }
}

/// Parse a cgroup memory specification (e.g. `memory.max` or `memory.swap.max`).
///
/// Treats `"max"`, `"-1"`, and empty/whitespace inputs as unlimited (`Ok(None)`).
/// All other values are delegated to [`parse_bytes`] and wrapped in `Ok(Some(bytes))`.
pub fn parse_cgroup_memory(input: &str) -> Result<Option<u64>, ParseBytesError> {
    let s = input.trim();
    if s.is_empty() || s.eq_ignore_ascii_case("max") || s == "-1" {
        return Ok(None);
    }
    parse_bytes(s).map(Some)
}

/// Format a byte count into a human-readable string according to the requested unit standard.
pub fn format_bytes(bytes: u64, standard: UnitStandard) -> String {
    let (kilo, suffix_k, suffix_m, suffix_g, suffix_t) = match standard {
        UnitStandard::IecBinary => (1024.0, "KiB", "MiB", "GiB", "TiB"),
        UnitStandard::SiDecimal => (1000.0, "KB", "MB", "GB", "TB"),
    };

    let b = bytes as f64;
    if b < kilo {
        format!("{bytes} B")
    } else if b < kilo * kilo {
        format!("{:.1} {}", b / kilo, suffix_k)
    } else if b < kilo * kilo * kilo {
        format!("{:.1} {}", b / (kilo * kilo), suffix_m)
    } else if b < kilo * kilo * kilo * kilo {
        format!("{:.1} {}", b / (kilo * kilo * kilo), suffix_g)
    } else {
        format!("{:.1} {}", b / (kilo * kilo * kilo * kilo), suffix_t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bytes_iec_binary_suffixes() {
        assert_eq!(parse_bytes("1kib").unwrap(), 1024);
        assert_eq!(parse_bytes("2KiB").unwrap(), 2048);
        assert_eq!(parse_bytes("1024kib").unwrap(), 1024 * 1024);
        assert_eq!(parse_bytes("1mib").unwrap(), 1024 * 1024);
        assert_eq!(parse_bytes("5MiB").unwrap(), 5 * 1024 * 1024);
        assert_eq!(parse_bytes("64mib").unwrap(), 64 * 1024 * 1024);
        assert_eq!(parse_bytes("1gib").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("2GiB").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("16gib").unwrap(), 16 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1tib").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("4TiB").unwrap(), 4 * 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_bytes_si_decimal_suffixes() {
        assert_eq!(parse_bytes("1kb").unwrap(), 1000);
        assert_eq!(parse_bytes("2KB").unwrap(), 2000);
        assert_eq!(parse_bytes("500kb").unwrap(), 500_000);
        assert_eq!(parse_bytes("1mb").unwrap(), 1_000_000);
        assert_eq!(parse_bytes("10MB").unwrap(), 10_000_000);
        assert_eq!(parse_bytes("100mb").unwrap(), 100_000_000);
        assert_eq!(parse_bytes("1gb").unwrap(), 1_000_000_000);
        assert_eq!(parse_bytes("2GB").unwrap(), 2_000_000_000);
        assert_eq!(parse_bytes("1tb").unwrap(), 1_000_000_000_000);
        assert_eq!(parse_bytes("2TB").unwrap(), 2_000_000_000_000);
    }

    #[test]
    fn test_parse_bytes_traditional_single_letter_suffixes() {
        assert_eq!(parse_bytes("1k").unwrap(), 1024);
        assert_eq!(parse_bytes("2K").unwrap(), 2048);
        assert_eq!(parse_bytes("64k").unwrap(), 64 * 1024);
        assert_eq!(parse_bytes("1m").unwrap(), 1024 * 1024);
        assert_eq!(parse_bytes("512M").unwrap(), 512 * 1024 * 1024);
        assert_eq!(parse_bytes("1g").unwrap(), 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("2G").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("1t").unwrap(), 1024 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("2T").unwrap(), 2 * 1024 * 1024 * 1024 * 1024);
    }

    #[test]
    fn test_parse_bytes_raw_integers_and_b_suffix() {
        assert_eq!(parse_bytes("0").unwrap(), 0);
        assert_eq!(parse_bytes("1").unwrap(), 1);
        assert_eq!(parse_bytes("1024").unwrap(), 1024);
        assert_eq!(parse_bytes("4096").unwrap(), 4096);
        assert_eq!(parse_bytes("18446744073709551615").unwrap(), u64::MAX);

        assert_eq!(parse_bytes("0b").unwrap(), 0);
        assert_eq!(parse_bytes("1B").unwrap(), 1);
        assert_eq!(parse_bytes("1024b").unwrap(), 1024);
        assert_eq!(parse_bytes("4096 B").unwrap(), 4096);
        assert_eq!(parse_bytes("18446744073709551615b").unwrap(), u64::MAX);
    }

    #[test]
    fn test_parse_bytes_fractional_values() {
        assert_eq!(parse_bytes("0.5kib").unwrap(), 512);
        assert_eq!(parse_bytes("1.5 KiB").unwrap(), 1536);
        assert_eq!(parse_bytes("0.5mb").unwrap(), 500_000);
        assert_eq!(parse_bytes("1.5 MB").unwrap(), 1_500_000);
        assert_eq!(
            parse_bytes("1.5g").unwrap(),
            (1.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(
            parse_bytes("2.5 GiB").unwrap(),
            (2.5 * 1024.0 * 1024.0 * 1024.0) as u64
        );
        assert_eq!(parse_bytes("0.25tb").unwrap(), 250_000_000_000);
        assert_eq!(parse_bytes("0.5 TiB").unwrap(), 512 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes(".5m").unwrap(), 512 * 1024);
        assert_eq!(parse_bytes("0.0 MB").unwrap(), 0);
    }

    #[test]
    fn test_parse_bytes_whitespace_handling() {
        assert_eq!(parse_bytes("  1024  ").unwrap(), 1024);
        assert_eq!(parse_bytes("  2  GiB  ").unwrap(), 2 * 1024 * 1024 * 1024);
        assert_eq!(parse_bytes("\t512 MB\n").unwrap(), 512_000_000);
        assert_eq!(parse_bytes(" 100   k ").unwrap(), 100 * 1024);
        assert_eq!(parse_bytes("   0   B ").unwrap(), 0);
    }

    #[test]
    fn test_parse_bytes_overflow() {
        // Exceeding u64::MAX as raw integer
        assert_eq!(
            parse_bytes("18446744073709551616"),
            Err(ParseBytesError::Overflow)
        );
        assert_eq!(
            parse_bytes("99999999999999999999999999999999"),
            Err(ParseBytesError::Overflow)
        );

        // Overflow during multiplication with units
        assert_eq!(
            parse_bytes("18446744073709551615k"),
            Err(ParseBytesError::Overflow)
        );
        assert_eq!(
            parse_bytes("20000000000000000000gib"),
            Err(ParseBytesError::Overflow)
        );
        assert_eq!(parse_bytes("20000000tb"), Err(ParseBytesError::Overflow));
        assert_eq!(
            parse_bytes("99999999999999999999999999999999.0 MB"),
            Err(ParseBytesError::Overflow)
        );
    }

    #[test]
    fn test_parse_bytes_errors() {
        assert_eq!(parse_bytes(""), Err(ParseBytesError::Empty));
        assert_eq!(parse_bytes("   "), Err(ParseBytesError::Empty));
        assert_eq!(
            parse_bytes("banana"),
            Err(ParseBytesError::UnknownUnit("banana".to_string()))
        );
        assert_eq!(
            parse_bytes("100xyz"),
            Err(ParseBytesError::UnknownUnit("100xyz".to_string()))
        );
        assert_eq!(
            parse_bytes("-100m"),
            Err(ParseBytesError::InvalidNumber("-100".to_string()))
        );
        assert_eq!(
            parse_bytes("-1.5gib"),
            Err(ParseBytesError::InvalidNumber("-1.5".to_string()))
        );
        assert_eq!(
            parse_bytes("kib"),
            Err(ParseBytesError::InvalidNumber("".to_string()))
        );
        assert_eq!(
            parse_bytes("MB"),
            Err(ParseBytesError::InvalidNumber("".to_string()))
        );
        assert_eq!(
            parse_bytes("b"),
            Err(ParseBytesError::InvalidNumber("".to_string()))
        );
        assert_eq!(
            parse_bytes("1.2.3mb"),
            Err(ParseBytesError::InvalidNumber("1.2.3".to_string()))
        );
        assert_eq!(
            parse_bytes("NaN mb"),
            Err(ParseBytesError::InvalidNumber("nan".to_string()))
        );
        assert_eq!(
            parse_bytes("inf.0 GiB"),
            Err(ParseBytesError::InvalidNumber("inf.0".to_string()))
        );
    }

    #[test]
    fn test_parse_cgroup_memory() {
        assert_eq!(parse_cgroup_memory("max").unwrap(), None);
        assert_eq!(parse_cgroup_memory("MAX").unwrap(), None);
        assert_eq!(parse_cgroup_memory("  max  ").unwrap(), None);
        assert_eq!(parse_cgroup_memory("-1").unwrap(), None);
        assert_eq!(parse_cgroup_memory("  -1  ").unwrap(), None);
        assert_eq!(parse_cgroup_memory("").unwrap(), None);
        assert_eq!(parse_cgroup_memory("   ").unwrap(), None);

        assert_eq!(
            parse_cgroup_memory("2g").unwrap(),
            Some(2 * 1024 * 1024 * 1024)
        );
        assert_eq!(
            parse_cgroup_memory("512M").unwrap(),
            Some(512 * 1024 * 1024)
        );
        assert_eq!(parse_cgroup_memory("0").unwrap(), Some(0));
        assert_eq!(parse_cgroup_memory("1024").unwrap(), Some(1024));

        assert_eq!(
            parse_cgroup_memory("invalid"),
            Err(ParseBytesError::UnknownUnit("invalid".to_string()))
        );
        assert_eq!(
            parse_cgroup_memory("-500M"),
            Err(ParseBytesError::InvalidNumber("-500".to_string()))
        );
    }

    #[test]
    fn test_format_bytes_iec_binary() {
        assert_eq!(format_bytes(0, UnitStandard::IecBinary), "0 B");
        assert_eq!(format_bytes(500, UnitStandard::IecBinary), "500 B");
        assert_eq!(format_bytes(1023, UnitStandard::IecBinary), "1023 B");
        assert_eq!(format_bytes(1024, UnitStandard::IecBinary), "1.0 KiB");
        assert_eq!(format_bytes(1536, UnitStandard::IecBinary), "1.5 KiB");
        assert_eq!(format_bytes(1024 * 1024, UnitStandard::IecBinary), "1.0 MiB");
        assert_eq!(
            format_bytes(1024 * 1024 * 5, UnitStandard::IecBinary),
            "5.0 MiB"
        );
        assert_eq!(
            format_bytes(1024 * 1024 * 1024, UnitStandard::IecBinary),
            "1.0 GiB"
        );
        assert_eq!(
            format_bytes(1024 * 1024 * 1024 * 3, UnitStandard::IecBinary),
            "3.0 GiB"
        );
        assert_eq!(
            format_bytes(1024 * 1024 * 1024 * 1024, UnitStandard::IecBinary),
            "1.0 TiB"
        );
    }

    #[test]
    fn test_format_bytes_si_decimal() {
        assert_eq!(format_bytes(0, UnitStandard::SiDecimal), "0 B");
        assert_eq!(format_bytes(500, UnitStandard::SiDecimal), "500 B");
        assert_eq!(format_bytes(999, UnitStandard::SiDecimal), "999 B");
        assert_eq!(format_bytes(1000, UnitStandard::SiDecimal), "1.0 KB");
        assert_eq!(format_bytes(1500, UnitStandard::SiDecimal), "1.5 KB");
        assert_eq!(format_bytes(1_000_000, UnitStandard::SiDecimal), "1.0 MB");
        assert_eq!(format_bytes(5_000_000, UnitStandard::SiDecimal), "5.0 MB");
        assert_eq!(
            format_bytes(1_000_000_000, UnitStandard::SiDecimal),
            "1.0 GB"
        );
        assert_eq!(
            format_bytes(3_000_000_000, UnitStandard::SiDecimal),
            "3.0 GB"
        );
        assert_eq!(
            format_bytes(1_000_000_000_000, UnitStandard::SiDecimal),
            "1.0 TB"
        );
    }
}
