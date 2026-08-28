//! CLI `--limits` spec parsing and strictest-wins merge into a loaded policy.
//!
//! Spec grammar: comma-separated `key=value` pairs.
//!
//! Keys:
//! - `cpu`    — CPU time seconds (`ResourceLimits::cpu_seconds`)
//! - `as`     — address space bytes (`ResourceLimits::address_space_bytes`)
//! - `procs`  — process count (`ResourceLimits::processes`)
//! - `nofile` — open file count (`ResourceLimits::open_files`)
//! - `fsize`  — maximum created file size in bytes (`ResourceLimits::file_size_bytes`)
//!
//! Byte values (`as`, `fsize`) accept a plain integer or an integer with a
//! case-insensitive size suffix: `k`/`m`/`g` are decimal (1000-based),
//! `kib`/`mib`/`gib` are binary (1024-based). `cpu`, `procs` and `nofile`
//! take plain integers only — no suffix.
//!
//! Constraints:
//! - Unknown keys and unparseable values are hard errors (fail-closed), never
//!   silently dropped: a typo must not weaken or disable a ceiling.
//! - The parsed ceilings merge strictest-wins with the policy layers: for
//!   every field the smaller value wins and `None` never loosens a `Some`.

use anyhow::{bail, Result};

use super::types::{Policy, ResourceLimits};

const VALID_KEYS: &str = "cpu, as, procs, nofile, fsize";

const BYTE_SUFFIX_DOC: &str =
    "byte values accept a plain integer or an integer with a case-insensitive \
     suffix k/m/g (1000-based) or kib/mib/gib (1024-based)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LimitKey {
    Cpu,
    AddressSpace,
    Processes,
    OpenFiles,
    FileSize,
}

impl LimitKey {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "cpu" => Some(Self::Cpu),
            "as" => Some(Self::AddressSpace),
            "procs" => Some(Self::Processes),
            "nofile" => Some(Self::OpenFiles),
            "fsize" => Some(Self::FileSize),
            _ => None,
        }
    }

    fn is_bytes(&self) -> bool {
        matches!(self, Self::AddressSpace | Self::FileSize)
    }

    /// Merge one parsed pair strictest-wins into the running set: the smaller
    /// value wins, so a later pair in the same spec cannot loosen an earlier
    /// one either.
    fn apply(self, limits: &mut ResourceLimits, value: u64) {
        match self {
            Self::Cpu => limits.cpu_seconds = strictest(limits.cpu_seconds, value),
            Self::AddressSpace => {
                limits.address_space_bytes = strictest(limits.address_space_bytes, value)
            }
            Self::Processes => limits.processes = strictest(limits.processes, value),
            Self::OpenFiles => limits.open_files = strictest(limits.open_files, value),
            Self::FileSize => limits.file_size_bytes = strictest(limits.file_size_bytes, value),
        }
    }
}

fn strictest(current: Option<u64>, value: u64) -> Option<u64> {
    Some(match current {
        Some(existing) => existing.min(value),
        None => value,
    })
}

/// Apply a `--limits` spec (e.g. `"cpu=300,as=4g"`) to an already-loaded
/// policy. Every parsed field merges strictest-wins into `policy.limits`.
pub fn apply_cli(policy: &mut Policy, spec: &str) -> Result<()> {
    let parsed = parse_spec(spec)?;
    policy.limits.merge_strictest(&parsed);
    Ok(())
}

/// Parse a full spec into standalone ceilings (all unparsed fields stay
/// `None`), ready for `ResourceLimits::merge_strictest`.
pub fn parse_spec(spec: &str) -> Result<ResourceLimits> {
    if spec.trim().is_empty() {
        bail!("--limits requires at least one key=value pair (valid keys: {VALID_KEYS})");
    }

    let mut limits = ResourceLimits::default();
    for (index, raw) in spec.split(',').enumerate() {
        let pair = raw.trim();
        if pair.is_empty() {
            bail!(
                "invalid --limits entry at position {} in '{spec}': empty pair \
                 (expected key=value, e.g. cpu=300,as=4g)",
                index + 1
            );
        }
        let (name, value) = pair.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "invalid --limits entry '{pair}' (expected key=value); valid keys: {VALID_KEYS}"
            )
        })?;
        let key_name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        let key = LimitKey::from_name(&key_name).ok_or_else(|| {
            anyhow::anyhow!(
                "unknown --limits key '{key_name}' in pair '{pair}'; valid keys: {VALID_KEYS}"
            )
        })?;
        let parsed = parse_value(&key, value, pair)?;
        key.apply(&mut limits, parsed);
    }
    Ok(limits)
}

fn parse_value(key: &LimitKey, value: &str, pair: &str) -> Result<u64> {
    if key.is_bytes() {
        parse_byte_value(value, pair)
    } else {
        value.parse::<u64>().map_err(|_| {
            anyhow::anyhow!(
                "invalid --limits value '{value}' in pair '{pair}': expected a plain \
                 integer (no suffix)"
            )
        })
    }
}

/// Parse a byte amount: a plain integer or `<integer><suffix>` with
/// case-insensitive suffix. Suffix math is checked for overflow so a
/// nonsensical value cannot wrap into a small (weaker) ceiling.
fn parse_byte_value(value: &str, pair: &str) -> Result<u64> {
    if let Ok(raw) = value.parse::<u64>() {
        return Ok(raw);
    }

    let lower = value.to_ascii_lowercase();
    // 3-char binary suffixes must be tested before the 1-char decimal ones,
    // otherwise "kib" would parse as "k" + garbage "ib".
    let (number, multiplier) = if let Some(number) = lower.strip_suffix("kib") {
        (number, 1024u64)
    } else if let Some(number) = lower.strip_suffix("mib") {
        (number, 1024u64 * 1024)
    } else if let Some(number) = lower.strip_suffix("gib") {
        (number, 1024u64 * 1024 * 1024)
    } else if let Some(number) = lower.strip_suffix('k') {
        (number, 1000u64)
    } else if let Some(number) = lower.strip_suffix('m') {
        (number, 1000u64 * 1000)
    } else if let Some(number) = lower.strip_suffix('g') {
        (number, 1000u64 * 1000 * 1000)
    } else {
        bail!("invalid --limits value '{value}' in pair '{pair}': {BYTE_SUFFIX_DOC}")
    };

    let base: u64 = number.trim().parse().map_err(|_| {
        anyhow::anyhow!("invalid --limits value '{value}' in pair '{pair}': {BYTE_SUFFIX_DOC}")
    })?;
    base.checked_mul(multiplier).ok_or_else(|| {
        anyhow::anyhow!("--limits value '{value}' in pair '{pair}' overflows u64 bytes")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_math_decimal_and_binary_case_insensitive() {
        let limits = parse_spec("as=2k").expect("2k");
        assert_eq!(limits.address_space_bytes, Some(2_000));
        let limits = parse_spec("as=3m").expect("3m");
        assert_eq!(limits.address_space_bytes, Some(3_000_000));
        let limits = parse_spec("as=1g").expect("1g");
        assert_eq!(limits.address_space_bytes, Some(1_000_000_000));
        let limits = parse_spec("as=4096").expect("raw");
        assert_eq!(limits.address_space_bytes, Some(4096));
        let limits = parse_spec("as=4kib").expect("4kib");
        assert_eq!(limits.address_space_bytes, Some(4 * 1024));
        let limits = parse_spec("as=8mib").expect("8mib");
        assert_eq!(limits.address_space_bytes, Some(8 * 1024 * 1024));
        let limits = parse_spec("as=2gib").expect("2gib");
        assert_eq!(limits.address_space_bytes, Some(2 * 1024 * 1024 * 1024));
        let limits = parse_spec("fsize=2M").expect("2M uppercase");
        assert_eq!(limits.file_size_bytes, Some(2_000_000));
        let limits = parse_spec("as=4GiB").expect("4GiB mixed case");
        assert_eq!(limits.address_space_bytes, Some(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn strictest_merge_smaller_wins_and_none_loses() {
        // Smaller wins: an existing policy ceiling tightens further.
        let mut policy = Policy::default();
        policy.limits.cpu_seconds = Some(7200);
        apply_cli(&mut policy, "cpu=3600").expect("apply cpu");
        assert_eq!(policy.limits.cpu_seconds, Some(3600));

        // The CLI spec can never loosen an existing tighter ceiling.
        let mut policy = Policy::default();
        policy.limits.cpu_seconds = Some(60);
        apply_cli(&mut policy, "cpu=3600").expect("apply cpu");
        assert_eq!(policy.limits.cpu_seconds, Some(60));

        // None loses: an unset field takes the CLI value.
        let mut policy = Policy::default();
        apply_cli(&mut policy, "nofile=512").expect("apply nofile");
        assert_eq!(policy.limits.open_files, Some(512));
        assert_eq!(policy.limits.cpu_seconds, None);

        // Within one spec, repeated keys are also strictest-wins.
        let limits = parse_spec("cpu=2,cpu=1").expect("repeat");
        assert_eq!(limits.cpu_seconds, Some(1));
        let limits = parse_spec("cpu=1,cpu=2").expect("repeat");
        assert_eq!(limits.cpu_seconds, Some(1));
    }

    #[test]
    fn unknown_key_error_names_pair_and_valid_keys() {
        let err = parse_spec("bandwidth=10").expect_err("unknown key");
        let text = err.to_string();
        assert!(text.contains("unknown"), "{text}");
        assert!(text.contains("bandwidth"), "{text}");
        assert!(text.contains("nofile"), "{text}");
    }

    #[test]
    fn unparseable_value_error_names_pair_and_suffix_doc() {
        let err = parse_spec("as=banana").expect_err("bad bytes");
        let text = err.to_string();
        assert!(text.contains("as=banana"), "{text}");
        assert!(text.contains("kib"), "{text}");

        let err = parse_spec("cpu=300s").expect_err("cpu takes no suffix");
        assert!(err.to_string().contains("cpu=300s"), "{}", err);

        let err = parse_spec("procs=1k").expect_err("counts take no suffix");
        assert!(err.to_string().contains("procs=1k"), "{}", err);
    }

    #[test]
    fn empty_pair_and_empty_spec_are_errors() {
        let err = parse_spec("cpu=1,,as=4g").expect_err("empty pair");
        assert!(err.to_string().contains("empty pair"), "{}", err);

        let err = parse_spec("cpu").expect_err("missing =");
        assert!(err.to_string().contains("cpu"), "{}", err);

        assert!(parse_spec("").is_err(), "empty spec must fail");
        assert!(parse_spec("   ").is_err(), "blank spec must fail");
    }
}
