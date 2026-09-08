//! Engine: single-owner pipeline Engine -> Killer -> Collector -> Oracle.
//!
//! Ownership rules (FM-14):
//! - Only the engine touches `Backend` and `SandboxHandle`. The handle is
//!   moved through killer/collector stages and never cloned.
//! - Fork-safety (FM-09): every `Backend::spawn` call site must hold
//!   [`SPAWN_SERIAL`] from before `detect` until after fork-return, because
//!   the Linux/macOS backends fork and forking a multi-threaded process can
//!   deadlock. Parallelize preparation and judging, never the spawn.
//! - One `detect` per scenario run; the detected tier is compared to the
//!   expected tier before spawn (FM-03 binding).
//! - Diagnostic env (`VETTO_SEATBELT_MODE`, `VETTO_NO_MAC_LIMITS`,
//!   `VETTO_FORCE_TIER` outside the tier-differential job) invalidates the
//!   run (FM-08). Detection happens before spawn; the poisoned run never
//!   reports PASS.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use super::frozen::FrozenSpec;
use super::frozen::hex_encode;
use super::model::{Category, ClaimStrength, ScenarioResult, Verdict};
use super::registry::{Scenario, Target};

/// Global spawn serializer (FM-09). Hold from `detect` to fork-return.
pub static SPAWN_SERIAL: OnceLock<Mutex<()>> = OnceLock::new();

pub fn spawn_serial() -> &'static Mutex<()> {
    SPAWN_SERIAL.get_or_init(|| Mutex::new(()))
}

/// Diagnostic env switches that weaken enforcement. Presence (except an
/// explicit opt-in for the tier-differential job) poisons the run.
pub const POISON_ENV: &[&str] =
    &["VETTO_SEATBELT_MODE", "VETTO_NO_MAC_LIMITS", "VETTO_CHILD_TRACE"];

/// Detect poisoned diagnostic env. `allow_force_tier` is true only in the
/// tier-differential CI job, where the actual tier is cross-checked.
pub fn detect_env_poison(allow_force_tier: bool) -> Vec<String> {
    let mut poisoned = Vec::new();
    for key in POISON_ENV {
        if std::env::var_os(key).is_some() {
            poisoned.push(key.to_string());
        }
    }
    if !allow_force_tier && std::env::var_os("VETTO_FORCE_TIER").is_some() {
        poisoned.push("VETTO_FORCE_TIER".to_string());
    }
    poisoned
}

/// Current platform target for strength lookup.
pub fn current_target(tier_label: Option<&str>) -> Target {
    #[cfg(target_os = "linux")]
    {
        match tier_label {
            Some("full") => Target::LinuxFull,
            Some("fs-only") => Target::LinuxFsOnly,
            Some("seccomp") => Target::LinuxSeccomp,
            _ => Target::LinuxSeccomp,
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = tier_label;
        Target::Macos
    }
    #[cfg(target_os = "windows")]
    {
        let _ = tier_label;
        Target::Windows
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = tier_label;
        Target::LinuxSeccomp
    }
}

/// Session nonce: 128 bits from `/dev/urandom` (fallback: time+pid mix;
/// uniqueness only, not secrecy from the host's perspective).
pub fn new_nonce() -> String {
    let mut bytes = [0u8; 16];
    let read_ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut bytes).map(|_| ())
        })
        .is_ok();
    if !read_ok {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((t >> (8 * (i % 8))) ^ (std::process::id() as u128) ^ (i as u128 * 0x9E37)) as u8;
        }
    }
    hex_encode(bytes)
}

/// Evaluate the gate-relevant outcome for a poisoned run without spawning
/// (FM-08: environment interference -> FAIL on blockers, INCONCLUSIVE on aux).
pub fn poisoned_result(scenario: &Scenario, target: Target, poison: &[String]) -> ScenarioResult {
    let verdict = match scenario.category {
        Category::Aux => Verdict::Inconclusive,
        _ => Verdict::Fail,
    };
    ScenarioResult {
        id: scenario.id.clone(),
        category: scenario.category,
        strength: scenario.strength_for(target),
        verdict,
        detail: super::redact::redact_text(&format!(
            "diagnostic env interference, refusing PASS: {}",
            poison.join(",")
        )),
    }
}

/// Frozen-spec continuity check (FM-03): the spec handed to spawn must hash
/// identically when re-frozen from the same references. Any drift means the
/// policy object was mutated between freeze and spawn.
pub fn verify_spec_continuity(before: &FrozenSpec, after: &FrozenSpec) -> bool {
    before.hash() == after.hash()
}

/// Required env mapping for a scenario run: isolated HOME plus the session
/// nonce. The caller merges this over an allowlist-filtered base; `env_extra`
/// bypasses the allowlist by backend design (internal VETTO_* only), so the
/// engine passes exactly these keys and nothing else.
pub fn run_env(home: &std::path::Path, nonce: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        ("VETTO_VNG_NONCE".to_string(), nonce.to_string()),
        ("VETTO_VNG_HOME".to_string(), home.display().to_string()),
    ])
}

#[cfg(test)]
mod engine_tests {
    use super::*;

    #[test]
    fn poison_detects_seatbelt_mode() {
        // Only assert the pure shape: detection reads the live env, so we
        // test the constant list instead of mutating process-global env.
        assert!(POISON_ENV.contains(&"VETTO_SEATBELT_MODE"));
        assert!(POISON_ENV.contains(&"VETTO_NO_MAC_LIMITS"));
    }

    #[test]
    fn nonce_is_unique_and_hex() {
        let a = new_nonce();
        let b = new_nonce();
        assert_eq!(a.len(), 32);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn spec_continuity_detects_drift() {
        use crate::verify_ng::frozen::FrozenSpec;
        let mk = |nonce: &str| FrozenSpec {
            scenario_id: "s".to_string(),
            registry_hash: "r".to_string(),
            tier: "full".to_string(),
            net_mode: "off".to_string(),
            backend: "b".to_string(),
            argv: vec![],
            env: BTreeMap::new(),
            cwd: std::path::PathBuf::from("/tmp"),
            allow_read: vec![],
            allow_write: vec![],
            deny_read: vec![],
            deny_write: vec![],
            deny_resolved: vec![],
            nonce: nonce.to_string(),
        };
        assert!(verify_spec_continuity(&mk("n"), &mk("n")));
        assert!(!verify_spec_continuity(&mk("n"), &mk("m")));
    }
}
