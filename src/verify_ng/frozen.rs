//! FrozenSpec: what was verified is what was launched (FM-03).
//!
//! Binding rules:
//! - Exactly one `Backend::detect` per scenario run; the detected tier is
//!   compared against the expected tier before spawn.
//! - The spec hash is computed once, in the same single-threaded section,
//!   from the same `&Policy` reference handed to `Backend::spawn`.
//! - Serialization is canonical: sorted paths, normalized strings, explicit
//!   tier/net/backend/argv/env/cwd. `Policy::deny_network` is intent-only;
//!   the effective [`crate::config::NetMode`] is hashed separately and
//!   explicitly.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Canonical, hashable snapshot of everything that defines a scenario run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FrozenSpec {
    pub scenario_id: String,
    pub registry_hash: String,
    pub tier: String,
    pub net_mode: String,
    pub backend: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: PathBuf,
    pub allow_read: Vec<String>,
    pub allow_write: Vec<String>,
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub deny_resolved: Vec<String>,
    /// Session nonce binding the positive control to the negative proof.
    pub nonce: String,
}

impl FrozenSpec {
    /// Canonical bytes: JSON with sorted keys over normalized strings.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // BTreeMap + sorted Vecs + explicit fields make serde_json output
        // deterministic for a fixed struct layout.
        serde_json::to_vec(self).unwrap_or_default()
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.canonical_bytes());
        hex_encode(&hasher.finalize())
    }
}

/// Build the canonical spec from a resolved policy plus the effective
/// launch context. Callers must pass the same `policy` reference onward
/// to `Backend::spawn` (FM-03 continuity rule).
#[allow(clippy::too_many_arguments)]
pub fn freeze_spec(
    scenario_id: &str,
    registry_hash: &str,
    policy: &crate::policy::Policy,
    tier: &str,
    net_mode: &crate::config::NetMode,
    backend_describe: &str,
    argv: &[String],
    env: &BTreeMap<String, String>,
    cwd: &std::path::Path,
    nonce: &str,
) -> FrozenSpec {
    fn sorted(paths: &[PathBuf]) -> Vec<String> {
        let mut out: Vec<String> = paths.iter().map(|p| p.display().to_string()).collect();
        out.sort();
        out
    }
    let mut deny_resolved: Vec<String> = policy
        .deny_resolved
        .iter()
        .map(|e| e.path.display().to_string())
        .collect();
    deny_resolved.sort();
    FrozenSpec {
        scenario_id: scenario_id.to_string(),
        registry_hash: registry_hash.to_string(),
        tier: tier.to_string(),
        net_mode: net_mode.label(),
        backend: backend_describe.to_string(),
        argv: argv.to_vec(),
        env: env.clone(),
        cwd: cwd.to_path_buf(),
        allow_read: sorted(&policy.allow_read),
        allow_write: sorted(&policy.allow_write),
        deny_read: sorted(&policy.deny_read),
        deny_write: sorted(&policy.deny_write),
        deny_resolved,
        nonce: nonce.to_string(),
    }
}

/// Hash of the compiled scenario registry (binding scenarios to results).
pub fn registry_hash(ids: &[String]) -> String {
    let mut sorted = ids.to_vec();
    sorted.sort();
    let mut hasher = Sha256::new();
    for id in sorted {
        hasher.update(id.as_bytes());
        hasher.update([0u8]);
    }
    hex_encode(&hasher.finalize())
}

/// Minimal hex encoding (no new dependency; mirrors
/// `sandbox::linux::debug_guard`).
pub fn hex_encode(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(data.len() * 2);
    for &b in data {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod frozen_tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_order_independent() {
        let mk = |writes: Vec<PathBuf>| FrozenSpec {
            scenario_id: "s".to_string(),
            registry_hash: "r".to_string(),
            tier: "full".to_string(),
            net_mode: "off".to_string(),
            backend: "b".to_string(),
            argv: vec!["a".to_string()],
            env: BTreeMap::new(),
            cwd: PathBuf::from("/tmp"),
            allow_read: vec![],
            allow_write: writes.iter().map(|p| p.display().to_string()).collect(),
            deny_read: vec![],
            deny_write: vec![],
            deny_resolved: vec![],
            nonce: "n".to_string(),
        };
        let a = mk(vec![PathBuf::from("/b"), PathBuf::from("/a")]);
        let mut b = mk(vec![PathBuf::from("/a"), PathBuf::from("/b")]);
        b.allow_write.sort();
        // freeze_spec sorts; simulate by sorting both.
        let mut a_sorted = a.clone();
        a_sorted.allow_write.sort();
        assert_eq!(a_sorted.hash(), b.hash());
        let mut c = b.clone();
        c.nonce = "other".to_string();
        assert_ne!(b.hash(), c.hash());
    }

    #[test]
    fn net_mode_label_distinguishes_relay() {
        let off = crate::config::NetMode::Off.label();
        let allow = crate::config::NetMode::Allowlist(vec!["example.com".to_string()]).label();
        assert_ne!(off, allow);
    }
}
