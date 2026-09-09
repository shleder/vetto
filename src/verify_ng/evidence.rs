//! Three-tier evidence model (FM-01) + Stage 2 identity-bound host control.
//!
//! - [`EvidenceTier::HostFact`]: observed by the trusted host after wait
//!   (post-mortem stat, wait status, sweep result, canary comparison).
//!   The only tier that can support a PASS.
//! - [`EvidenceTier::Constrained`]: narrow in-sandbox signal through a
//!   nonce-bound channel (errno class + nonce). Supports FAIL, never PASS
//!   alone.
//! - [`EvidenceTier::SelfReport`]: attacker-controlled stdout markers.
//!   Hints for triage only; never decide a verdict.
//!
//! Stage 2 adds identity binding for the positive control: a `HOST_FACT`
//! named [`HOST_CONTROL_FACT`] counts toward PASS only when it carries a
//! [`HostProvenance`] that exactly matches the current [`ExecutionIdentity`]
//! (scenario + session nonce + registry hash + frozen-spec hash) over the
//! host-created channel [`HOST_CONTROL_CHANNEL`]. The only way to mint the
//! [`VerifiedControl`] capability that stamps such a fact is
//! [`attest_control`] with the exact identity-bound token the host read from
//! its own channel end — there is no constructor that wraps an arbitrary
//! child-supplied value into a verified fact.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTier {
    HostFact,
    Constrained,
    SelfReport,
}

/// Host-owned positive-control channel label. Only facts stamped over this
/// channel (by [`Evidence::host_control_fact`], which requires a
/// [`VerifiedControl`]) can satisfy the oracle's identity gate.
pub const HOST_CONTROL_CHANNEL: &str = "host-fifo-v1";
/// Fact name for the verified host-owned positive control.
pub const HOST_CONTROL_FACT: &str = "control";

/// Immutable execution identity, fixed before spawn and never mutated after.
/// The host-owned control token binds all four fields; the oracle rejects
/// control evidence stamped for any other identity (cross-session replay,
/// wrong scenario, wrong registry/frozen spec).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionIdentity {
    pub scenario_id: String,
    pub session_nonce: String,
    pub registry_hash: String,
    pub frozen_hash: String,
}

impl ExecutionIdentity {
    pub fn new(
        scenario_id: &str,
        session_nonce: &str,
        registry_hash: &str,
        frozen_hash: &str,
    ) -> Self {
        ExecutionIdentity {
            scenario_id: scenario_id.to_string(),
            session_nonce: session_nonce.to_string(),
            registry_hash: registry_hash.to_string(),
            frozen_hash: frozen_hash.to_string(),
        }
    }

    /// Malformed identities (any empty field) can never support PASS.
    pub fn is_well_formed(&self) -> bool {
        !self.scenario_id.is_empty()
            && !self.session_nonce.is_empty()
            && !self.registry_hash.is_empty()
            && !self.frozen_hash.is_empty()
    }
}

/// Provenance stamped on verified host-control facts only. Legacy host facts
/// (wait-status, kill, sentinel) carry `None` and keep supporting FAIL paths;
/// PASS additionally requires a control fact whose provenance matches the
/// current execution identity exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProvenance {
    pub scenario_id: String,
    pub session_nonce: String,
    pub registry_hash: String,
    pub frozen_hash: String,
    pub channel: String,
}

impl HostProvenance {
    pub fn matches(&self, identity: &ExecutionIdentity) -> bool {
        self.channel == HOST_CONTROL_CHANNEL
            && self.scenario_id == identity.scenario_id
            && self.session_nonce == identity.session_nonce
            && self.registry_hash == identity.registry_hash
            && self.frozen_hash == identity.frozen_hash
    }
}

/// Capability minted ONLY by [`attest_control`] after the host verified the
/// exact identity-bound token arriving on its own channel end. There is
/// deliberately no `new`/public-field constructor: callers cannot wrap an
/// arbitrary child-supplied value into this type.
#[derive(Debug, Clone)]
pub struct VerifiedControl {
    identity: ExecutionIdentity,
}

impl VerifiedControl {
    pub fn identity(&self) -> &ExecutionIdentity {
        &self.identity
    }
}

/// Derive the per-execution control token binding the channel secret to the
/// full execution identity. Pure function (no I/O): the host computes the
/// expected value before spawn, hands it to the child as a capability, and
/// re-derives nothing afterwards — verification is exact comparison in
/// [`attest_control`].
pub fn derive_control_token(channel_secret: &str, identity: &ExecutionIdentity) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"vng-control-v1;");
    hasher.update(b"secret=");
    hasher.update(channel_secret.as_bytes());
    hasher.update(b";scenario=");
    hasher.update(identity.scenario_id.as_bytes());
    hasher.update(b";nonce=");
    hasher.update(identity.session_nonce.as_bytes());
    hasher.update(b";registry=");
    hasher.update(identity.registry_hash.as_bytes());
    hasher.update(b";frozen=");
    hasher.update(identity.frozen_hash.as_bytes());
    super::frozen::hex_encode(&hasher.finalize())
}

/// Host-side verification (pure, no I/O): mint the [`VerifiedControl`]
/// capability only when the bytes the host read from its own channel end
/// exactly equal the expected identity-bound token AND the identity is
/// well-formed. Anything else — wrong token, forged file content, stdout
/// markers, replayed bytes from another session/scenario/registry — yields
/// `None`, so no verified fact can ever be stamped from it.
pub fn attest_control(
    identity: &ExecutionIdentity,
    expected_token: &str,
    received: &[u8],
) -> Option<VerifiedControl> {
    if !identity.is_well_formed() {
        return None;
    }
    if expected_token.is_empty() {
        return None;
    }
    if received.len() != expected_token.len() {
        return None;
    }
    if received != expected_token.as_bytes() {
        return None;
    }
    Some(VerifiedControl {
        identity: identity.clone(),
    })
}

/// One collected fact with its tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub tier: EvidenceTier,
    pub name: String,
    pub value: String,
    /// Set only on verified host-control facts; `None` everywhere else.
    /// `#[serde(default)]` keeps previously serialized evidence readable.
    #[serde(default)]
    pub provenance: Option<HostProvenance>,
}

/// Collected evidence for one scenario run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub facts: Vec<Fact>,
}

impl Evidence {
    pub fn push(&mut self, tier: EvidenceTier, name: &str, value: String) {
        self.facts.push(Fact {
            tier,
            name: name.to_string(),
            value,
            provenance: None,
        });
    }

    pub fn host_fact(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::HostFact, name, value);
    }

    pub fn constrained(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::Constrained, name, value);
    }

    pub fn self_report(&mut self, name: &str, value: String) {
        self.push(EvidenceTier::SelfReport, name, value);
    }

    /// Stamp the verified host-owned positive control. Requires the
    /// [`VerifiedControl`] capability, which only [`attest_control`] can
    /// mint after host-side token verification. The stored value is a fixed
    /// marker — never the token or any child-supplied bytes — so evidence
    /// logs cannot leak the per-execution secret.
    pub fn host_control_fact(&mut self, verified: &VerifiedControl) {
        let id = verified.identity();
        self.facts.push(Fact {
            tier: EvidenceTier::HostFact,
            name: HOST_CONTROL_FACT.to_string(),
            value: "host-observed:verified".to_string(),
            provenance: Some(HostProvenance {
                scenario_id: id.scenario_id.clone(),
                session_nonce: id.session_nonce.clone(),
                registry_hash: id.registry_hash.clone(),
                frozen_hash: id.frozen_hash.clone(),
                channel: HOST_CONTROL_CHANNEL.to_string(),
            }),
        });
    }

    /// True only when a `HOST_FACT` control fact carries provenance exactly
    /// matching `identity`. Cross-session replays, wrong-scenario and
    /// wrong-registry evidence all fail this check.
    pub fn has_verified_control(&self, identity: &ExecutionIdentity) -> bool {
        self.facts.iter().any(|f| {
            f.tier == EvidenceTier::HostFact
                && f.name == HOST_CONTROL_FACT
                && f.provenance.as_ref().is_some_and(|p| p.matches(identity))
        })
    }

    /// PASS requires at least one host fact (FM-01 structural rule).
    pub fn has_host_fact(&self) -> bool {
        self.facts.iter().any(|f| f.tier == EvidenceTier::HostFact)
    }

    pub fn host_fact_value(&self, name: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.tier == EvidenceTier::HostFact && f.name == name)
            .map(|f| f.value.as_str())
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn pass_requires_host_fact() {
        let mut e = Evidence::default();
        e.self_report("marker", "PASS".to_string());
        e.constrained("errno", "EACCES".to_string());
        assert!(!e.has_host_fact());
        e.host_fact("postmortem", "absent".to_string());
        assert!(e.has_host_fact());
    }

    fn test_identity() -> ExecutionIdentity {
        ExecutionIdentity::new("SCEN-A", "nonce-a", "reg-a", "frozen-a")
    }

    #[test]
    fn control_token_binds_full_identity() {
        let id = test_identity();
        let base = derive_control_token("secret", &id);
        assert_eq!(base.len(), 64);
        // Every bound field flips the token; pure re-derivation is stable.
        assert_eq!(derive_control_token("secret", &id), base);
        assert_ne!(
            derive_control_token("other", &id),
            base,
            "channel secret binds"
        );
        let mut mutated = id.clone();
        mutated.scenario_id = "SCEN-B".to_string();
        assert_ne!(derive_control_token("secret", &mutated), base);
        let mut mutated = id.clone();
        mutated.session_nonce = "nonce-b".to_string();
        assert_ne!(derive_control_token("secret", &mutated), base);
        let mut mutated = id.clone();
        mutated.registry_hash = "reg-b".to_string();
        assert_ne!(derive_control_token("secret", &mutated), base);
        let mut mutated = id.clone();
        mutated.frozen_hash = "frozen-b".to_string();
        assert_ne!(derive_control_token("secret", &mutated), base);
    }

    #[test]
    fn attest_mints_only_on_exact_match() {
        let id = test_identity();
        let token = derive_control_token("secret", &id);
        assert!(attest_control(&id, &token, token.as_bytes()).is_some());
        // Forged / truncated / extended / empty payloads never mint.
        assert!(attest_control(&id, &token, b"forged").is_none());
        assert!(attest_control(&id, &token, b"").is_none());
        let mut short = token.as_bytes().to_vec();
        short.pop();
        assert!(attest_control(&id, &token, &short).is_none());
        let mut long = token.as_bytes().to_vec();
        long.push(b'x');
        assert!(attest_control(&id, &token, &long).is_none());
        // Malformed identity never mints, even with a matching token.
        let bad = ExecutionIdentity::new("", "n", "r", "f");
        assert!(!bad.is_well_formed());
        assert!(attest_control(&bad, &token, token.as_bytes()).is_none());
        assert!(attest_control(&id, "", token.as_bytes()).is_none());
    }

    #[test]
    fn verified_control_fact_matches_only_own_identity() {
        let id = test_identity();
        let token = derive_control_token("secret", &id);
        let verified = attest_control(&id, &token, token.as_bytes()).expect("mint");
        let mut e = Evidence::default();
        // Legacy facts alone never satisfy the identity gate.
        e.host_fact("wait-status", "exit=0".to_string());
        assert!(!e.has_verified_control(&id));
        e.host_control_fact(&verified);
        assert!(e.has_verified_control(&id));
        // The stamped value carries no secret material.
        let fact = e
            .facts
            .iter()
            .find(|f| f.name == HOST_CONTROL_FACT)
            .expect("control fact");
        assert!(!fact.value.contains(&token));
        assert!(!fact.value.contains("secret"));
        // Any identity drift rejects: replay, wrong scenario, wrong registry.
        let mut other = id.clone();
        other.session_nonce = "nonce-b".to_string();
        assert!(!e.has_verified_control(&other));
        let mut other = id.clone();
        other.scenario_id = "SCEN-B".to_string();
        assert!(!e.has_verified_control(&other));
        let mut other = id.clone();
        other.registry_hash = "reg-b".to_string();
        assert!(!e.has_verified_control(&other));
        let mut other = id.clone();
        other.frozen_hash = "frozen-b".to_string();
        assert!(!e.has_verified_control(&other));
    }
}
