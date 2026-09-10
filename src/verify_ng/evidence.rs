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
//! [`attest_control`] with the exact expected response the host read from
//! its own channel end — there is no constructor that wraps an arbitrary
//! child-supplied value into a verified fact.
//!
//! Non-self-authorization invariant (Stage 2 correction): the host NEVER
//! issues a value whose mere echo satisfies the control. The expected
//! response is [`derive_expected_response`] of a host-fresh challenge the
//! child never receives except by actively reading the host downlink, plus
//! a rotation transform the child must apply. Replaying or echoing any
//! verifier-issued capability (env values, the challenge itself, stale
//! responses) fails verification: PASS requires performing the
//! challenge-response behavior, not copying bytes.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceTier {
    HostFact,
    Constrained,
    SelfReport,
}

/// Host-owned positive-control channel label. Only facts stamped over this
/// channel (by [`Evidence::host_control_fact`], which requires a
/// [`VerifiedControl`]) can satisfy the oracle's identity gate.
pub const HOST_CONTROL_CHANNEL: &str = "host-challenge-v1";
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

/// Derive the expected challenge response from the host-fresh `challenge`
/// plus the session nonce. Pure function (no I/O).
///
/// Response = rotation of (`challenge` + `session_nonce`): the last 8
/// characters move to the front (short inputs pass through unchanged).
/// The rotation is deliberately trivial to verify and deliberately NOT
/// computable from env-issued material alone: `challenge` is fresh
/// per execution and reaches the child ONLY through the host downlink,
/// never through env. Echoing the challenge, the nonce, or any stale
/// response therefore differs from the expected value.
///
/// ASCII-only contract: challenge and nonce are hex; byte rotation is safe.
pub fn derive_expected_response(challenge: &str, session_nonce: &str) -> String {
    let combined = format!("{challenge}{session_nonce}");
    let bytes = combined.as_bytes();
    if bytes.len() <= 8 {
        return combined;
    }
    let (head, tail) = combined.split_at(bytes.len() - 8);
    format!("{tail}{head}")
}

/// Host-side verification (pure, no I/O): mint the [`VerifiedControl`]
/// capability only when the bytes the host read from its own uplink end
/// exactly equal the expected challenge response AND the identity is
/// well-formed.
///
/// Critical: `expected` MUST be host-derived from a never-issued challenge
/// (see [`derive_expected_response`]). It must never be a value the child
/// was given, otherwise verification degrades to self-authorization.
/// Anything else — echoed challenge, copied env, forged file content,
/// stdout markers, duplicated/stale responses, replayed bytes from another
/// session/scenario/registry — yields `None`, so no verified fact can ever
/// be stamped from it.
pub fn attest_control(
    identity: &ExecutionIdentity,
    expected: &str,
    received: &[u8],
) -> Option<VerifiedControl> {
    if !identity.is_well_formed() {
        return None;
    }
    if expected.is_empty() {
        return None;
    }
    if received.len() != expected.len() {
        return None;
    }
    if received != expected.as_bytes() {
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

    /// Test stand-in for a host-fresh challenge (production challenges come
    /// from the host RNG and never appear in env).
    const TEST_CHALLENGE: &str = "0123456789abcdef0123456789abcdef";

    fn test_expected() -> (ExecutionIdentity, String) {
        let id = test_identity();
        let expected = derive_expected_response(TEST_CHALLENGE, &id.session_nonce);
        (id, expected)
    }

    #[test]
    fn response_rotates_challenge_plus_nonce() {
        // "0123..def" (32) + "nonce-a" (7) = 39 chars; last 8 to front.
        let r = derive_expected_response(TEST_CHALLENGE, "nonce-a");
        let s = format!("{TEST_CHALLENGE}nonce-a");
        assert_eq!(r.len(), s.len());
        assert_eq!(r, format!("{}{}", &s[s.len() - 8..], &s[..s.len() - 8]));
        // Rotation is stable and sensitive to both inputs.
        assert_eq!(derive_expected_response(TEST_CHALLENGE, "nonce-a"), r);
        assert_ne!(
            derive_expected_response("fedcba9876543210fedcba9876543210", "nonce-a"),
            r
        );
        assert_ne!(derive_expected_response(TEST_CHALLENGE, "nonce-b"), r);
    }

    #[test]
    fn echo_is_never_the_response() {
        // Literal echo of every verifier-visible value differs: echoing is
        // not performing the behavior. This is the self-authorization kill.
        let r = derive_expected_response(TEST_CHALLENGE, "nonce-a");
        assert_ne!(TEST_CHALLENGE, r, "challenge echo is not the response");
        assert_ne!("nonce-a", r, "nonce echo is not the response");
        assert_ne!(
            format!("{TEST_CHALLENGE}nonce-a"),
            r,
            "unrotated concatenation is not the response"
        );
    }

    #[test]
    fn attest_mints_only_on_exact_response() {
        let (id, expected) = test_expected();
        assert!(attest_control(&id, &expected, expected.as_bytes()).is_some());
        // Echoed challenge / nonce / concatenation never mint.
        assert!(attest_control(&id, &expected, TEST_CHALLENGE.as_bytes()).is_none());
        assert!(attest_control(&id, &expected, b"nonce-a").is_none());
        let plain = format!("{TEST_CHALLENGE}nonce-a");
        assert!(attest_control(&id, &expected, plain.as_bytes()).is_none());
        // Forged / truncated / extended / duplicated / empty never mint.
        assert!(attest_control(&id, &expected, b"forged").is_none());
        assert!(attest_control(&id, &expected, b"").is_none());
        let mut short = expected.as_bytes().to_vec();
        short.pop();
        assert!(attest_control(&id, &expected, &short).is_none());
        let mut doubled = expected.as_bytes().to_vec();
        doubled.extend_from_slice(expected.as_bytes());
        assert!(attest_control(&id, &expected, &doubled).is_none());
        // Malformed identity never mints, even with a matching response.
        let bad = ExecutionIdentity::new("", "n", "r", "f");
        assert!(!bad.is_well_formed());
        assert!(attest_control(&bad, &expected, expected.as_bytes()).is_none());
        assert!(attest_control(&id, "", expected.as_bytes()).is_none());
    }

    #[test]
    fn verified_control_fact_matches_only_own_identity() {
        let (id, expected) = test_expected();
        let verified = attest_control(&id, &expected, expected.as_bytes()).expect("mint");
        let mut e = Evidence::default();
        // Legacy facts alone never satisfy the identity gate.
        e.host_fact("wait-status", "exit=0".to_string());
        assert!(!e.has_verified_control(&id));
        e.host_control_fact(&verified);
        assert!(e.has_verified_control(&id));
        // The stamped value carries no challenge/response material.
        let fact = e
            .facts
            .iter()
            .find(|f| f.name == HOST_CONTROL_FACT)
            .expect("control fact");
        assert!(!fact.value.contains(&expected));
        assert!(!fact.value.contains(TEST_CHALLENGE));
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
