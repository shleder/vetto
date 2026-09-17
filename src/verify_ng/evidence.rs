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

/// Trust level hierarchy alias per verify-ng contract:
/// HOST_FACT > CONSTRAINED > SELF_REPORT
pub type TrustLevel = EvidenceTier;

impl PartialOrd for EvidenceTier {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvidenceTier {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.priority().cmp(&other.priority())
    }
}

impl EvidenceTier {
    #[inline]
    pub fn priority(&self) -> u8 {
        match self {
            EvidenceTier::HostFact => 3,
            EvidenceTier::Constrained => 2,
            EvidenceTier::SelfReport => 1,
        }
    }

    #[inline]
    pub fn can_support_pass(&self) -> bool {
        matches!(self, EvidenceTier::HostFact)
    }

    #[inline]
    pub fn is_proof(&self) -> bool {
        matches!(self, EvidenceTier::HostFact | EvidenceTier::Constrained)
    }
}

/// Source classification for evidence items.
///
/// Master Task Section 12:
/// НЕ доказательство: agent self-report; stdout; произвольный JSON от sandboxed
/// process; snapshot без provenance; observation без связи с execution identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EvidenceSource {
    /// Trusted host observation after wait status, stat, or canary check.
    HostObservation,
    /// Narrow nonce-bound constrained channel from inside sandbox.
    ConstrainedChannel,
    /// Agent self-report marker. Never proof.
    AgentSelfReport,
    /// Process stdout. Never proof.
    ProcessStdout,
    /// Process stderr. Never proof.
    ProcessStderr,
    /// Arbitrary JSON from sandboxed process. Never proof.
    SandboxedArbitraryJson,
    /// Filesystem or memory snapshot lacking provenance. Never proof.
    UnprovenancedSnapshot,
    /// Observation lacking execution identity binding. Never proof.
    UnboundObservation,
}

impl EvidenceSource {
    pub fn tier(&self) -> EvidenceTier {
        match self {
            EvidenceSource::HostObservation => EvidenceTier::HostFact,
            EvidenceSource::ConstrainedChannel => EvidenceTier::Constrained,
            EvidenceSource::AgentSelfReport
            | EvidenceSource::ProcessStdout
            | EvidenceSource::ProcessStderr
            | EvidenceSource::SandboxedArbitraryJson
            | EvidenceSource::UnprovenancedSnapshot
            | EvidenceSource::UnboundObservation => EvidenceTier::SelfReport,
        }
    }

    /// Master Task Section 12: can this source ever count as proof?
    pub fn counts_as_proof(&self) -> bool {
        match self {
            EvidenceSource::HostObservation | EvidenceSource::ConstrainedChannel => true,
            EvidenceSource::AgentSelfReport
            | EvidenceSource::ProcessStdout
            | EvidenceSource::ProcessStderr
            | EvidenceSource::SandboxedArbitraryJson
            | EvidenceSource::UnprovenancedSnapshot
            | EvidenceSource::UnboundObservation => false,
        }
    }

    pub fn can_support_pass(&self) -> bool {
        matches!(self, EvidenceSource::HostObservation)
    }
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
    #[serde(default)]
    pub contract_digest: Option<String>,
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
            contract_digest: None,
        }
    }

    pub fn with_contract_digest(mut self, contract_digest: &str) -> Self {
        self.contract_digest = Some(contract_digest.to_string());
        self
    }

    pub fn execution_id(&self) -> String {
        format!(
            "{}:{}:{}",
            self.scenario_id, self.session_nonce, self.frozen_hash
        )
    }

    /// Malformed identities (any empty field) can never support PASS.
    pub fn is_well_formed(&self) -> bool {
        !self.scenario_id.is_empty()
            && !self.session_nonce.is_empty()
            && !self.registry_hash.is_empty()
            && !self.frozen_hash.is_empty()
            && self
                .contract_digest
                .as_ref()
                .map_or(true, |d| !d.is_empty())
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
    #[serde(default)]
    pub contract_digest: Option<String>,
}

impl HostProvenance {
    pub fn matches(&self, identity: &ExecutionIdentity) -> bool {
        self.channel == HOST_CONTROL_CHANNEL
            && self.scenario_id == identity.scenario_id
            && self.session_nonce == identity.session_nonce
            && self.registry_hash == identity.registry_hash
            && self.frozen_hash == identity.frozen_hash
            && match (&self.contract_digest, &identity.contract_digest) {
                (Some(p_dig), Some(id_dig)) => p_dig == id_dig,
                (Some(_), None) => false,
                (None, Some(_)) => false,
                (None, None) => true,
            }
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
    /// Source classification of this fact.
    #[serde(default)]
    pub source: Option<EvidenceSource>,
    /// Optional timestamp in milliseconds since UNIX epoch.
    #[serde(default)]
    pub timestamp_epoch_ms: Option<u64>,
}

impl Fact {
    pub fn counts_as_proof(&self) -> bool {
        if let Some(src) = self.source {
            if !src.counts_as_proof() {
                return false;
            }
        }
        self.tier.is_proof()
    }

    pub fn can_support_pass(&self) -> bool {
        if let Some(src) = self.source {
            if !src.can_support_pass() {
                return false;
            }
        }
        self.tier.can_support_pass()
    }
}

/// Collected evidence for one scenario run.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    pub facts: Vec<Fact>,
}

impl Evidence {
    fn current_timestamp_ms() -> Option<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_millis() as u64)
    }

    pub fn push(&mut self, tier: EvidenceTier, name: &str, value: String) {
        let source = match tier {
            EvidenceTier::HostFact => Some(EvidenceSource::HostObservation),
            EvidenceTier::Constrained => Some(EvidenceSource::ConstrainedChannel),
            EvidenceTier::SelfReport => Some(EvidenceSource::AgentSelfReport),
        };
        self.facts.push(Fact {
            tier,
            name: name.to_string(),
            value,
            provenance: None,
            source,
            timestamp_epoch_ms: Self::current_timestamp_ms(),
        });
    }

    pub fn push_with_source(
        &mut self,
        tier: EvidenceTier,
        source: EvidenceSource,
        name: &str,
        value: String,
    ) {
        // Enforce hierarchy: untrusted source can NEVER count as proof or support pass
        let effective_tier = if !source.counts_as_proof() {
            EvidenceTier::SelfReport
        } else {
            tier.min(source.tier())
        };
        self.facts.push(Fact {
            tier: effective_tier,
            name: name.to_string(),
            value,
            provenance: None,
            source: Some(source),
            timestamp_epoch_ms: Self::current_timestamp_ms(),
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

    pub fn add_stdout(&mut self, name: &str, value: String) {
        self.push_with_source(
            EvidenceTier::SelfReport,
            EvidenceSource::ProcessStdout,
            name,
            value,
        );
    }

    pub fn add_arbitrary_json(&mut self, name: &str, value: String) {
        self.push_with_source(
            EvidenceTier::SelfReport,
            EvidenceSource::SandboxedArbitraryJson,
            name,
            value,
        );
    }

    pub fn add_unprovenanced_snapshot(&mut self, name: &str, value: String) {
        self.push_with_source(
            EvidenceTier::SelfReport,
            EvidenceSource::UnprovenancedSnapshot,
            name,
            value,
        );
    }

    pub fn add_unbound_observation(&mut self, name: &str, value: String) {
        self.push_with_source(
            EvidenceTier::SelfReport,
            EvidenceSource::UnboundObservation,
            name,
            value,
        );
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
                contract_digest: id.contract_digest.clone(),
            }),
            source: Some(EvidenceSource::HostObservation),
            timestamp_epoch_ms: Self::current_timestamp_ms(),
        });
    }

    /// True only when a `HOST_FACT` control fact carries provenance exactly
    /// matching `identity`. Cross-session replays, wrong-scenario and
    /// wrong-registry evidence all fail this check.
    pub fn has_verified_control(&self, identity: &ExecutionIdentity) -> bool {
        self.facts.iter().any(|f| {
            f.tier == EvidenceTier::HostFact
                && f.can_support_pass()
                && f.name == HOST_CONTROL_FACT
                && f.provenance.as_ref().map_or(false, |p| p.matches(identity))
        })
    }

    /// PASS requires at least one host fact (FM-01 structural rule).
    pub fn has_host_fact(&self) -> bool {
        self.facts
            .iter()
            .any(|f| f.tier == EvidenceTier::HostFact && f.can_support_pass())
    }

    pub fn host_fact_value(&self, name: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|f| f.tier == EvidenceTier::HostFact && f.name == name && f.can_support_pass())
            .map(|f| f.value.as_str())
    }

    /// Structural integrity of the evidence set.
    /// Returns false if any fact claims a tier higher than allowed by its source,
    /// or if a control fact lacks valid host channel provenance.
    pub fn verify_integrity(&self) -> bool {
        for fact in &self.facts {
            if let Some(src) = fact.source {
                if !src.counts_as_proof() && fact.tier != EvidenceTier::SelfReport {
                    return false;
                }
                if fact.tier > src.tier() {
                    return false;
                }
            }
            if fact.name == HOST_CONTROL_FACT && fact.tier == EvidenceTier::HostFact {
                match &fact.provenance {
                    Some(prov) if prov.channel == HOST_CONTROL_CHANNEL => {}
                    _ => return false,
                }
            }
        }
        true
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

    #[test]
    fn evidence_tier_trust_hierarchy_ordering() {
        // Contract: HOST_FACT > CONSTRAINED > SELF_REPORT
        assert!(EvidenceTier::HostFact > EvidenceTier::Constrained);
        assert!(EvidenceTier::Constrained > EvidenceTier::SelfReport);
        assert!(EvidenceTier::HostFact > EvidenceTier::SelfReport);
        assert_eq!(EvidenceTier::HostFact.priority(), 3);
        assert_eq!(EvidenceTier::Constrained.priority(), 2);
        assert_eq!(EvidenceTier::SelfReport.priority(), 1);

        assert!(EvidenceTier::HostFact.can_support_pass());
        assert!(!EvidenceTier::Constrained.can_support_pass());
        assert!(!EvidenceTier::SelfReport.can_support_pass());

        assert!(EvidenceTier::HostFact.is_proof());
        assert!(EvidenceTier::Constrained.is_proof());
        assert!(!EvidenceTier::SelfReport.is_proof());
    }

    #[test]
    fn evidence_source_classification_and_proof_rules() {
        // Master Task Section 12: НЕ доказательство: agent self-report; stdout;
        // произвольный JSON от sandboxed process; snapshot без provenance; observation без связи с execution identity.
        let untrusted = [
            EvidenceSource::AgentSelfReport,
            EvidenceSource::ProcessStdout,
            EvidenceSource::ProcessStderr,
            EvidenceSource::SandboxedArbitraryJson,
            EvidenceSource::UnprovenancedSnapshot,
            EvidenceSource::UnboundObservation,
        ];
        for src in untrusted {
            assert!(!src.counts_as_proof(), "{src:?} must never count as proof");
            assert!(!src.can_support_pass(), "{src:?} must never support PASS");
            assert_eq!(src.tier(), EvidenceTier::SelfReport);
        }

        assert!(EvidenceSource::HostObservation.counts_as_proof());
        assert!(EvidenceSource::HostObservation.can_support_pass());
        assert_eq!(
            EvidenceSource::HostObservation.tier(),
            EvidenceTier::HostFact
        );

        assert!(EvidenceSource::ConstrainedChannel.counts_as_proof());
        assert!(!EvidenceSource::ConstrainedChannel.can_support_pass());
        assert_eq!(
            EvidenceSource::ConstrainedChannel.tier(),
            EvidenceTier::Constrained
        );
    }

    #[test]
    fn evidence_push_with_source_enforces_hierarchy() {
        let mut e = Evidence::default();
        // Attempting to push stdout as HostFact is downgraded to SelfReport
        e.push_with_source(
            EvidenceTier::HostFact,
            EvidenceSource::ProcessStdout,
            "fake_host",
            "escaped".to_string(),
        );
        assert_eq!(e.facts.last().unwrap().tier, EvidenceTier::SelfReport);
        assert!(!e.has_host_fact());

        // Attempting to push arbitrary JSON as HostFact is downgraded
        e.add_arbitrary_json("status", "{\"verdict\": \"PASS\"}".to_string());
        assert_eq!(e.facts.last().unwrap().tier, EvidenceTier::SelfReport);
        assert!(!e.has_host_fact());

        // Snapshot without provenance cannot be host fact
        e.add_unprovenanced_snapshot("fs_tree", "/".to_string());
        assert_eq!(e.facts.last().unwrap().tier, EvidenceTier::SelfReport);
        assert!(!e.has_host_fact());

        // Unbound observation cannot be host fact
        e.add_unbound_observation("event", "open".to_string());
        assert_eq!(e.facts.last().unwrap().tier, EvidenceTier::SelfReport);
        assert!(!e.has_host_fact());
    }

    #[test]
    fn evidence_integrity_rejects_escalated_source() {
        let mut e = Evidence::default();
        e.host_fact("valid", "ok".to_string());
        assert!(e.verify_integrity());

        // Forged fact: tier is HostFact but source is SandboxedArbitraryJson
        e.facts.push(Fact {
            tier: EvidenceTier::HostFact,
            name: "forged".to_string(),
            value: "hack".to_string(),
            provenance: None,
            source: Some(EvidenceSource::SandboxedArbitraryJson),
            timestamp_epoch_ms: None,
        });
        assert!(!e.verify_integrity());
        assert!(!e.facts.last().unwrap().can_support_pass());
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

    #[test]
    fn contract_digest_binding_in_identity_and_provenance() {
        let id_with_digest = ExecutionIdentity::new("SCEN-A", "nonce-a", "reg-a", "frozen-a")
            .with_contract_digest("digest-123");
        assert_eq!(
            id_with_digest.contract_digest.as_deref(),
            Some("digest-123")
        );
        assert!(id_with_digest.is_well_formed());

        let expected = derive_expected_response(TEST_CHALLENGE, &id_with_digest.session_nonce);
        let verified =
            attest_control(&id_with_digest, &expected, expected.as_bytes()).expect("mint");
        let mut e = Evidence::default();
        e.host_control_fact(&verified);
        assert!(e.has_verified_control(&id_with_digest));

        // Different contract digest fails matching
        let mismatched_digest = id_with_digest
            .clone()
            .with_contract_digest("digest-TAMPERED");
        assert!(!e.has_verified_control(&mismatched_digest));

        // Identity without digest rejects evidence carrying digest
        let no_digest_id = test_identity();
        assert!(!e.has_verified_control(&no_digest_id));
    }
}
